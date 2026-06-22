package translate

import (
	"fmt"
	"sort"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// interval is an inclusive [lo, hi] range over the operand domain.
type interval struct{ lo, hi uint64 }

// reduceRange evaluates a FlowSpec numeric operator list (RFC 8955 §4.2.1.1) over
// the domain [0, max] and requires the result to be a *single contiguous* range,
// which is the only form a VPP ACL port range can express (§5, §6).
//
// Semantics: items form OR-of-AND terms. An item with And=false opens a new OR
// term (the very first item's And is ignored); items within a term are ANDed.
// Each item denotes a set of values; we intersect within a term and union across
// terms, then demand exactly one non-empty contiguous interval. Anything else
// (e.g. "!= v" -> two disjoint ranges, or "=80 or =443") is rejected as an
// unsupported expression — never approximated.
//
// An empty list means the component is absent: callers treat that as the full
// range [0, max].
func reduceRange(ops []flowspec.NumericOp, max uint64, what string) (lo, hi uint64, err error) {
	if len(ops) == 0 {
		return 0, max, nil
	}

	var result []interval // union of fully-reduced OR terms
	var cur []interval    // current OR term, intersected incrementally
	curStarted := false

	closeTerm := func() {
		if curStarted {
			result = unionSets(result, cur)
		}
		cur = nil
		curStarted = false
	}

	for i, op := range ops {
		set, oerr := opToSet(op, max)
		if oerr != nil {
			return 0, 0, fmt.Errorf("%s: %w", what, oerr)
		}
		if i > 0 && !op.And {
			closeTerm() // new OR term begins
		}
		if !curStarted {
			cur = set
			curStarted = true
		} else {
			cur = intersectSets(cur, set)
		}
	}
	closeTerm()

	result = normalize(result)
	if len(result) == 0 {
		return 0, 0, unsupported(ReasonUnsupportedExpression,
			fmt.Sprintf("%s: expression matches no value", what))
	}
	if len(result) != 1 {
		return 0, 0, unsupported(ReasonUnsupportedExpression,
			fmt.Sprintf("%s: expression is not a single contiguous range", what))
	}
	return result[0].lo, result[0].hi, nil
}

// opToSet converts a single numeric operator item into a (possibly disjoint) set
// of intervals over [0, max].
func opToSet(op flowspec.NumericOp, max uint64) ([]interval, error) {
	v := op.Value
	switch {
	case !op.LT && !op.GT && !op.EQ:
		// Numeric "true": matches the whole operand domain.
		return []interval{{0, max}}, nil
	case op.LT && op.GT && op.EQ:
		// Numeric "false": matches no values.
		return nil, nil
	}
	if v > max {
		return nil, unsupported(ReasonUnsupportedExpression,
			fmt.Sprintf("numeric operand %d out of range 0-%d", v, max))
	}
	switch {
	case op.EQ && !op.LT && !op.GT: // ==
		return []interval{{v, v}}, nil
	case op.GT && !op.EQ && !op.LT: // >
		if v >= max {
			return nil, nil // empty
		}
		return []interval{{v + 1, max}}, nil
	case op.LT && !op.EQ && !op.GT: // <
		if v == 0 {
			return nil, nil
		}
		return []interval{{0, v - 1}}, nil
	case op.GT && op.EQ && !op.LT: // >=
		return []interval{{v, max}}, nil
	case op.LT && op.EQ && !op.GT: // <=
		return []interval{{0, v}}, nil
	case op.LT && op.GT && !op.EQ: // != (two disjoint ranges; never contiguous)
		var out []interval
		if v > 0 {
			out = append(out, interval{0, v - 1})
		}
		if v < max {
			out = append(out, interval{v + 1, max})
		}
		return out, nil
	default:
		return nil, unsupported(ReasonUnsupportedExpression, "unknown numeric op")
	}
}

func intersectSets(a, b []interval) []interval {
	var out []interval
	for _, x := range a {
		for _, y := range b {
			lo := x.lo
			if y.lo > lo {
				lo = y.lo
			}
			hi := x.hi
			if y.hi < hi {
				hi = y.hi
			}
			if lo <= hi {
				out = append(out, interval{lo, hi})
			}
		}
	}
	return normalize(out)
}

func unionSets(a, b []interval) []interval {
	out := append([]interval{}, a...)
	out = append(out, b...)
	return normalize(out)
}

// normalize sorts and merges overlapping/adjacent intervals into a canonical
// disjoint set. Adjacency (hi+1 == lo) merges so that, e.g., [0,79]∪[80,80]
// collapses to a single contiguous [0,80].
func normalize(s []interval) []interval {
	if len(s) == 0 {
		return nil
	}
	cp := append([]interval{}, s...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].lo != cp[j].lo {
			return cp[i].lo < cp[j].lo
		}
		return cp[i].hi < cp[j].hi
	})
	out := []interval{cp[0]}
	for _, iv := range cp[1:] {
		last := &out[len(out)-1]
		if iv.lo <= last.hi || iv.lo == last.hi+1 {
			if iv.hi > last.hi {
				last.hi = iv.hi
			}
		} else {
			out = append(out, iv)
		}
	}
	return out
}
