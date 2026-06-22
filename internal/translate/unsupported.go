// Package translate is the pure, stateless core that maps an internal FlowSpec
// Rule to a VPP ACL rule (§2–§12). Its single guiding principle: a rule that
// cannot be converted *equivalently* is never approximated — it is rejected with
// a typed Unsupported reason so the caller can log it and bump the right metric.
package translate

// Reason enumerates the ignore reasons that are surfaced as the `reason`
// dimension of the flowspec_rules_ignored_total metric (§12).
type Reason string

const (
	// ReasonUnsupportedComponent: a match component this version does not handle
	// (generic port, packet length, dscp, flow label, fragment, ...).
	ReasonUnsupportedComponent Reason = "unsupported_component"
	// ReasonUnsupportedExpression: a supported component carrying an expression
	// that cannot be reduced to a single contiguous range / exact value
	// (e.g. dport != 80, proto > 10, OR of disjoint ports).
	ReasonUnsupportedExpression Reason = "unsupported_expression"
	// ReasonUnsupportedAction: the FlowSpec action is not a pure drop
	// (rate>0, redirect, marking, sample, ...).
	ReasonUnsupportedAction Reason = "unsupported_action"
	// ReasonUnmappablePrefix: a prefix that has no equivalent VPP form, e.g. an
	// RFC 8956 IPv6 prefix with non-zero offset (§3.2).
	ReasonUnmappablePrefix Reason = "unmappable_prefix"
)

// Unsupported is returned by Translate when a rule must be ignored. It carries
// the metric reason plus a human-readable detail for the structured log (§12).
type Unsupported struct {
	Reason Reason
	Detail string
}

func (u *Unsupported) Error() string {
	return string(u.Reason) + ": " + u.Detail
}

// AsUnsupported extracts the *Unsupported from an error, if present.
func AsUnsupported(err error) (*Unsupported, bool) {
	u, ok := err.(*Unsupported)
	return u, ok
}

func unsupported(r Reason, detail string) error {
	return &Unsupported{Reason: r, Detail: detail}
}
