package detector

import "time"

// Engine folds samples into rule state and evaluates triggers on Tick. Rules are
// indexed by protocol so the sample hot path skips unrelated matchers.
type Engine struct {
	anyProto []*Rule
	byProto  map[uint8][]*Rule
	all      []*Rule
}

// NewEngine builds a detector engine from compiled rules.
func NewEngine(rules []*Rule) *Engine {
	e := &Engine{byProto: make(map[uint8][]*Rule)}
	for _, r := range rules {
		e.all = append(e.all, r)
		if len(r.protoFilter) > 0 {
			for _, p := range r.protoFilter {
				e.byProto[p] = append(e.byProto[p], r)
			}
		} else {
			e.anyProto = append(e.anyProto, r)
		}
	}
	return e
}

// Observe folds one sample into every candidate rule's rings. No trigger work
// happens here.
func (e *Engine) Observe(s Sample) {
	for _, r := range e.anyProto {
		r.Observe(s)
	}
	for _, r := range e.byProto[s.Proto] {
		r.Observe(s)
	}
}

// Tick evaluates all rules at time now and returns the events that fired.
func (e *Engine) Tick(now time.Time, ctx EvalContext) []Event {
	var out []Event
	for _, r := range e.all {
		out = append(out, r.Tick(now, ctx)...)
	}
	return out
}

// TickInterval is the recommended evaluation cadence: the finest hot resolution
// across rules (clamped to >= 1s). Returns 0 when there are no rules.
func (e *Engine) TickInterval() time.Duration {
	var best time.Duration
	for _, r := range e.all {
		res := r.history.fineResolution
		if res <= 0 {
			continue
		}
		if best == 0 || res < best {
			best = res
		}
	}
	if best > 0 && best < time.Second {
		best = time.Second
	}
	return best
}
