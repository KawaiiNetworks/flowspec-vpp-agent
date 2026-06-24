package detector

import (
	"strconv"
	"time"
)

// icmpSnap renders an instance's icmp type/code for /status: empty (omitted) when
// the field is not applicable to this descriptor.
func icmpSnap(v uint8, wild bool) string {
	if wild {
		return ""
	}
	return strconv.Itoa(int(v))
}

// EngineSnapshot is a point-in-time, JSON-friendly view of every rule's live
// instance state. It is plain data (no pointers into engine internals) so it can
// be published across goroutines and serialized directly.
type EngineSnapshot struct {
	At    time.Time      `json:"at"`
	Rules []RuleSnapshot `json:"rules"`
}

// RuleSnapshot is one rule's occupancy and its current instances.
type RuleSnapshot struct {
	Name          string             `json:"name"`
	InstanceCount int                `json:"instance_count"`
	MaxInstances  int                `json:"max_instances"`
	Instances     []InstanceSnapshot `json:"instances"`
}

// InstanceSnapshot is the live state of one tracked identity: its descriptor
// fields, current traffic rate from the fine ring, the evaluated trigger terms,
// and whether the trigger expression is currently holding.
type InstanceSnapshot struct {
	Key       string             `json:"key"`
	Family    string             `json:"family"`
	Proto     string             `json:"proto"`
	Src       string             `json:"src"`
	Dst       string             `json:"dst"`
	SrcPort   string             `json:"src_port"`
	DstPort   string             `json:"dst_port"`
	ICMPType  string             `json:"icmp_type,omitempty"`
	ICMPCode  string             `json:"icmp_code,omitempty"`
	IngressIf string             `json:"ingress_if,omitempty"`
	LastSeen  time.Time          `json:"last_seen"`
	PPS       float64            `json:"pps"`
	BPS       float64            `json:"bps"`
	Score     float64            `json:"score"` // HeavyKeeper admission estimate (recent weight)
	Firing    bool               `json:"firing"`
	Terms     map[string]float64 `json:"terms,omitempty"`
	Spread    map[string]int     `json:"spread,omitempty"` // ratio_detection: field -> percent
}

// Snapshot builds a view of all rules at time now. It must be called on the
// goroutine that owns the engine (the Runner's loop), since it reads instance
// state without locking.
func (e *Engine) Snapshot(now time.Time, ctx EvalContext) EngineSnapshot {
	out := EngineSnapshot{At: now, Rules: make([]RuleSnapshot, 0, len(e.all))}
	for _, r := range e.all {
		out.Rules = append(out.Rules, r.snapshot(now, ctx))
	}
	return out
}

func (r *Rule) snapshot(now time.Time, ctx EvalContext) RuleSnapshot {
	rs := RuleSnapshot{
		Name:          r.name,
		InstanceCount: r.store.len(),
		MaxInstances:  r.store.max,
		Instances:     make([]InstanceSnapshot, 0, r.store.len()),
	}
	for _, inst := range r.store.items {
		rs.Instances = append(rs.Instances, r.instanceSnapshot(inst, now, ctx))
	}
	return rs
}

func (r *Rule) instanceSnapshot(inst *instance, now time.Time, ctx EvalContext) InstanceSnapshot {
	field := func(name string) string {
		v, _ := r.resolveDescriptorVar(inst.key, name)
		return v
	}
	var terms map[string]float64
	if len(r.terms) > 0 {
		terms = make(map[string]float64, len(r.terms))
		for _, t := range r.terms {
			terms[t.name] = r.termValue(t, inst, now, ctx)
		}
	}
	var spread map[string]int
	if len(r.spreadFields) > 0 && inst.spread != nil {
		spread = make(map[string]int, len(r.spreadFields))
		for i, f := range r.spreadFields {
			spread[f.String()] = inst.spread[i].ratioPct()
		}
	}
	return InstanceSnapshot{
		Key:       r.descriptorString(inst.key),
		Family:    field("family"),
		Proto:     field("proto"),
		Src:       field("src"),
		Dst:       field("dst"),
		SrcPort:   field("src_port"),
		DstPort:   field("dst_port"),
		ICMPType:  icmpSnap(inst.key.icmpType, inst.key.icmpTypeWild),
		ICMPCode:  icmpSnap(inst.key.icmpCode, inst.key.icmpCodeWild),
		IngressIf: inst.lastIngressIf,
		LastSeen:  inst.lastSeen,
		PPS:       inst.fine.rate(now, 1, metricPPS),
		BPS:       inst.fine.rate(now, 1, metricBPS),
		Score:     r.sketch.estimate(inst.keyHash),
		Firing:    !inst.trueSince.IsZero(),
		Terms:     terms,
		Spread:    spread,
	}
}
