package detector

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// Rule is one compiled detection rule with fixed-capacity instance state.
type Rule struct {
	name        string
	description *template

	// match filters (a zero/empty filter imposes no constraint)
	family        flowspec.Family
	familySet     bool
	protoFilter   []uint8
	srcFilter     netip.Prefix
	dstFilter     netip.Prefix
	srcPortFilter []uint16
	dstPortFilter []uint16
	packetLen     CompareUint

	// descriptor granularity (aggregate). Every field is always part of the
	// identity; these control its resolution. *MaskBits: -1 = full host, 0 = all.
	protoWild   bool
	srcMaskBits int
	dstMaskBits int
	srcPortAgg  portAgg
	dstPortAgg  portAgg

	// trigger
	terms     []*term
	expr      *vm.Program
	sustained time.Duration

	// emission
	action       flowSpecAction
	emitInterval time.Duration

	history historySpec
	store   *instanceStore
}

// Name returns the compiled rule name.
func (r *Rule) Name() string { return r.name }

// InstanceCount returns how many instance slots are currently occupied.
func (r *Rule) InstanceCount() int { return r.store.len() }

// MaxInstances returns the fixed capacity for this rule.
func (r *Rule) MaxInstances() int { return r.store.max }

// Observe folds one matching sample into the rule's instance rings. It performs
// no trigger work; evaluation happens on Tick.
func (r *Rule) Observe(s Sample) {
	if !r.matches(s) {
		return
	}
	d := r.descriptorFor(s)
	weight := uint64(s.SampleRate)
	if weight == 0 {
		weight = 1
	}
	firstScore := float64(weight) / r.history.fineResolution.Seconds()
	inst, ok := r.store.upsert(d, s.At, firstScore)
	if !ok {
		return
	}
	inst.add(s.At, s.PacketLen, weight)
	inst.lastIngressIf = s.IngressIf
}

// Tick evaluates every instance of this rule at time now and returns the events
// that fired.
func (r *Rule) Tick(now time.Time, ctx EvalContext) []Event {
	var out []Event
	for _, inst := range r.store.items {
		if ev, ok := r.evalInstance(inst, now, ctx); ok {
			out = append(out, *ev)
		}
	}
	return out
}

func (r *Rule) matches(s Sample) bool {
	if r.familySet && s.Family != r.family {
		return false
	}
	if len(r.protoFilter) > 0 && !containsU8(r.protoFilter, s.Proto) {
		return false
	}
	if r.srcFilter.IsValid() && !r.srcFilter.Contains(s.Src) {
		return false
	}
	if r.dstFilter.IsValid() && !r.dstFilter.Contains(s.Dst) {
		return false
	}
	if len(r.srcPortFilter) > 0 && !containsU16(r.srcPortFilter, s.SrcPort) {
		return false
	}
	if len(r.dstPortFilter) > 0 && !containsU16(r.dstPortFilter, s.DstPort) {
		return false
	}
	pl := uint64(s.PacketLen)
	if r.packetLen.LT != 0 && pl >= r.packetLen.LT {
		return false
	}
	if r.packetLen.LTE != 0 && pl > r.packetLen.LTE {
		return false
	}
	if r.packetLen.GT != 0 && pl <= r.packetLen.GT {
		return false
	}
	if r.packetLen.GTE != 0 && pl < r.packetLen.GTE {
		return false
	}
	return true
}

// descriptorFor reduces a matched sample to its comparable identity. Every field
// is carried (pass-through) at the granularity set by aggregate. Allocation free:
// netip.Addr masking and port reduction are value operations.
func (r *Rule) descriptorFor(s Sample) descriptor {
	d := descriptor{family: s.Family, protoWild: r.protoWild}
	if !r.protoWild {
		d.proto = s.Proto
	}
	d.src = maskAddr(s.Src, r.srcMaskBits)
	d.dst = maskAddr(s.Dst, r.dstMaskBits)
	d.srcPortLo, d.srcPortHi = r.srcPortAgg.reduce(s.SrcPort)
	d.dstPortLo, d.dstPortHi = r.dstPortAgg.reduce(s.DstPort)
	return d
}

func (r *Rule) evalInstance(inst *instance, now time.Time, ctx EvalContext) (*Event, bool) {
	values := make(map[string]float64, len(r.terms))
	env := make(map[string]any, len(r.terms))
	for _, t := range r.terms {
		v := r.termValue(t, inst, now, ctx)
		values[t.name] = v
		env[t.name] = v
	}
	res, err := expr.Run(r.expr, env)
	if err != nil {
		return nil, false
	}
	fired, _ := res.(bool)
	if !fired {
		inst.trueSince = time.Time{}
		return nil, false
	}
	if inst.trueSince.IsZero() {
		inst.trueSince = now
	}
	if now.Sub(inst.trueSince) < r.sustained {
		return nil, false
	}
	if !inst.shouldEmit(now, r.emitInterval) {
		return nil, false
	}
	rule, err := r.buildFlowSpec(inst.key)
	if err != nil {
		return nil, false
	}
	keyStr := r.descriptorString(inst.key)
	ev := &Event{
		ID:          r.name + "/" + keyStr,
		RuleName:    r.name,
		InstanceKey: keyStr,
		Description: r.renderDescription(inst, values),
		TTL:         r.action.ttl,
		Refresh:     r.action.refresh,
		ObservedPPS: maxValue(values),
		Rule:        rule,
	}
	return ev, true
}

func (r *Rule) termValue(t *term, inst *instance, now time.Time, ctx EvalContext) float64 {
	if t.metric.isStats() {
		return statsValue(t.metric, inst.lastIngressIf, ctx)
	}
	ring := inst.ringFor(t.ring)
	if ring == nil {
		return 0
	}
	return ring.aggregate(now, t)
}

func statsValue(m metricKind, ingressIf string, ctx EvalContext) float64 {
	if ctx.Stats == nil || ingressIf == "" {
		return 0
	}
	rx, tx, drop, ok := ctx.Stats.InterfaceRates(ingressIf)
	if !ok {
		return 0
	}
	switch m {
	case metricVPPIngressRXPPS:
		return rx
	case metricVPPIngressTXPPS:
		return tx
	case metricVPPIngressDropPPS:
		return drop
	default:
		return 0
	}
}

func (r *Rule) buildFlowSpec(d descriptor) (flowspec.Rule, error) {
	m := flowspec.Match{}

	fam := d.family
	if r.action.family.mode == emitTemplate {
		if f, _, err := parseFamily(r.renderField(r.action.family, d)); err == nil {
			fam = f
		}
	}

	switch r.action.proto.mode {
	case emitDefault:
		if !d.protoWild {
			m.Proto = []flowspec.NumericOp{{EQ: true, Value: uint64(d.proto)}}
		}
	case emitTemplate:
		n, err := parseProtoName(r.renderField(r.action.proto, d))
		if err != nil {
			return flowspec.Rule{}, err
		}
		m.Proto = []flowspec.NumericOp{{EQ: true, Value: uint64(n)}}
	}

	if p, ok, err := r.emitPrefix(r.action.src, d, true); err != nil {
		return flowspec.Rule{}, err
	} else if ok {
		m.HasSrc, m.Src = true, p
	}
	if p, ok, err := r.emitPrefix(r.action.dst, d, false); err != nil {
		return flowspec.Rule{}, err
	} else if ok {
		m.HasDst, m.Dst = true, p
	}

	if ops, err := r.emitPort(r.action.srcPort, d, true); err != nil {
		return flowspec.Rule{}, err
	} else {
		m.SrcPort = ops
	}
	if ops, err := r.emitPort(r.action.dstPort, d, false); err != nil {
		return flowspec.Rule{}, err
	} else {
		m.DstPort = ops
	}

	return flowspec.Rule{
		Family: fam,
		Match:  m,
		Action: flowspec.Action{Kind: flowspec.ActionDrop, Desc: "local-detector:" + r.name},
		Raw:    "local-detector:" + r.name + ":" + r.descriptorString(d),
	}, nil
}

func (r *Rule) emitPrefix(f emitField, d descriptor, isSrc bool) (netip.Prefix, bool, error) {
	addr := d.src
	bits := r.srcMaskBits
	if !isSrc {
		addr, bits = d.dst, r.dstMaskBits
	}
	switch f.mode {
	case emitWildcard:
		return netip.Prefix{}, false, nil
	case emitTemplate:
		p, err := netip.ParsePrefix(r.renderField(f, d))
		if err != nil {
			return netip.Prefix{}, false, err
		}
		return p, true, nil
	default: // emitDefault
		if bits == 0 { // aggregated to /0 -> wildcard
			return netip.Prefix{}, false, nil
		}
		return prefixOf(addr, bits), true, nil
	}
}

func (r *Rule) emitPort(f emitField, d descriptor, isSrc bool) ([]flowspec.NumericOp, error) {
	lo, hi := d.srcPortLo, d.srcPortHi
	if !isSrc {
		lo, hi = d.dstPortLo, d.dstPortHi
	}
	switch f.mode {
	case emitWildcard:
		return nil, nil
	case emitTemplate:
		v, err := strconv.ParseUint(strings.TrimSpace(r.renderField(f, d)), 10, 16)
		if err != nil {
			return nil, err
		}
		return []flowspec.NumericOp{{EQ: true, Value: v}}, nil
	default: // emitDefault
		if lo == 0 && hi == 65535 { // wildcard
			return nil, nil
		}
		return portRangeOps(lo, hi), nil
	}
}

func (r *Rule) renderField(f emitField, d descriptor) string {
	return f.tmpl.render(func(name string) (string, bool) {
		return r.resolveDescriptorVar(d, name)
	})
}

func (r *Rule) renderDescription(inst *instance, values map[string]float64) string {
	if r.description == nil {
		return ""
	}
	return r.description.render(func(name string) (string, bool) {
		if v, ok := values[name]; ok {
			return strconv.FormatFloat(v, 'f', 0, 64), true
		}
		if name == "ingress_if" {
			return inst.lastIngressIf, true
		}
		return r.resolveDescriptorVar(inst.key, name)
	})
}

func portString(lo, hi uint16) string {
	if lo == hi {
		return strconv.Itoa(int(lo))
	}
	return strconv.Itoa(int(lo)) + "-" + strconv.Itoa(int(hi))
}

func (r *Rule) resolveDescriptorVar(d descriptor, name string) (string, bool) {
	switch name {
	case "family":
		return d.family.String(), true
	case "proto":
		if d.protoWild {
			return "any", true
		}
		return strconv.Itoa(int(d.proto)), true
	case "src":
		if r.srcMaskBits == 0 {
			return "any", true
		}
		return prefixOf(d.src, r.srcMaskBits).String(), true
	case "dst":
		if r.dstMaskBits == 0 {
			return "any", true
		}
		return prefixOf(d.dst, r.dstMaskBits).String(), true
	case "src_port":
		if d.srcPortLo == 0 && d.srcPortHi == 65535 {
			return "any", true
		}
		return portString(d.srcPortLo, d.srcPortHi), true
	case "dst_port":
		if d.dstPortLo == 0 && d.dstPortHi == 65535 {
			return "any", true
		}
		return portString(d.dstPortLo, d.dstPortHi), true
	}
	return "", false
}

func (r *Rule) descriptorString(d descriptor) string {
	var b strings.Builder
	b.WriteString("family=")
	b.WriteString(d.family.String())
	b.WriteString("|proto=")
	if d.protoWild {
		b.WriteString("any")
	} else {
		b.WriteString(strconv.Itoa(int(d.proto)))
	}
	b.WriteString("|src=")
	b.WriteString(prefixOf(d.src, r.srcMaskBits).String())
	b.WriteString("|dst=")
	b.WriteString(prefixOf(d.dst, r.dstMaskBits).String())
	b.WriteString("|src_port=")
	b.WriteString(portString(d.srcPortLo, d.srcPortHi))
	b.WriteString("|dst_port=")
	b.WriteString(portString(d.dstPortLo, d.dstPortHi))
	return b.String()
}

// --- value helpers ---

func maskAddr(a netip.Addr, bits int) netip.Addr {
	if !a.IsValid() {
		return a
	}
	max := a.BitLen()
	if bits < 0 || bits > max {
		bits = max
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return a
	}
	return p.Addr()
}

func prefixOf(a netip.Addr, bits int) netip.Prefix {
	max := a.BitLen()
	if bits < 0 || bits > max {
		bits = max
	}
	return netip.PrefixFrom(a, bits)
}

// portRangeOps encodes an inclusive [lo, hi] as FlowSpec numeric ops: an exact
// equality when lo==hi, otherwise ">=lo AND <=hi" which translate reduces to a
// single contiguous range.
func portRangeOps(lo, hi uint16) []flowspec.NumericOp {
	if lo == hi {
		return []flowspec.NumericOp{{EQ: true, Value: uint64(lo)}}
	}
	return []flowspec.NumericOp{
		{GT: true, EQ: true, Value: uint64(lo)},
		{And: true, LT: true, EQ: true, Value: uint64(hi)},
	}
}

func containsU8(s []uint8, v uint8) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsU16(s []uint16, v uint16) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func maxValue(m map[string]float64) float64 {
	first := true
	var out float64
	for _, v := range m {
		if first || v > out {
			out = v
			first = false
		}
	}
	return out
}
