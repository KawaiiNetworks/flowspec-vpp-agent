package detector

import (
	"math"
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
	fingerprint string // hash of the source RuleConfig; gates history reload (persist.go)
	description *template

	// match filters (a zero/empty filter imposes no constraint)
	family         flowspec.Family
	familySet      bool
	protoFilter    []uint8
	srcFilter      netip.Prefix
	dstFilter      netip.Prefix
	srcPortFilter  []uint16
	dstPortFilter  []uint16
	packetLen      CompareUint
	tcpCare        uint8   // match filter: bits we test (0 = no tcp-flags filter)
	tcpWant        uint8   // match filter: required bit values within tcpCare
	icmpTypeFilter []uint8 // match filter on ICMP type (empty = no constraint)
	icmpCodeFilter []uint8 // match filter on ICMP code

	// descriptor granularity (aggregate). Every field is always part of the
	// identity; these control its resolution. *MaskBits: -1 = full host, 0 = all.
	protoWild      bool
	srcMaskBits    int
	dstMaskBits    int
	srcPortAgg     portAgg
	dstPortAgg     portAgg
	icmpTypeAggAll bool // aggregate.icmp_type: all -> type wildcarded out of identity
	icmpCodeAggAll bool // aggregate.icmp_code: all

	// spreadFields are optional per-field diversity gates (ratio_detection): a packet
	// is added to history only when every field's observed spread meets its minimum.
	spreadFields []spreadField

	// trigger
	terms     []*term
	expr      *vm.Program
	sustained time.Duration

	// emission
	action       flowSpecAction
	tcpEmit      tcpEmitSpec
	emitInterval time.Duration

	history historySpec
	store   *instanceStore

	// evalEnv is a reusable scratch env for expr evaluation, refilled per instance
	// on Tick. The engine runs single-goroutine, so sharing one map is safe and
	// avoids allocating a fresh map per instance per tick.
	evalEnv map[string]any

	// admission: a HeavyKeeper sketch observes every matched descriptor and ranks
	// candidates so the bounded instance pool tracks the heaviest targets. rankBytes
	// weights the sketch by bytes (bps rank) rather than packets. The sketch ages by
	// halfLife on each Tick (lastDecay tracks wall-clock between ticks, so the decay
	// is interval-agnostic).
	sketch    *heavyKeeper
	rankBytes bool
	halfLife  time.Duration
	lastDecay time.Time
}

// Name returns the compiled rule name.
func (r *Rule) Name() string { return r.name }

// InstanceCount returns how many instance slots are currently occupied.
func (r *Rule) InstanceCount() int { return r.store.len() }

// MaxInstances returns the fixed capacity for this rule.
func (r *Rule) MaxInstances() int { return r.store.max }

// UsesVPPStats reports whether any trigger term reads a VPP-stats metric
// (vpp.packet_iface.*). Such a rule is meaningless unless detector.vpp_stats is
// enabled, so the caller can reject the configuration early.
func (r *Rule) UsesVPPStats() bool {
	for _, t := range r.terms {
		if t.metric.isStats() {
			return true
		}
	}
	return false
}

// StatsWindow is one VPP-stats term's window/offset, used by the caller to
// validate it against the configured vpp_stats rings at startup.
type StatsWindow struct {
	Window time.Duration
	Offset time.Duration
}

// StatsWindows returns the (window, offset) of every windowed VPP-stats term in
// this rule (instant terms with no window are omitted).
func (r *Rule) StatsWindows() []StatsWindow {
	var out []StatsWindow
	for _, t := range r.terms {
		if t.metric.isStats() && t.window > 0 {
			out = append(out, StatsWindow{Window: t.window, Offset: t.offset})
		}
	}
	return out
}

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
	// Every matched target is observed by the sketch (cheap, fixed memory); only
	// the heaviest are promoted to a full instance with rings. The sketch is
	// weighted by the rank metric (bytes for a bps rank, else packets).
	hkWeight := float64(weight)
	if r.rankBytes {
		hkWeight *= float64(s.PacketLen)
	}
	r.sketch.add(d.hash(), hkWeight)
	inst, ok := r.store.admit(d, r.sketch, s.At)
	if !ok {
		return
	}
	// Diversity gate: update every spread estimator, then only fold this packet into
	// the history rings when every gated field meets its minimum spread. A low-
	// diversity flow (one source/target) thus never triggers a wide-range rule.
	if len(r.spreadFields) > 0 && !r.spreadOK(inst, s) {
		inst.lastSeen = s.At
		inst.lastIngressIf = s.IngressIf
		return
	}
	inst.add(s.At, s.PacketLen, weight)
	inst.lastIngressIf = s.IngressIf
}

// spreadOK updates the instance's per-field diversity estimators with this sample
// and reports whether all of them currently meet their minimum ratio.
func (r *Rule) spreadOK(inst *instance, s Sample) bool {
	if inst.spread == nil {
		inst.spread = make([]spreadEstimator, len(r.spreadFields))
		for i, f := range r.spreadFields {
			inst.spread[i] = newSpreadEstimator(f.buckets)
		}
	}
	ok := true
	for i, f := range r.spreadFields {
		if inst.spread[i].observe(f.bucket(s)) < f.minRatio {
			ok = false // keep updating the rest, but the gate fails
		}
	}
	return ok
}

// Tick evaluates every instance of this rule at time now and returns the events
// that fired.
func (r *Rule) Tick(now time.Time, ctx EvalContext) []Event {
	r.ageSketch(now)
	var out []Event
	for _, inst := range r.store.items {
		if ev, ok := r.evalInstance(inst, now, ctx); ok {
			out = append(out, *ev)
		}
	}
	return out
}

// ageSketch decays the admission sketch by the wall-clock elapsed since the last
// tick, so estimates track recent volume regardless of tick cadence.
func (r *Rule) ageSketch(now time.Time) {
	if !r.lastDecay.IsZero() && r.halfLife > 0 {
		if dt := now.Sub(r.lastDecay); dt > 0 {
			r.sketch.decayAll(math.Pow(0.5, dt.Seconds()/r.halfLife.Seconds()))
		}
	}
	r.lastDecay = now
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
	if r.tcpCare != 0 && s.TCPFlags&r.tcpCare != r.tcpWant {
		return false
	}
	// ICMP type/code filter: only icmp/icmpv6 packets can satisfy it, so a rule
	// that sets either never matches non-ICMP traffic.
	if len(r.icmpTypeFilter) > 0 || len(r.icmpCodeFilter) > 0 {
		if s.Proto != protoICMP && s.Proto != protoICMPv6 {
			return false
		}
		if len(r.icmpTypeFilter) > 0 && !containsU8(r.icmpTypeFilter, s.ICMPType) {
			return false
		}
		if len(r.icmpCodeFilter) > 0 && !containsU8(r.icmpCodeFilter, s.ICMPCode) {
			return false
		}
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
	// Ports only exist for TCP/UDP, and can only be emitted under a concrete
	// tcp/udp protocol. For any other packet (or when proto is wildcarded) ports
	// are "not applicable": wildcard, so they neither split the identity nor get
	// emitted. This lets e.g. an ICMP rule ignore ports without boilerplate.
	if !r.protoWild && (s.Proto == protoTCP || s.Proto == protoUDP) {
		d.srcPortLo, d.srcPortHi = r.srcPortAgg.reduce(s.SrcPort)
		d.dstPortLo, d.dstPortHi = r.dstPortAgg.reduce(s.DstPort)
	} else {
		d.srcPortLo, d.srcPortHi = 0, 65535
		d.dstPortLo, d.dstPortHi = 0, 65535
	}
	// ICMP type/code mirror the port logic but apply to icmp/icmpv6. Exact (the
	// default) makes each type/code its own instance — so a flood of one type is
	// dropped without touching the others (e.g. ICMPv6 NDP types 133-137 survive an
	// echo-request flood). "all" wildcards the field; non-ICMP packets are N/A.
	if !r.protoWild && (s.Proto == protoICMP || s.Proto == protoICMPv6) {
		if r.icmpTypeAggAll {
			d.icmpTypeWild = true
		} else {
			d.icmpType = s.ICMPType
		}
		if r.icmpCodeAggAll {
			d.icmpCodeWild = true
		} else {
			d.icmpCode = s.ICMPCode
		}
	} else {
		d.icmpTypeWild, d.icmpCodeWild = true, true
	}
	return d
}

func (r *Rule) evalInstance(inst *instance, now time.Time, ctx EvalContext) (*Event, bool) {
	// Refill the shared scratch env (every term key is overwritten, so no clear is
	// needed) and run the trigger. This is the per-instance-per-tick hot path, so
	// it must not allocate: the float-valued `values` map is built lazily below,
	// only once we know the instance will emit.
	if r.evalEnv == nil {
		r.evalEnv = make(map[string]any, len(r.terms))
	}
	env := r.evalEnv
	for _, t := range r.terms {
		env[t.name] = r.termValue(t, inst, now, ctx)
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
	// Emitting: now materialize the term values for the description and ObservedPPS.
	values := make(map[string]float64, len(r.terms))
	for _, t := range r.terms {
		values[t.name] = env[t.name].(float64)
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
		return statsValue(t, inst.lastIngressIf, now, ctx)
	}
	ring := inst.ringFor(t.ring)
	if ring == nil {
		return 0
	}
	return ring.aggregate(now, t)
}

// statsValue reads a VPP-stats term: instant (no window) from the latest poll,
// or aggregated over the term's window/offset from the stats rings.
func statsValue(t *term, ingressIf string, now time.Time, ctx EvalContext) float64 {
	if ctx.Stats == nil {
		return 0
	}
	m := t.metric
	if t.window <= 0 {
		// Instant: latest poll.
		if m.isTotal() {
			return m.selectRate(ctx.Stats.TotalRates())
		}
		if ingressIf == "" {
			return 0
		}
		rates, ok := ctx.Stats.InterfaceRates(ingressIf)
		if !ok {
			return 0
		}
		return m.selectRate(rates)
	}
	// Windowed: aggregate over the configured rings.
	peak := t.agg == aggMax
	if m.isTotal() {
		rates, ok := ctx.Stats.TotalWindow(now, t.window, t.offset, peak)
		if !ok {
			return 0
		}
		return m.selectRate(rates)
	}
	if ingressIf == "" {
		return 0
	}
	rates, ok := ctx.Stats.InterfaceWindow(ingressIf, now, t.window, t.offset, peak)
	if !ok {
		return 0
	}
	return m.selectRate(rates)
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

	if care, want, ok := r.tcpEmit.resolve(r.tcpCare, r.tcpWant); ok {
		m.TCPFlags = tcpFlagOps(care, want)
	}

	if ops, err := r.emitICMP(r.action.icmpType, d.icmpType, d.icmpTypeWild, d); err != nil {
		return flowspec.Rule{}, err
	} else {
		m.ICMPType = ops
	}
	if ops, err := r.emitICMP(r.action.icmpCode, d.icmpCode, d.icmpCodeWild, d); err != nil {
		return flowspec.Rule{}, err
	} else {
		m.ICMPCode = ops
	}

	return flowspec.Rule{
		Family: fam,
		Match:  m,
		Action: flowspec.Action{Kind: flowspec.ActionDrop, Desc: "detector:" + r.name},
		Raw:    "detector:" + r.name + ":" + r.descriptorString(d),
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

// emitICMP produces the ICMP type/code constraint for the synthetic FlowSpec:
// wildcard emits nothing; a template parses an explicit value; otherwise the
// descriptor value is emitted unless it is not applicable (wild).
func (r *Rule) emitICMP(f emitField, val uint8, wild bool, d descriptor) ([]flowspec.NumericOp, error) {
	switch f.mode {
	case emitWildcard:
		return nil, nil
	case emitTemplate:
		v, err := strconv.ParseUint(strings.TrimSpace(r.renderField(f, d)), 10, 8)
		if err != nil {
			return nil, err
		}
		return []flowspec.NumericOp{{EQ: true, Value: v}}, nil
	default: // emitDefault
		if wild {
			return nil, nil
		}
		return []flowspec.NumericOp{{EQ: true, Value: uint64(val)}}, nil
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
	case "icmp_type":
		if d.icmpTypeWild {
			return "any", true
		}
		return strconv.Itoa(int(d.icmpType)), true
	case "icmp_code":
		if d.icmpCodeWild {
			return "any", true
		}
		return strconv.Itoa(int(d.icmpCode)), true
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
	// Append icmp type/code only when applicable, so non-ICMP keys are unchanged.
	if !d.icmpTypeWild {
		b.WriteString("|icmp_type=")
		b.WriteString(strconv.Itoa(int(d.icmpType)))
	}
	if !d.icmpCodeWild {
		b.WriteString("|icmp_code=")
		b.WriteString(strconv.Itoa(int(d.icmpCode)))
	}
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

// TCP flag bits in the TCP header flags byte (sFlow sample byte 13).
const (
	tcpFIN uint8 = 1 << 0
	tcpSYN uint8 = 1 << 1
	tcpRST uint8 = 1 << 2
	tcpPSH uint8 = 1 << 3
	tcpACK uint8 = 1 << 4
	tcpURG uint8 = 1 << 5
	tcpECE uint8 = 1 << 6
	tcpCWR uint8 = 1 << 7
)

// tcpEmitSpec controls how a rule emits a tcp-flags constraint into the FlowSpec.
type tcpEmitSpec struct {
	mode       emitMode // emitDefault: mirror the match filter; emitWildcard: none; emitTemplate: explicit
	care, want uint8
}

// resolve returns the (care, want) to emit and whether anything should be emitted,
// given the rule's match filter as the default.
func (e tcpEmitSpec) resolve(matchCare, matchWant uint8) (care, want uint8, ok bool) {
	switch e.mode {
	case emitWildcard:
		return 0, 0, false
	case emitTemplate:
		return e.care, e.want, e.care != 0
	default: // emitDefault: mirror the match filter
		return matchCare, matchWant, matchCare != 0
	}
}

// tcpFlagOps builds FlowSpec bitmask ops for "(flags & care) == want": one op for
// the bits that must be set, one for the bits that must be clear.
func tcpFlagOps(care, want uint8) []flowspec.BitmaskOp {
	set := want
	clear := care &^ want
	var ops []flowspec.BitmaskOp
	if set != 0 {
		ops = append(ops, flowspec.BitmaskOp{Match: true, Value: uint64(set)})
	}
	if clear != 0 {
		ops = append(ops, flowspec.BitmaskOp{And: len(ops) > 0, Not: true, Value: uint64(clear)})
	}
	return ops
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
