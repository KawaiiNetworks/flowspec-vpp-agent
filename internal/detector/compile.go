package detector

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

type historySpec struct {
	maxInstances     int
	fineResolution   time.Duration
	fineSlots        int
	mediumResolution time.Duration
	mediumSlots      int
	coarseResolution time.Duration
	coarseSlots      int
}

// term is a compiled, named windowed aggregate read during trigger evaluation.
type term struct {
	name    string
	metric  metricKind
	agg     aggKind
	window  time.Duration
	offset  time.Duration
	ring    ringKind
	ringRes time.Duration
	slots   int // window / ringRes
}

// emitMode selects how a FlowSpec field is produced.
type emitMode uint8

const (
	emitDefault  emitMode = iota // field omitted: use the descriptor value
	emitWildcard                 // "all"/"any": match everything
	emitTemplate                 // explicit template over descriptor variables
)

type emitField struct {
	mode emitMode
	tmpl *template
}

type flowSpecAction struct {
	ttl      time.Duration
	refresh  bool
	family   emitField
	proto    emitField
	src      emitField
	dst      emitField
	srcPort  emitField
	dstPort  emitField
	icmpType emitField
	icmpCode emitField
}

func compileRule(cfg RuleConfig) (*Rule, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("name must be set")
	}
	r := &Rule{name: cfg.Name, fingerprint: ruleFingerprint(cfg)}

	// --- match: family filter ---
	fam, famSet, err := parseFamily(cfg.Match.Family)
	if err != nil {
		return nil, fmt.Errorf("match.family: %w", err)
	}
	r.family, r.familySet = fam, famSet

	// --- match: protocol filter (single or set) ---
	for _, p := range cfg.Match.Proto {
		n, err := parseProtoName(p)
		if err != nil {
			return nil, fmt.Errorf("match.proto: %w", err)
		}
		r.protoFilter = append(r.protoFilter, n)
	}

	// --- match: address filters ---
	if cfg.Match.Src != "" {
		p, err := netip.ParsePrefix(cfg.Match.Src)
		if err != nil {
			return nil, fmt.Errorf("match.src: %w", err)
		}
		r.srcFilter = p.Masked()
	}
	if cfg.Match.Dst != "" {
		p, err := netip.ParsePrefix(cfg.Match.Dst)
		if err != nil {
			return nil, fmt.Errorf("match.dst: %w", err)
		}
		r.dstFilter = p.Masked()
	}

	// --- match: port filters ---
	for _, p := range cfg.Match.SrcPort {
		if p < 0 || p > 65535 {
			return nil, fmt.Errorf("match.src_port %d out of range", p)
		}
		r.srcPortFilter = append(r.srcPortFilter, uint16(p))
	}
	for _, p := range cfg.Match.DstPort {
		if p < 0 || p > 65535 {
			return nil, fmt.Errorf("match.dst_port %d out of range", p)
		}
		r.dstPortFilter = append(r.dstPortFilter, uint16(p))
	}
	r.packetLen = cfg.Match.PacketLen

	// --- match: icmp type/code filter ---
	if r.icmpTypeFilter, err = compileU8List(cfg.Match.ICMPType, "match.icmp_type"); err != nil {
		return nil, err
	}
	if r.icmpCodeFilter, err = compileU8List(cfg.Match.ICMPCode, "match.icmp_code"); err != nil {
		return nil, err
	}

	// --- match: tcp flags filter ---
	if cfg.Match.TCPFlags != "" {
		r.tcpCare, r.tcpWant, err = parseTCPFlags(cfg.Match.TCPFlags)
		if err != nil {
			return nil, fmt.Errorf("match.tcp_flags: %w", err)
		}
	}

	// --- aggregate: granularity of each descriptor field ---
	r.protoWild, err = aggProto(cfg.Aggregate.Proto)
	if err != nil {
		return nil, fmt.Errorf("aggregate.proto: %w", err)
	}
	r.srcMaskBits, err = aggAddrBits(cfg.Aggregate.Src, famSet, fam)
	if err != nil {
		return nil, fmt.Errorf("aggregate.src: %w", err)
	}
	r.dstMaskBits, err = aggAddrBits(cfg.Aggregate.Dst, famSet, fam)
	if err != nil {
		return nil, fmt.Errorf("aggregate.dst: %w", err)
	}
	r.srcPortAgg, err = aggPort(cfg.Aggregate.SrcPort)
	if err != nil {
		return nil, fmt.Errorf("aggregate.src_port: %w", err)
	}
	r.dstPortAgg, err = aggPort(cfg.Aggregate.DstPort)
	if err != nil {
		return nil, fmt.Errorf("aggregate.dst_port: %w", err)
	}
	r.icmpTypeAggAll, err = aggICMP(cfg.Aggregate.ICMPType)
	if err != nil {
		return nil, fmt.Errorf("aggregate.icmp_type: %w", err)
	}
	r.icmpCodeAggAll, err = aggICMP(cfg.Aggregate.ICMPCode)
	if err != nil {
		return nil, fmt.Errorf("aggregate.icmp_code: %w", err)
	}

	// A FlowSpec port range needs a concrete protocol, so non-wildcard ports
	// cannot be combined with a wildcarded protocol. (Ports for non-TCP/UDP
	// packets are handled at runtime: they are treated as not-applicable and never
	// emitted, so no per-rule proto restriction is needed here.)
	if (!r.srcPortAgg.wildcard() || !r.dstPortAgg.wildcard()) && r.protoWild {
		return nil, fmt.Errorf("non-wildcard src_port/dst_port cannot be combined with aggregate.proto: all")
	}

	// --- history ---
	hist, err := compileHistory(cfg.History)
	if err != nil {
		return nil, err
	}
	r.history = hist
	r.store = newInstanceStore(hist)
	r.sketch = newHeavyKeeper(sketchWidth(hist.maxInstances), sketchDepth, heavyKeeperDecay)

	// --- trigger: terms + expression ---
	terms, err := compileTerms(cfg.Trigger, hist)
	if err != nil {
		return nil, err
	}
	r.terms = terms
	r.rankBytes, r.halfLife, err = resolveRank(cfg.Rank, terms)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(terms))
	for _, t := range terms {
		names = append(names, t.name)
	}
	prog, err := compileExpr(cfg.Trigger.Expr, names)
	if err != nil {
		return nil, fmt.Errorf("trigger.expr: %w", err)
	}
	r.expr = prog
	r.sustained = cfg.Trigger.Sustained.Duration()

	// --- flowspec emission ---
	action, err := compileAction(cfg.FlowSpec)
	if err != nil {
		return nil, err
	}
	r.action = action
	r.tcpEmit, err = compileTCPEmit(cfg.FlowSpec.TCPFlags)
	if err != nil {
		return nil, fmt.Errorf("flowspec.tcp_flags: %w", err)
	}
	// tcp-flags (matched or emitted) only makes sense for TCP.
	if r.tcpCare != 0 || r.tcpEmit.mode == emitTemplate {
		if !r.protoOnlyTCP() {
			return nil, fmt.Errorf("tcp_flags requires match.proto to be tcp")
		}
	}
	r.emitInterval = action.ttl / 2
	if r.emitInterval < hist.fineResolution {
		r.emitInterval = hist.fineResolution
	}

	// --- description ---
	if cfg.Description != "" {
		dt, err := compileTemplate(cfg.Description)
		if err != nil {
			return nil, fmt.Errorf("description: %w", err)
		}
		r.description = dt
	}

	// --- validate template variable references ---
	if err := r.validateVars(names); err != nil {
		return nil, err
	}
	return r, nil
}

// protoOnlyTCP reports whether the proto filter is exactly {tcp}.
func (r *Rule) protoOnlyTCP() bool {
	for _, p := range r.protoFilter {
		if p != protoTCP {
			return false
		}
	}
	return len(r.protoFilter) > 0
}

var tcpFlagBits = map[string]uint8{
	"fin": tcpFIN, "syn": tcpSYN, "rst": tcpRST, "psh": tcpPSH,
	"ack": tcpACK, "urg": tcpURG, "ece": tcpECE, "cwr": tcpCWR,
}

// parseTCPFlags parses a spec like "syn !ack" into a (care, want) pair where a
// packet matches when (flags & care) == want. Tokens are space/comma separated;
// a leading "!" requires the flag to be clear.
func parseTCPFlags(s string) (care, want uint8, err error) {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' })
	for _, tok := range fields {
		neg := strings.HasPrefix(tok, "!")
		name := strings.ToLower(strings.TrimPrefix(tok, "!"))
		bit, ok := tcpFlagBits[name]
		if !ok {
			return 0, 0, fmt.Errorf("unknown tcp flag %q", tok)
		}
		care |= bit
		if !neg {
			want |= bit
		}
	}
	if care == 0 {
		return 0, 0, fmt.Errorf("no flags specified")
	}
	return care, want, nil
}

// compileTCPEmit parses flowspec.tcp_flags: "" mirrors the match filter,
// "all"/"any" emits nothing, otherwise an explicit spec.
func compileTCPEmit(s string) (tcpEmitSpec, error) {
	t := strings.TrimSpace(s)
	switch {
	case t == "":
		return tcpEmitSpec{mode: emitDefault}, nil
	case strings.EqualFold(t, "all"), strings.EqualFold(t, "any"):
		return tcpEmitSpec{mode: emitWildcard}, nil
	default:
		care, want, err := parseTCPFlags(t)
		if err != nil {
			return tcpEmitSpec{}, err
		}
		return tcpEmitSpec{mode: emitTemplate, care: care, want: want}, nil
	}
}

// descriptorVars is the set of variables every rule produces. Each matched
// packet carries all fields, so all are always available (a wildcard aggregate
// renders empty, not "missing").
var descriptorVars = map[string]struct{}{
	"family": {}, "proto": {}, "src": {}, "dst": {}, "src_port": {}, "dst_port": {},
	"icmp_type": {}, "icmp_code": {},
}

func (r *Rule) validateVars(termNames []string) error {
	checkFlowSpec := func(field string, f emitField) error {
		if f.mode != emitTemplate {
			return nil
		}
		for _, v := range f.tmpl.vars() {
			if _, ok := descriptorVars[v]; !ok {
				return fmt.Errorf("flowspec.%s references {{%s}} which is not a descriptor field", field, v)
			}
		}
		return nil
	}
	for _, c := range []struct {
		name string
		f    emitField
	}{
		{"family", r.action.family}, {"proto", r.action.proto},
		{"src_prefix", r.action.src}, {"dst_prefix", r.action.dst},
		{"src_port", r.action.srcPort}, {"dst_port", r.action.dstPort},
		{"icmp_type", r.action.icmpType}, {"icmp_code", r.action.icmpCode},
	} {
		if err := checkFlowSpec(c.name, c.f); err != nil {
			return err
		}
	}
	if r.description != nil {
		allowed := map[string]struct{}{"ingress_if": {}}
		for k := range descriptorVars {
			allowed[k] = struct{}{}
		}
		for _, n := range termNames {
			allowed[n] = struct{}{}
		}
		for _, v := range r.description.vars() {
			if _, ok := allowed[v]; !ok {
				return fmt.Errorf("description references {{%s}} which is not a descriptor field, ingress_if, or trigger term", v)
			}
		}
	}
	return nil
}

func parseFamily(s string) (flowspec.Family, bool, error) {
	switch strings.ToLower(s) {
	case "":
		return flowspec.FamilyIPv4, false, nil
	case "ipv4", "ip4":
		return flowspec.FamilyIPv4, true, nil
	case "ipv6", "ip6":
		return flowspec.FamilyIPv6, true, nil
	default:
		return 0, false, fmt.Errorf("unknown family %q", s)
	}
}

func parseProtoName(s string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "icmp":
		return protoICMP, nil
	case "tcp":
		return protoTCP, nil
	case "udp":
		return protoUDP, nil
	case "icmpv6":
		return protoICMPv6, nil
	default:
		v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 8)
		if err != nil {
			return 0, fmt.Errorf("unknown proto %q", s)
		}
		return uint8(v), nil
	}
}

// portAggMode selects how a matched port is reduced into the descriptor.
type portAggMode uint8

const (
	portExact  portAggMode = iota // pass-through: identity = the exact port
	portAll                       // wildcard: all ports collapse to 0..65535
	portRange                     // fixed inclusive range, copied verbatim
	portBucket                    // floor bucket of width `step`
)

// portAgg is a compiled port aggregation.
type portAgg struct {
	mode   portAggMode
	lo, hi uint16 // portRange bounds
	step   uint32 // portBucket width
}

func (p portAgg) wildcard() bool { return p.mode == portAll }

// reduce maps a packet's port to its aggregated inclusive [lo, hi].
func (p portAgg) reduce(port uint16) (lo, hi uint16) {
	switch p.mode {
	case portAll:
		return 0, 65535
	case portRange:
		return p.lo, p.hi
	case portBucket:
		base := (uint32(port) / p.step) * p.step
		end := base + p.step - 1
		if end > 65535 {
			end = 65535
		}
		return uint16(base), uint16(end)
	default: // portExact
		return port, port
	}
}

// aggProto parses the protocol aggregation: "exact" (default) keeps the concrete
// protocol; "all" makes it a wildcard. Returns protoWild.
func aggProto(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "exact", "keep":
		return false, nil
	case "all", "any":
		return true, nil
	default:
		return false, fmt.Errorf("must be \"exact\" or \"all\", got %q", s)
	}
}

// aggAddrBits parses an address aggregate ("/24"). An empty value means full host
// granularity (-1, resolved per packet against the family). "/0" collapses all
// addresses into one instance.
func aggAddrBits(s string, famSet bool, fam flowspec.Family) (int, error) {
	if strings.TrimSpace(s) == "" {
		return -1, nil
	}
	bits, err := parseSlashBits(s, 128)
	if err != nil {
		return 0, err
	}
	if famSet && fam == flowspec.FamilyIPv4 && bits > 32 {
		return 0, fmt.Errorf("prefix /%d exceeds 32 for an ipv4 rule", bits)
	}
	return bits, nil
}

func parseSlashBits(s string, max int) (int, error) {
	t := strings.TrimPrefix(strings.TrimSpace(s), "/")
	bits, err := strconv.Atoi(t)
	if err != nil {
		return 0, fmt.Errorf("invalid prefix %q (want \"/N\")", s)
	}
	if bits < 0 || bits > max {
		return 0, fmt.Errorf("prefix /%d out of range 0-%d", bits, max)
	}
	return bits, nil
}

// aggPort parses a port aggregate:
//
//	"" / "exact" / "keep"  -> pass-through (identity is the exact port)
//	"all" / "any"          -> wildcard (0..65535)
//	"LO-HI"                -> fixed inclusive range, copied verbatim (no check)
//	"N"                    -> floor bucket of width N (101 with "100" -> 100-199)
func aggPort(s string) (portAgg, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "", "exact", "keep":
		return portAgg{mode: portExact}, nil
	case "all", "any":
		return portAgg{mode: portAll}, nil
	}
	if strings.Contains(t, "-") {
		parts := strings.SplitN(t, "-", 2)
		lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		if err != nil {
			return portAgg{}, fmt.Errorf("invalid range %q", s)
		}
		hi, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err != nil {
			return portAgg{}, fmt.Errorf("invalid range %q", s)
		}
		if lo > hi {
			return portAgg{}, fmt.Errorf("range %q has lo > hi", s)
		}
		return portAgg{mode: portRange, lo: uint16(lo), hi: uint16(hi)}, nil
	}
	step, err := strconv.ParseUint(t, 10, 32)
	if err != nil || step == 0 {
		return portAgg{}, fmt.Errorf("invalid bucket step %q (want a positive integer)", s)
	}
	return portAgg{mode: portBucket, step: uint32(step)}, nil
}

func compileHistory(c HistoryConfig) (historySpec, error) {
	if c.MaxInstances <= 0 {
		return historySpec{}, fmt.Errorf("history.max_instances must be > 0")
	}
	fineRes, fineSlots, err := compileRing(c.Fine, "history.fine")
	if err != nil {
		return historySpec{}, err
	}
	mediumRes, mediumSlots, err := compileOptionalRing(c.Medium, "history.medium")
	if err != nil {
		return historySpec{}, err
	}
	coarseRes, coarseSlots, err := compileOptionalRing(c.Coarse, "history.coarse")
	if err != nil {
		return historySpec{}, err
	}
	return historySpec{
		maxInstances:     c.MaxInstances,
		fineResolution:   fineRes,
		fineSlots:        fineSlots,
		mediumResolution: mediumRes,
		mediumSlots:      mediumSlots,
		coarseResolution: coarseRes,
		coarseSlots:      coarseSlots,
	}, nil
}

func compileOptionalRing(c RingConfig, field string) (time.Duration, int, error) {
	if c.Resolution.Duration() == 0 && c.Duration.Duration() == 0 {
		return 0, 0, nil
	}
	return compileRing(c, field)
}

func compileRing(c RingConfig, field string) (time.Duration, int, error) {
	res := c.Resolution.Duration()
	dur := c.Duration.Duration()
	if res <= 0 || dur <= 0 {
		return 0, 0, fmt.Errorf("%s resolution and duration must be set", field)
	}
	if dur%res != 0 {
		return 0, 0, fmt.Errorf("%s duration must be a multiple of resolution", field)
	}
	slots := int(dur / res)
	if slots <= 0 {
		return 0, 0, fmt.Errorf("%s must have at least one slot", field)
	}
	return res, slots, nil
}

// resolveRank maps the rule's `rank` term name to the admission sketch settings:
// whether to weight by bytes (a bps term) and the decay half-life (the term's
// window, so the rank estimate is smoothed over the same span the term spans). An
// empty rank ranks by packet rate over the default half-life. A vpp.* term cannot
// rank (it is interface-level, not per-target).
func resolveRank(name string, terms []*term) (rankBytes bool, halfLife time.Duration, err error) {
	if name == "" {
		return false, sketchHalfLife, nil
	}
	for _, t := range terms {
		if t.name != name {
			continue
		}
		if t.metric.isStats() {
			return false, 0, fmt.Errorf("rank %q is a vpp.* term; rank must reference a pps or bps term", name)
		}
		hl := t.window
		if hl <= 0 {
			hl = sketchHalfLife
		}
		return t.metric == metricBPS, hl, nil
	}
	return false, 0, fmt.Errorf("rank %q is not a defined trigger term", name)
}

func compileTerms(c TriggerConfig, hist historySpec) ([]*term, error) {
	if len(c.Terms) == 0 {
		return nil, fmt.Errorf("trigger.terms must not be empty")
	}
	terms := make([]*term, 0, len(c.Terms))
	for name, tc := range c.Terms {
		if !validIdent(name) {
			return nil, fmt.Errorf("trigger.terms: %q is not a valid identifier", name)
		}
		metric, err := parseMetric(tc.Metric)
		if err != nil {
			return nil, fmt.Errorf("trigger.terms.%s: %w", name, err)
		}
		agg, err := parseAgg(tc.Agg)
		if err != nil {
			return nil, fmt.Errorf("trigger.terms.%s: %w", name, err)
		}
		t := &term{name: name, metric: metric, agg: agg}
		if metric.isStats() {
			// VPP-stats terms: window is OPTIONAL. window=0 reads the latest poll;
			// window>0 aggregates over the global vpp_stats rings (coverage is
			// validated at startup against the configured rings, not here). Only
			// avg/max make sense over already-per-second rates; sum is rejected.
			window := tc.Window.Duration()
			if window < 0 {
				return nil, fmt.Errorf("trigger.terms.%s: window must be >= 0", name)
			}
			if window > 0 {
				offset := tc.Offset.Duration()
				if offset < 0 {
					return nil, fmt.Errorf("trigger.terms.%s: offset must be >= 0", name)
				}
				if agg == aggSum {
					return nil, fmt.Errorf("trigger.terms.%s: vpp metrics support agg avg or max, not sum", name)
				}
				t.window = window
				t.offset = offset
			}
		} else {
			window := tc.Window.Duration()
			if window <= 0 {
				return nil, fmt.Errorf("trigger.terms.%s: window must be > 0", name)
			}
			t.window = window
			t.offset = tc.Offset.Duration()
			if t.offset < 0 {
				return nil, fmt.Errorf("trigger.terms.%s: offset must be >= 0", name)
			}
			ring, res, err := chooseRing(hist, window, t.offset)
			if err != nil {
				return nil, fmt.Errorf("trigger.terms.%s: %w", name, err)
			}
			t.ring, t.ringRes = ring, res
			t.slots = int(window / res)
		}
		terms = append(terms, t)
	}
	return terms, nil
}

// chooseRing picks the coarsest history ring whose resolution divides both the
// window and the offset and whose span covers window+offset. Coarser rings make
// long-window terms cheap (fewer slot reads).
func chooseRing(h historySpec, window, offset time.Duration) (ringKind, time.Duration, error) {
	type cand struct {
		kind ringKind
		res  time.Duration
		span time.Duration
	}
	cands := []cand{{ringFine, h.fineResolution, time.Duration(h.fineSlots) * h.fineResolution}}
	if h.mediumSlots > 0 {
		cands = append(cands, cand{ringMedium, h.mediumResolution, time.Duration(h.mediumSlots) * h.mediumResolution})
	}
	if h.coarseSlots > 0 {
		cands = append(cands, cand{ringCoarse, h.coarseResolution, time.Duration(h.coarseSlots) * h.coarseResolution})
	}
	best := cand{}
	found := false
	for _, c := range cands {
		if c.res > window || window%c.res != 0 || offset%c.res != 0 {
			continue
		}
		if c.span < window+offset {
			continue
		}
		if !found || c.res > best.res {
			best, found = c, true
		}
	}
	if !found {
		return 0, 0, fmt.Errorf("no history ring covers window %s offset %s (check resolutions and durations)", window, offset)
	}
	return best.kind, best.res, nil
}

func parseMetric(s string) (metricKind, error) {
	switch strings.ToLower(s) {
	case "pps", "":
		return metricPPS, nil
	case "bps":
		return metricBPS, nil
	// Per-interface (the instance's packet ingress interface).
	case "vpp.packet_iface.rx_pps":
		return metricIfaceRXPPS, nil
	case "vpp.packet_iface.tx_pps":
		return metricIfaceTXPPS, nil
	case "vpp.packet_iface.rx_bps":
		return metricIfaceRXBPS, nil
	case "vpp.packet_iface.tx_bps":
		return metricIfaceTXBPS, nil
	case "vpp.packet_iface.sw_drop_pps":
		return metricIfaceSWDropPPS, nil
	case "vpp.packet_iface.hw_drop_pps":
		return metricIfaceHWDropPPS, nil
	// Totals across all interfaces.
	case "vpp.total.rx_pps":
		return metricTotalRXPPS, nil
	case "vpp.total.tx_pps":
		return metricTotalTXPPS, nil
	case "vpp.total.rx_bps":
		return metricTotalRXBPS, nil
	case "vpp.total.tx_bps":
		return metricTotalTXBPS, nil
	case "vpp.total.sw_drop_pps":
		return metricTotalSWDropPPS, nil
	case "vpp.total.hw_drop_pps":
		return metricTotalHWDropPPS, nil
	default:
		return 0, fmt.Errorf("unknown metric %q", s)
	}
}

func parseAgg(s string) (aggKind, error) {
	switch strings.ToLower(s) {
	case "avg", "rate", "":
		return aggAvg, nil
	case "max", "peak":
		return aggMax, nil
	case "sum", "total":
		return aggSum, nil
	default:
		return 0, fmt.Errorf("unknown agg %q", s)
	}
}

func compileExpr(src string, termNames []string) (*vm.Program, error) {
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("expr must be set")
	}
	env := make(map[string]any, len(termNames))
	for _, n := range termNames {
		env[n] = float64(0)
	}
	prog, err := expr.Compile(src, expr.Env(env), expr.AsBool())
	if err != nil {
		return nil, err
	}
	return prog, nil
}

func compileAction(c FlowSpecConfig) (flowSpecAction, error) {
	if strings.ToLower(c.Action) != "drop" {
		return flowSpecAction{}, fmt.Errorf("flowspec.action must be drop")
	}
	ttl := c.TTL.Duration()
	if ttl <= 0 {
		return flowSpecAction{}, fmt.Errorf("flowspec.ttl must be > 0")
	}
	refresh := true
	if c.Refresh != nil {
		refresh = *c.Refresh
	}
	a := flowSpecAction{ttl: ttl, refresh: refresh}
	var err error
	if a.family, err = compileField(c.Family); err != nil {
		return flowSpecAction{}, fmt.Errorf("flowspec.family: %w", err)
	}
	if a.proto, err = compileField(c.Proto); err != nil {
		return flowSpecAction{}, fmt.Errorf("flowspec.proto: %w", err)
	}
	if a.src, err = compileField(c.SrcPrefix); err != nil {
		return flowSpecAction{}, fmt.Errorf("flowspec.src_prefix: %w", err)
	}
	if a.dst, err = compileField(c.DstPrefix); err != nil {
		return flowSpecAction{}, fmt.Errorf("flowspec.dst_prefix: %w", err)
	}
	if a.srcPort, err = compileField(c.SrcPort); err != nil {
		return flowSpecAction{}, fmt.Errorf("flowspec.src_port: %w", err)
	}
	if a.dstPort, err = compileField(c.DstPort); err != nil {
		return flowSpecAction{}, fmt.Errorf("flowspec.dst_port: %w", err)
	}
	if a.icmpType, err = compileField(c.ICMPType); err != nil {
		return flowSpecAction{}, fmt.Errorf("flowspec.icmp_type: %w", err)
	}
	if a.icmpCode, err = compileField(c.ICMPCode); err != nil {
		return flowSpecAction{}, fmt.Errorf("flowspec.icmp_code: %w", err)
	}
	return a, nil
}

// aggICMP parses an ICMP type/code aggregate: "exact" (default) keeps the concrete
// value as identity; "all" wildcards it out. Returns whether it is wildcarded.
func aggICMP(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "exact", "keep":
		return false, nil
	case "all", "any":
		return true, nil
	default:
		return false, fmt.Errorf("must be \"exact\" or \"all\", got %q", s)
	}
}

// compileU8List validates an IntList of byte-range values (0-255) used by the
// icmp type/code match filters.
func compileU8List(vals IntList, field string) ([]uint8, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	out := make([]uint8, 0, len(vals))
	for _, v := range vals {
		if v < 0 || v > 255 {
			return nil, fmt.Errorf("%s %d out of range 0-255", field, v)
		}
		out = append(out, uint8(v))
	}
	return out, nil
}

func compileField(s string) (emitField, error) {
	t := strings.TrimSpace(s)
	switch {
	case t == "":
		return emitField{mode: emitDefault}, nil
	case strings.EqualFold(t, "all"), strings.EqualFold(t, "any"):
		return emitField{mode: emitWildcard}, nil
	default:
		tmpl, err := compileTemplate(t)
		if err != nil {
			return emitField{}, err
		}
		return emitField{mode: emitTemplate, tmpl: tmpl}, nil
	}
}

func validIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}
