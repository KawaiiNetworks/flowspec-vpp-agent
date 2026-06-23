package detector

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

const udpFloodYAML = `
rules:
  - name: udp-small-src-flood
    match:
      family: ipv4
      proto: udp
      packet_len:
        lt: 100
    aggregate:
      src: "/32"
    history:
      fine: { resolution: 1s, duration: 30s }
      medium: { resolution: 1m, duration: 1d }
      coarse: { resolution: 1h, duration: 7d }
      max_instances: 100
    trigger:
      terms:
        short: { metric: pps, window: 10s }
      expr: "short > 100000"
    flowspec:
      action: drop
      ttl: 300s
      refresh: true
    description: "UDP small-packet flood from {{src}}, pps={{short}}"
`

func TestCompileConfig_Rings(t *testing.T) {
	rules, err := CompileConfig([]byte(udpFloodYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("compiled %d rules, want 1", len(rules))
	}
	r := rules[0]
	if r.Name() != "udp-small-src-flood" || r.MaxInstances() != 100 {
		t.Fatalf("name=%q max=%d", r.Name(), r.MaxInstances())
	}
	inst := newInstance(descriptor{}, r.history, time.Unix(0, 0))
	if len(inst.fine.slots) != 30 {
		t.Fatalf("fine slots = %d, want 30", len(inst.fine.slots))
	}
	if inst.medium == nil || len(inst.medium.slots) != 1440 {
		t.Fatalf("medium slots = %v, want 1440", ringSlots(inst.medium))
	}
	if inst.coarse == nil || len(inst.coarse.slots) != 168 {
		t.Fatalf("coarse slots = %v, want 168", ringSlots(inst.coarse))
	}
}

func TestEngine_UDPFloodTriggers(t *testing.T) {
	rules, err := CompileConfig([]byte(udpFloodYAML))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	start := time.Unix(1000, 0)
	var last time.Time
	for sec := 0; sec < 20; sec++ {
		at := start.Add(time.Duration(sec) * time.Second)
		last = at
		for n := 0; n < 101; n++ {
			engine.Observe(Sample{
				At:         at,
				Family:     flowspec.FamilyIPv4,
				Src:        netip.MustParseAddr("198.51.100.9"),
				Dst:        netip.MustParseAddr("203.0.113.10"),
				Proto:      protoUDP,
				PacketLen:  80,
				SampleRate: 1000,
			})
		}
	}
	events := engine.Tick(last, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.TTL != 300*time.Second {
		t.Fatalf("ttl = %s, want 300s", ev.TTL)
	}
	if ev.ObservedPPS <= 100000 {
		t.Fatalf("observed pps = %f, want >100000", ev.ObservedPPS)
	}
	if !ev.Rule.Match.HasSrc || ev.Rule.Match.Src.String() != "198.51.100.9/32" {
		t.Fatalf("src = %v/%s, want 198.51.100.9/32", ev.Rule.Match.HasSrc, ev.Rule.Match.Src)
	}
	// proto auto-filled from match (descriptor default).
	if len(ev.Rule.Match.Proto) != 1 || !ev.Rule.Match.Proto[0].EQ || ev.Rule.Match.Proto[0].Value != protoUDP {
		t.Fatalf("proto ops = %+v, want udp equality", ev.Rule.Match.Proto)
	}
	if ev.Rule.Action.Kind != flowspec.ActionDrop {
		t.Fatalf("action = %v, want drop", ev.Rule.Action.Kind)
	}
}

// Two source IPs in the same /24 collapse to one instance and emit the /24.
func TestEngine_AggregateCollapsesInstances(t *testing.T) {
	cfg := `
rules:
  - name: subnet-flood
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/24" }
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 100
    trigger:
      terms:
        short: { metric: pps, window: 1s }
      expr: "short > 0"
    flowspec:
      action: drop
      ttl: 60s
      src_prefix: "{{src}}"
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(2000, 0)
	for _, ip := range []string{"198.51.100.9", "198.51.100.200"} {
		engine.Observe(Sample{
			At: now, Family: flowspec.FamilyIPv4,
			Src: netip.MustParseAddr(ip), Dst: netip.MustParseAddr("203.0.113.1"),
			Proto: protoUDP, PacketLen: 100, SampleRate: 1,
		})
	}
	if got := rules[0].InstanceCount(); got != 1 {
		t.Fatalf("instance count = %d, want 1 (same /24)", got)
	}
	events := engine.Tick(now, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Rule.Match.Src.String() != "198.51.100.0/24" {
		t.Fatalf("src = %s, want 198.51.100.0/24", events[0].Rule.Match.Src)
	}
}

// short > 5 * base, evaluated from the fine ring with an offset baseline.
func TestEngine_RelativeComparison(t *testing.T) {
	cfg := `
rules:
  - name: spike
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history:
      fine: { resolution: 1s, duration: 40s }
      max_instances: 100
    trigger:
      terms:
        short: { metric: pps, window: 5s }
        base:  { metric: pps, window: 20s, offset: 5s }
      expr: "short > 5 * base and short > 100"
    flowspec:
      action: drop
      ttl: 60s
      src_prefix: "{{src}}"
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	start := time.Unix(3000, 0)
	src := netip.MustParseAddr("198.51.100.5")
	observe := func(at time.Time, count int) {
		for n := 0; n < count; n++ {
			engine.Observe(Sample{
				At: at, Family: flowspec.FamilyIPv4, Src: src,
				Dst: netip.MustParseAddr("203.0.113.1"), Proto: protoUDP,
				PacketLen: 100, SampleRate: 1,
			})
		}
	}
	var last time.Time
	for sec := 0; sec < 20; sec++ { // baseline 10 pps
		last = start.Add(time.Duration(sec) * time.Second)
		observe(last, 10)
	}
	for sec := 20; sec < 25; sec++ { // spike 1000 pps
		last = start.Add(time.Duration(sec) * time.Second)
		observe(last, 1000)
	}
	events := engine.Tick(last, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 (spike over baseline)", len(events))
	}
}

func TestEngine_MaxInstancesBounded(t *testing.T) {
	cfg := `
rules:
  - name: tiny
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 2
    trigger:
      terms:
        short: { metric: pps, window: 1s }
      expr: "short > 0"
    flowspec:
      action: drop
      ttl: 10s
      src_prefix: "{{src}}"
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(4000, 0)
	for i := 1; i <= 20; i++ {
		engine.Observe(Sample{
			At: now, Family: flowspec.FamilyIPv4,
			Src:   netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}),
			Dst:   netip.MustParseAddr("203.0.113.1"),
			Proto: protoUDP, PacketLen: 100, SampleRate: 1,
		})
	}
	if got := rules[0].InstanceCount(); got != 2 {
		t.Fatalf("instance count = %d, want fixed cap 2", got)
	}
}

func TestEngine_VPPStatsMetric(t *testing.T) {
	cfg := `
rules:
  - name: ingress-drops
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 10
    trigger:
      terms:
        drops: { metric: vpp.ingress.drop_pps }
      expr: "drops > 1000"
    flowspec:
      action: drop
      ttl: 10s
      src_prefix: "{{src}}"
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(5000, 0)
	engine.Observe(Sample{
		At: now, Family: flowspec.FamilyIPv4,
		Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("203.0.113.1"),
		Proto: protoUDP, PacketLen: 100, IngressIf: "ifindex:3", SampleRate: 1,
	})
	ctx := EvalContext{Stats: fakeStats{"ifindex:3": {drop: 2000}}}
	events := engine.Tick(now, ctx)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].ObservedPPS != 2000 {
		t.Fatalf("observed = %f, want 2000", events[0].ObservedPPS)
	}
}

// Aggregating proto/ports to "all" widens the emitted FlowSpec to block every
// protocol and port from the source, while the descriptor identity stays the
// source host.
func TestEngine_AggregateAllWidensFlowSpec(t *testing.T) {
	cfg := `
rules:
  - name: scan-block
    match: { family: ipv4, proto: tcp, dst_port: 22 }
    aggregate:
      src: "/32"
      dst: "/0"
      proto: all
      src_port: all
      dst_port: all
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 100
    trigger:
      terms:
        rate: { metric: pps, window: 1s }
      expr: "rate > 0"
    flowspec:
      action: drop
      ttl: 60s
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(6000, 0)
	// Two destinations/ports from one source collapse to one instance because
	// dst/0, proto and ports are all aggregated away.
	for _, dp := range []uint16{22, 23} {
		engine.Observe(Sample{
			At: now, Family: flowspec.FamilyIPv4,
			Src: netip.MustParseAddr("198.51.100.7"), Dst: netip.MustParseAddr("203.0.113.9"),
			Proto: protoTCP, DstPort: dp, PacketLen: 60, SampleRate: 1,
		})
	}
	if got := rules[0].InstanceCount(); got != 1 {
		t.Fatalf("instance count = %d, want 1", got)
	}
	events := engine.Tick(now, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	m := events[0].Rule.Match
	if !m.HasSrc || m.Src.String() != "198.51.100.7/32" {
		t.Fatalf("src = %v/%s, want 198.51.100.7/32", m.HasSrc, m.Src)
	}
	if m.HasDst {
		t.Fatalf("dst should be wildcard, got %s", m.Dst)
	}
	if len(m.Proto) != 0 || len(m.SrcPort) != 0 || len(m.DstPort) != 0 {
		t.Fatalf("proto/ports should be wildcard, got proto=%v sport=%v dport=%v", m.Proto, m.SrcPort, m.DstPort)
	}
}

// A numeric bucket aggregate collapses ports within one bucket and emits the
// bucket's contiguous range.
func TestEngine_PortBucketAggregate(t *testing.T) {
	cfg := `
rules:
  - name: bucketed
    match: { family: ipv4, proto: udp }
    aggregate:
      src: "/32"
      dst: "/0"
      dst_port: "100"
      src_port: all
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 100
    trigger:
      terms:
        rate: { metric: pps, window: 1s }
      expr: "rate > 0"
    flowspec:
      action: drop
      ttl: 60s
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(7000, 0)
	// dst ports 101 and 150 fall in the same [100,199] bucket -> one instance.
	for _, dp := range []uint16{101, 150} {
		engine.Observe(Sample{
			At: now, Family: flowspec.FamilyIPv4,
			Src: netip.MustParseAddr("198.51.100.8"), Dst: netip.MustParseAddr("203.0.113.9"),
			Proto: protoUDP, DstPort: dp, PacketLen: 60, SampleRate: 1,
		})
	}
	if got := rules[0].InstanceCount(); got != 1 {
		t.Fatalf("instance count = %d, want 1 (same bucket)", got)
	}
	events := engine.Tick(now, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	dp := events[0].Rule.Match.DstPort
	// Expect a contiguous range 100..199 encoded as >=100 AND <=199.
	if len(dp) != 2 || dp[0].Value != 100 || dp[1].Value != 199 {
		t.Fatalf("dst port ops = %+v, want range 100-199", dp)
	}
}

// A SYN-flood rule counts only SYN-without-ACK packets and emits a drop that
// carries the same tcp-flags constraint (so established connections survive).
func TestEngine_SynFloodFlagsFilterAndEmit(t *testing.T) {
	cfg := `
rules:
  - name: syn-flood
    match: { family: ipv4, proto: tcp, tcp_flags: "syn !ack" }
    aggregate: { proto: exact, src: "/0", dst: "/32", src_port: all, dst_port: all }
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 20
    trigger:
      terms:
        pps: { metric: pps, window: 1s }
      expr: "pps > 0"
    flowspec: { action: drop, ttl: 60s }
    description: "syn flood to {{dst}}"
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(8000, 0)
	syn := Sample{At: now, Family: flowspec.FamilyIPv4, Src: netip.MustParseAddr("198.51.100.1"),
		Dst: netip.MustParseAddr("203.0.113.5"), Proto: protoTCP, TCPFlags: tcpSYN, SampleRate: 1}
	ackOnly := syn
	ackOnly.Src = netip.MustParseAddr("198.51.100.2")
	ackOnly.TCPFlags = tcpACK // established traffic: must be ignored
	engine.Observe(syn)
	engine.Observe(ackOnly)

	events := engine.Tick(now, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 (only SYN counted)", len(events))
	}
	fl := events[0].Rule.Match.TCPFlags
	// Expect SYN required-set and ACK required-clear.
	if len(fl) != 2 || !fl[0].Match || fl[0].Value != uint64(tcpSYN) || !fl[1].Not || fl[1].Value != uint64(tcpACK) {
		t.Fatalf("tcp flag ops = %+v, want syn-set + ack-clear", fl)
	}
}

// Ports do not apply to non-TCP/UDP packets: an ICMP rule with a port aggregate
// compiles, and the emitted rule carries no port constraint.
func TestEngine_PortsIgnoredForNonTCPUDP(t *testing.T) {
	cfg := `
rules:
  - name: icmp-rule
    match: { family: ipv4, proto: icmp }
    aggregate: { src: "/0", dst: "/32", dst_port: "100" }
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 10 }
    trigger:
      terms:
        pps: { metric: pps, window: 1s }
      expr: "pps > 0"
    flowspec: { action: drop, ttl: 10s }
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatalf("icmp rule with a port aggregate should compile: %v", err)
	}
	engine := NewEngine(rules)
	now := time.Unix(9000, 0)
	engine.Observe(Sample{At: now, Family: flowspec.FamilyIPv4,
		Src: netip.MustParseAddr("198.51.100.1"), Dst: netip.MustParseAddr("203.0.113.5"),
		Proto: protoICMP, SampleRate: 1})
	events := engine.Tick(now, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	m := events[0].Rule.Match
	if len(m.SrcPort) != 0 || len(m.DstPort) != 0 {
		t.Fatalf("icmp rule emitted ports: sport=%v dport=%v", m.SrcPort, m.DstPort)
	}
	if len(m.Proto) != 1 || m.Proto[0].Value != protoICMP {
		t.Fatalf("proto = %+v, want icmp", m.Proto)
	}
}

func TestCompile_RejectsPortsWithProtoAll(t *testing.T) {
	cfg := `
rules:
  - name: bad
    match: { family: ipv4, proto: tcp }
    aggregate: { src: "/32", proto: all, dst_port: "100" }
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 10 }
    trigger:
      terms:
        short: { metric: pps, window: 1s }
      expr: "short > 1"
    flowspec: { action: drop, ttl: 10s }
`
	if _, err := CompileConfig([]byte(cfg)); err == nil {
		t.Fatal("expected compile error: ports with proto: all")
	}
}

func TestRule_MemoryEstimate(t *testing.T) {
	rules, err := CompileConfig([]byte(udpFloodYAML))
	if err != nil {
		t.Fatal(err)
	}
	// 100 instances * (30 + 1440 + 168 slots) ought to be a few MiB; just sanity
	// check it is positive and scales with max_instances.
	est := rules[0].MemoryEstimate()
	if est <= 0 {
		t.Fatalf("memory estimate = %d, want > 0", est)
	}
	if NewEngine(rules).MemoryEstimate() != est {
		t.Fatalf("engine estimate should equal the single rule estimate")
	}
}

func TestCompile_RejectsUnknownExprVar(t *testing.T) {
	cfg := `
rules:
  - name: bad
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 10 }
    trigger:
      terms:
        short: { metric: pps, window: 1s }
      expr: "shrot > 1"
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{src}}" }
`
	if _, err := CompileConfig([]byte(cfg)); err == nil {
		t.Fatal("expected compile error for unknown expr variable")
	}
}

func TestCompile_RejectsUnknownFlowSpecVar(t *testing.T) {
	cfg := `
rules:
  - name: bad
    match: { family: ipv4, proto: udp }
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 10 }
    trigger:
      terms:
        short: { metric: pps, window: 1s }
      expr: "short > 1"
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{nope}}" }
`
	if _, err := CompileConfig([]byte(cfg)); err == nil {
		t.Fatal("expected compile error: {{nope}} is not a descriptor field")
	}
}

func ringSlots(r *sampleRing) int {
	if r == nil {
		return 0
	}
	return len(r.slots)
}

type fakeRate struct {
	rx, tx, drop float64
}

type fakeStats map[string]fakeRate

func (f fakeStats) InterfaceRates(name string) (float64, float64, float64, bool) {
	v, ok := f[name]
	return v.rx, v.tx, v.drop, ok
}
