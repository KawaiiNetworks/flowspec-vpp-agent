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

func TestSlotIndex_NegativeEpoch(t *testing.T) {
	cases := []struct {
		epoch int64
		n     int
		want  int
	}{
		{5, 10, 5},
		{-1, 10, 9},
		{-10, 10, 0},
		{-11, 10, 9},
	}
	for _, c := range cases {
		if got := slotIndex(c.epoch, c.n); got != c.want {
			t.Fatalf("slotIndex(%d, %d) = %d, want %d", c.epoch, c.n, got, c.want)
		}
	}
	// A pre-Unix-epoch timestamp must not panic the ring.
	r := newSampleRing(10, time.Second)
	r.add(time.Unix(-5, 0), 100, 1)
}

func TestEngine_Snapshot(t *testing.T) {
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
				IngressIf:  "GigabitEthernet0/0/0",
				SampleRate: 1000,
			})
		}
	}
	// Tick first so the instance's firing state (trueSince) is populated.
	engine.Tick(last, EvalContext{})
	snap := engine.Snapshot(last, EvalContext{})
	if len(snap.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(snap.Rules))
	}
	rs := snap.Rules[0]
	if rs.Name != "udp-small-src-flood" || rs.MaxInstances != 100 {
		t.Fatalf("rule snapshot = %+v", rs)
	}
	if rs.InstanceCount != 1 || len(rs.Instances) != 1 {
		t.Fatalf("instances = %d/%d, want 1", rs.InstanceCount, len(rs.Instances))
	}
	in := rs.Instances[0]
	if in.Src != "198.51.100.9/32" || in.Proto != "17" {
		t.Fatalf("instance descriptor = %+v", in)
	}
	if in.IngressIf != "GigabitEthernet0/0/0" {
		t.Fatalf("ingress_if = %q", in.IngressIf)
	}
	if !in.Firing {
		t.Fatalf("instance should be firing")
	}
	if in.PPS <= 100000 {
		t.Fatalf("pps = %f, want >100000", in.PPS)
	}
	if v, ok := in.Terms["short"]; !ok || v <= 100000 {
		t.Fatalf("term short = %v (ok=%v), want >100000", v, ok)
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

// Cold-start fix: once the pool is full of light targets, a genuinely heavier new
// target (per the HeavyKeeper sketch) must still be admitted, displacing a light
// one — the old single-sample admission froze the table instead.
func TestEngine_HeavyNewcomerDisplacesLight(t *testing.T) {
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
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{src}}" }
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(5000, 0)
	obs := func(src string, n int) {
		for i := 0; i < n; i++ {
			engine.Observe(Sample{
				At: now, Family: flowspec.FamilyIPv4,
				Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr("203.0.113.1"),
				Proto: protoUDP, PacketLen: 100, SampleRate: 1,
			})
		}
	}
	tracks := func(src string) bool {
		want := netip.MustParseAddr(src)
		for k := range rules[0].store.items {
			if k.src == want {
				return true
			}
		}
		return false
	}

	obs("198.51.100.1", 1)  // light A
	obs("198.51.100.2", 1)  // light B -> pool full (2)
	obs("198.51.100.3", 50) // heavy newcomer

	if got := rules[0].InstanceCount(); got != 2 {
		t.Fatalf("instance count = %d, want 2", got)
	}
	if !tracks("198.51.100.3") {
		t.Fatal("heavy newcomer was not admitted (cold-start starvation)")
	}
}

// rank: <bps term> ranks the pool by bytes, so a low-pps/high-bps victim
// (reflection-shaped) outranks a high-pps/low-bps one for the single slot.
func TestEngine_RankByBytes(t *testing.T) {
	cfg := `
rules:
  - name: refl
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    rank: rate
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 1
    trigger:
      terms:
        rate: { metric: bps, window: 5s }
      expr: "rate > 1000000000"
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{src}}" }
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !rules[0].rankBytes {
		t.Fatal("rank: rate should rank by bytes (bps term)")
	}
	engine := NewEngine(rules)
	now := time.Unix(6000, 0)
	obs := func(src string, n int, plen uint16) {
		for i := 0; i < n; i++ {
			engine.Observe(Sample{
				At: now, Family: flowspec.FamilyIPv4,
				Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr("203.0.113.1"),
				Proto: protoUDP, PacketLen: plen, SampleRate: 1,
			})
		}
	}
	tracks := func(src string) bool {
		want := netip.MustParseAddr(src)
		for k := range rules[0].store.items {
			if k.src == want {
				return true
			}
		}
		return false
	}

	obs("198.51.100.10", 100, 64)  // many small packets: high pps, 6400 bytes
	obs("198.51.100.11", 10, 1400) // few large packets: low pps, 14000 bytes

	if !tracks("198.51.100.11") {
		t.Fatal("high-bytes victim should hold the slot under rank: rate")
	}
	if tracks("198.51.100.10") {
		t.Fatal("high-pps/low-bytes victim should have been displaced")
	}
}

func TestCompile_RankErrors(t *testing.T) {
	base := func(rank string) string {
		return `
rules:
  - name: r
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    rank: ` + rank + `
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 2 }
    trigger:
      terms:
        pps: { metric: pps, window: 5s }
      expr: "pps > 1"
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{src}}" }
`
	}
	if _, err := CompileConfig([]byte(base("nope"))); err == nil {
		t.Fatal("expected error for rank referencing an undefined term")
	}
	if _, err := CompileConfig([]byte(base("pps"))); err != nil {
		t.Fatalf("rank: pps should compile: %v", err)
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
        drops: { metric: vpp.packet_iface.sw_drop_pps }
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

// A windowed vpp term compiles and records its window/offset for coverage
// validation; sum aggregation is rejected for rate metrics.
func TestCompile_VPPWindowTerm(t *testing.T) {
	cfg := `
rules:
  - name: total-spike
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 10
    trigger:
      terms:
        recent: { metric: vpp.total.rx_bps, window: 10s }
        base:   { metric: vpp.total.rx_bps, window: 1m, offset: 1m, agg: max }
      expr: "recent > 3 * base"
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{src}}" }
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	got := rules[0].StatsWindows()
	if len(got) != 2 {
		t.Fatalf("stats windows = %+v, want 2", got)
	}

	// sum is not a valid aggregation for vpp rate metrics.
	bad := `
rules:
  - name: bad
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 10
    trigger:
      terms:
        t: { metric: vpp.total.rx_pps, window: 10s, agg: sum }
      expr: "t > 1"
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{src}}" }
`
	if _, err := CompileConfig([]byte(bad)); err == nil {
		t.Fatal("expected error: agg sum on vpp metric")
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

// An ICMPv6 rule keyed per-type tracks each type as its own instance and emits a
// drop for only that type — so an echo-request (128) flood does not produce a rule
// that would also block Neighbor Discovery (135). icmp_code: all is never emitted.
func TestEngine_ICMPv6PerTypeEmitNDPSafe(t *testing.T) {
	cfg := `
rules:
  - name: icmp6
    match: { family: ipv6, proto: icmpv6 }
    aggregate: { proto: exact, src: "/0", dst: "/128", icmp_type: exact, icmp_code: all }
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 100 }
    trigger:
      terms:
        pps: { metric: pps, window: 1s }
      expr: "pps > 0"
    flowspec: { action: drop, ttl: 60s }
    description: "icmpv6 type {{icmp_type}} to {{dst}}"
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(8000, 0)
	victim := netip.MustParseAddr("2001:db8::1")
	src := netip.MustParseAddr("2001:db8::99")
	for i := 0; i < 5; i++ { // echo-request flood
		engine.Observe(Sample{At: now, Family: flowspec.FamilyIPv6, Src: src, Dst: victim,
			Proto: protoICMPv6, ICMPType: 128, ICMPCode: 0, PacketLen: 64, SampleRate: 1})
	}
	// One Neighbor Solicitation (NDP) to the same victim.
	engine.Observe(Sample{At: now, Family: flowspec.FamilyIPv6, Src: src, Dst: victim,
		Proto: protoICMPv6, ICMPType: 135, ICMPCode: 0, PacketLen: 64, SampleRate: 1})

	if got := rules[0].InstanceCount(); got != 2 {
		t.Fatalf("instance count = %d, want 2 (types 128 and 135 are distinct)", got)
	}
	var got128 bool
	for _, ev := range engine.Tick(now, EvalContext{}) {
		m := ev.Rule.Match
		if len(m.ICMPCode) != 0 {
			t.Fatalf("icmp_code: all should never emit a code, got %+v", m.ICMPCode)
		}
		if len(m.ICMPType) == 1 && m.ICMPType[0].EQ && m.ICMPType[0].Value == 128 {
			got128 = true
		}
	}
	if !got128 {
		t.Fatal("expected an emitted drop carrying icmp-type 128")
	}
}

// match.icmp_type restricts which packets count; non-matching types (and any
// non-ICMP packet) are ignored.
func TestEngine_ICMPTypeMatchFilter(t *testing.T) {
	cfg := `
rules:
  - name: echo-only
    match: { family: ipv6, proto: icmpv6, icmp_type: 128 }
    aggregate: { proto: exact, src: "/0", dst: "/128", icmp_code: all }
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 100 }
    trigger:
      terms:
        pps: { metric: pps, window: 1s }
      expr: "pps > 0"
    flowspec: { action: drop, ttl: 60s }
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(8100, 0)
	victim := netip.MustParseAddr("2001:db8::1")
	src := netip.MustParseAddr("2001:db8::99")
	engine.Observe(Sample{At: now, Family: flowspec.FamilyIPv6, Src: src, Dst: victim,
		Proto: protoICMPv6, ICMPType: 128, PacketLen: 64, SampleRate: 1})
	engine.Observe(Sample{At: now, Family: flowspec.FamilyIPv6, Src: src, Dst: victim,
		Proto: protoICMPv6, ICMPType: 135, PacketLen: 64, SampleRate: 1}) // filtered out
	if got := rules[0].InstanceCount(); got != 1 {
		t.Fatalf("instance count = %d, want 1 (only type 128 counted)", got)
	}
}

// aggregate.icmp_type: all collapses every type into one instance and emits no
// type constraint (drop all ICMP to the victim).
func TestEngine_ICMPAggregateAllCollapses(t *testing.T) {
	cfg := `
rules:
  - name: all-icmp
    match: { family: ipv4, proto: icmp }
    aggregate: { proto: exact, src: "/0", dst: "/32", icmp_type: all, icmp_code: all }
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 100 }
    trigger:
      terms:
        pps: { metric: pps, window: 1s }
      expr: "pps > 0"
    flowspec: { action: drop, ttl: 60s }
`
	rules, err := CompileConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(rules)
	now := time.Unix(8200, 0)
	victim := netip.MustParseAddr("203.0.113.5")
	src := netip.MustParseAddr("198.51.100.1")
	for _, typ := range []uint8{8, 0} { // echo-request + echo-reply collapse
		engine.Observe(Sample{At: now, Family: flowspec.FamilyIPv4, Src: src, Dst: victim,
			Proto: protoICMP, ICMPType: typ, PacketLen: 64, SampleRate: 1})
	}
	if got := rules[0].InstanceCount(); got != 1 {
		t.Fatalf("instance count = %d, want 1 (icmp_type: all collapses)", got)
	}
	events := engine.Tick(now, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if m := events[0].Rule.Match; len(m.ICMPType) != 0 || len(m.ICMPCode) != 0 {
		t.Fatalf("icmp type/code should be wildcard, got type=%v code=%v", m.ICMPType, m.ICMPCode)
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

func (f fakeStats) InterfaceRates(name string) (Rates, bool) {
	v, ok := f[name]
	return Rates{RXPPS: v.rx, TXPPS: v.tx, SWDropPPS: v.drop}, ok
}

func (f fakeStats) TotalRates() Rates {
	var t Rates
	for _, v := range f {
		t.RXPPS += v.rx
		t.TXPPS += v.tx
		t.SWDropPPS += v.drop
	}
	return t
}

// The fake ignores the window and returns its instant rates, which is enough for
// term-plumbing tests; ring aggregation is covered in vppstats.
func (f fakeStats) InterfaceWindow(name string, _ time.Time, _, _ time.Duration, _ bool) (Rates, bool) {
	return f.InterfaceRates(name)
}

func (f fakeStats) TotalWindow(_ time.Time, _, _ time.Duration, _ bool) (Rates, bool) {
	return f.TotalRates(), true
}
