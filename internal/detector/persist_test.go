package detector

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// Export then Import (into a freshly compiled identical rule set) must restore the
// instance, its descriptor, and ring contents — so detection resumes from history.
func TestEngine_ExportImportRoundTrip(t *testing.T) {
	rules, err := CompileConfig([]byte(udpFloodYAML))
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("198.51.100.9")
	engine := NewEngine(rules)
	start := time.Unix(1000, 0)
	var last time.Time
	for sec := 0; sec < 20; sec++ {
		at := start.Add(time.Duration(sec) * time.Second)
		last = at
		for n := 0; n < 101; n++ {
			engine.Observe(Sample{
				At: at, Family: flowspec.FamilyIPv4, Src: src,
				Dst: netip.MustParseAddr("203.0.113.10"), Proto: protoUDP,
				PacketLen: 80, SampleRate: 1000,
			})
		}
	}
	if len(rules[0].store.items) != 1 {
		t.Fatalf("want 1 instance before export, got %d", len(rules[0].store.items))
	}

	st := engine.Export()

	// Fresh engine with the same rule definitions.
	rules2, _ := CompileConfig([]byte(udpFloodYAML))
	engine2 := NewEngine(rules2)
	engine2.Import(st)

	if got := rules2[0].InstanceCount(); got != 1 {
		t.Fatalf("restored instance count = %d, want 1", got)
	}
	// The restored instance must fire on the same history the original would.
	events := engine2.Tick(last, EvalContext{})
	if len(events) != 1 {
		t.Fatalf("restored engine events = %d, want 1 (history not restored?)", len(events))
	}
	if events[0].Rule.Match.Src.String() != "198.51.100.9/32" {
		t.Fatalf("restored src = %s", events[0].Rule.Match.Src)
	}
}

// History for a rule that no longer exists, or whose ring shape changed, is skipped.
func TestEngine_ImportSkipsUnknownAndReshaped(t *testing.T) {
	rules, _ := CompileConfig([]byte(udpFloodYAML))
	engine := NewEngine(rules)
	engine.Observe(Sample{
		At: time.Unix(1000, 0), Family: 0, Src: netip.MustParseAddr("198.51.100.9"),
		Dst: netip.MustParseAddr("203.0.113.10"), Proto: protoUDP, PacketLen: 80, SampleRate: 1000,
	})
	st := engine.Export()

	// (a) rule renamed -> not found -> skipped.
	renamed := `
rules:
  - name: different-name
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history: { fine: { resolution: 1s, duration: 30s }, medium: { resolution: 1m, duration: 1d }, coarse: { resolution: 1h, duration: 7d }, max_instances: 100 }
    trigger:
      terms:
        short: { metric: pps, window: 10s }
      expr: "short > 100000"
    flowspec: { action: drop, ttl: 300s, src_prefix: "{{src}}" }
`
	r2, _ := CompileConfig([]byte(renamed))
	e2 := NewEngine(r2)
	e2.Import(st)
	if r2[0].InstanceCount() != 0 {
		t.Fatal("renamed rule should not receive old history")
	}

	// (b) same name, different fine ring duration -> shape mismatch -> skipped.
	reshaped := `
rules:
  - name: udp-small-src-flood
    match: { family: ipv4, proto: udp, packet_len: { lt: 100 } }
    aggregate: { src: "/32" }
    history: { fine: { resolution: 1s, duration: 60s }, medium: { resolution: 1m, duration: 1d }, coarse: { resolution: 1h, duration: 7d }, max_instances: 100 }
    trigger:
      terms:
        short: { metric: pps, window: 10s }
      expr: "short > 100000"
    flowspec: { action: drop, ttl: 300s, refresh: true, src_prefix: "{{src}}" }
`
	r3, _ := CompileConfig([]byte(reshaped))
	e3 := NewEngine(r3)
	e3.Import(st)
	if r3[0].InstanceCount() != 0 {
		t.Fatal("reshaped rule should not receive mismatched history")
	}
}

// A rule whose body changed but whose ring shape is identical must still be
// skipped — the fingerprint, not just the ring shape, gates the reload. Covers
// both a trigger/aggregate edit and a max_instances-only change.
func TestEngine_ImportSkipsChangedRuleBody(t *testing.T) {
	rules, _ := CompileConfig([]byte(udpFloodYAML))
	engine := NewEngine(rules)
	engine.Observe(Sample{
		At: time.Unix(1000, 0), Family: flowspec.FamilyIPv4, Src: netip.MustParseAddr("198.51.100.9"),
		Dst: netip.MustParseAddr("203.0.113.10"), Proto: protoUDP, PacketLen: 80, SampleRate: 1000,
	})
	st := engine.Export()

	// Same name and identical rings, but a changed trigger threshold + aggregate.
	changedBody := `
rules:
  - name: udp-small-src-flood
    match: { family: ipv4, proto: udp, packet_len: { lt: 100 } }
    aggregate: { src: "/24" }
    history:
      fine: { resolution: 1s, duration: 30s }
      medium: { resolution: 1m, duration: 1d }
      coarse: { resolution: 1h, duration: 7d }
      max_instances: 100
    trigger:
      terms:
        short: { metric: pps, window: 10s }
      expr: "short > 50000"
    flowspec: { action: drop, ttl: 300s, refresh: true }
`
	rb, _ := CompileConfig([]byte(changedBody))
	eb := NewEngine(rb)
	eb.Import(st)
	if rb[0].InstanceCount() != 0 {
		t.Fatal("changed rule body should not receive old history")
	}

	// max_instances-only change (ring shape unchanged) must also skip.
	changedMax := `
rules:
  - name: udp-small-src-flood
    match: { family: ipv4, proto: udp, packet_len: { lt: 100 } }
    aggregate: { src: "/32" }
    history:
      fine: { resolution: 1s, duration: 30s }
      medium: { resolution: 1m, duration: 1d }
      coarse: { resolution: 1h, duration: 7d }
      max_instances: 50
    trigger:
      terms:
        short: { metric: pps, window: 10s }
      expr: "short > 100000"
    flowspec: { action: drop, ttl: 300s, refresh: true }
    description: "UDP small-packet flood from {{src}}, pps={{short}}"
`
	rm, _ := CompileConfig([]byte(changedMax))
	em := NewEngine(rm)
	em.Import(st)
	if rm[0].InstanceCount() != 0 {
		t.Fatal("max_instances change should not receive old history")
	}
}
