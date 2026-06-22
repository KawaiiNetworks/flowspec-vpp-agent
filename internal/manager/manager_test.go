package manager

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vpp"
)

// fakeBackend records the latest desired rule set per family.
type fakeBackend struct {
	mu      sync.Mutex
	rules   map[vpp.Family][]vpp.ACLRule
	attach  map[vpp.Family]vpp.Direction
	replace int
}

func newFake() *fakeBackend {
	return &fakeBackend{rules: map[vpp.Family][]vpp.ACLRule{}, attach: map[vpp.Family]vpp.Direction{}}
}

func (f *fakeBackend) ReplaceACL(_ context.Context, fam vpp.Family, rules []vpp.ACLRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[fam] = append([]vpp.ACLRule(nil), rules...)
	f.replace++
	return nil
}

func (f *fakeBackend) AttachAll(_ context.Context, fam vpp.Family, dir vpp.Direction) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attach[fam] = dir
	return nil
}

func (f *fakeBackend) Close() {}

func (f *fakeBackend) count(fam vpp.Family) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rules[fam])
}

// countingMetrics records metric calls for assertions.
type countingMetrics struct {
	applied map[string]int // keyed by "family/peer"
	ignored map[string]int // keyed by "reason/family/peer"
	entries map[string]int
}

func newMetrics() *countingMetrics {
	return &countingMetrics{applied: map[string]int{}, ignored: map[string]int{}, entries: map[string]int{}}
}
func (c *countingMetrics) RuleApplied(family, peer string) { c.applied[family+"/"+peer]++ }
func (c *countingMetrics) RuleIgnored(reason, family, peer string) {
	c.ignored[reason+"/"+family+"/"+peer]++
}
func (c *countingMetrics) SetACLEntries(family string, n int) { c.entries[family] = n }

func pfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// v4UDPRule builds a simple "deny dst/32 udp dport" IPv4 rule.
func v4UDPRule(t *testing.T, dst string, dport uint64) *flowspec.Rule {
	return &flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: flowspec.Action{Kind: flowspec.ActionDrop, Desc: "discard"},
		Raw:    fmt.Sprintf("dst %s udp dport %d", dst, dport),
		Match: flowspec.Match{
			HasDst:  true,
			Dst:     pfx(t, dst),
			Proto:   []flowspec.NumericOp{{EQ: true, Value: 17}},
			DstPort: []flowspec.NumericOp{{EQ: true, Value: dport}},
		},
	}
}

func ann(session, peer string, r *flowspec.Rule) bgp.Update {
	return bgp.Update{Session: bgp.SessionID(session), Peer: peer, Op: bgp.OpAnnounce, Rule: r}
}
func wd(session, peer string, r *flowspec.Rule) bgp.Update {
	return bgp.Update{Session: bgp.SessionID(session), Peer: peer, Op: bgp.OpWithdraw, Rule: r}
}

func TestAnnounceWithdraw_SingleSession(t *testing.T) {
	fb := newFake()
	m := New(fb, nil, nil)
	ctx := context.Background()

	m.Apply(ctx, ann("s1", "10.0.0.1", v4UDPRule(t, "203.0.113.10/32", 443)))
	if fb.count(vpp.IPv4) != 1 {
		t.Fatalf("after announce: %d entries, want 1", fb.count(vpp.IPv4))
	}
	m.Apply(ctx, wd("s1", "10.0.0.1", v4UDPRule(t, "203.0.113.10/32", 443)))
	if fb.count(vpp.IPv4) != 0 {
		t.Fatalf("after withdraw: %d entries, want 0", fb.count(vpp.IPv4))
	}
}

// §15: multi-session same-rule dedup — two sessions announce the same rule, only
// one entry is generated.
func TestMultiSession_Dedup(t *testing.T) {
	fb := newFake()
	m := New(fb, nil, nil)
	ctx := context.Background()

	m.Apply(ctx, ann("s1", "10.0.0.1", v4UDPRule(t, "203.0.113.10/32", 443)))
	m.Apply(ctx, ann("s2", "10.0.0.2", v4UDPRule(t, "203.0.113.10/32", 443)))

	if got := fb.count(vpp.IPv4); got != 1 {
		t.Fatalf("dedup failed: %d entries, want 1", got)
	}
}

// §15: multi-session partial withdraw — one session withdraws but the other still
// holds the rule, so the entry is retained.
func TestMultiSession_PartialWithdraw(t *testing.T) {
	fb := newFake()
	m := New(fb, nil, nil)
	ctx := context.Background()

	m.Apply(ctx, ann("s1", "10.0.0.1", v4UDPRule(t, "203.0.113.10/32", 443)))
	m.Apply(ctx, ann("s2", "10.0.0.2", v4UDPRule(t, "203.0.113.10/32", 443)))

	m.Apply(ctx, wd("s1", "10.0.0.1", v4UDPRule(t, "203.0.113.10/32", 443)))
	if got := fb.count(vpp.IPv4); got != 1 {
		t.Fatalf("after partial withdraw: %d entries, want 1 (s2 still holds)", got)
	}

	m.Apply(ctx, wd("s2", "10.0.0.2", v4UDPRule(t, "203.0.113.10/32", 443)))
	if got := fb.count(vpp.IPv4); got != 0 {
		t.Fatalf("after final withdraw: %d entries, want 0", got)
	}
}

// §15: session disconnect == withdraw all of that session's rules.
func TestSessionDown_WithdrawsAll(t *testing.T) {
	fb := newFake()
	m := New(fb, nil, nil)
	ctx := context.Background()

	m.Apply(ctx, ann("s1", "10.0.0.1", v4UDPRule(t, "203.0.113.10/32", 443)))
	m.Apply(ctx, ann("s1", "10.0.0.1", v4UDPRule(t, "203.0.113.11/32", 53)))
	m.Apply(ctx, ann("s2", "10.0.0.2", v4UDPRule(t, "203.0.113.10/32", 443))) // shared with s1

	if got := fb.count(vpp.IPv4); got != 2 {
		t.Fatalf("setup: %d entries, want 2", got)
	}

	m.Apply(ctx, bgp.Update{Session: "s1", Op: bgp.OpSessionDown})

	// .11/53 was only s1's -> gone; .10/443 still held by s2 -> retained.
	if got := fb.count(vpp.IPv4); got != 1 {
		t.Fatalf("after s1 down: %d entries, want 1", got)
	}
}

func TestFamilySeparation(t *testing.T) {
	fb := newFake()
	m := New(fb, nil, nil)
	ctx := context.Background()

	m.Apply(ctx, ann("s1", "p", v4UDPRule(t, "203.0.113.10/32", 443)))
	v6 := &flowspec.Rule{
		Family: flowspec.FamilyIPv6,
		Action: flowspec.Action{Kind: flowspec.ActionDrop},
		Match: flowspec.Match{
			HasDst: true, Dst: pfx(t, "2001:db8::10/128"),
			Proto:   []flowspec.NumericOp{{EQ: true, Value: 17}},
			DstPort: []flowspec.NumericOp{{EQ: true, Value: 443}},
		},
	}
	m.Apply(ctx, ann("s1", "p", v6))

	if fb.count(vpp.IPv4) != 1 || fb.count(vpp.IPv6) != 1 {
		t.Fatalf("family separation: v4=%d v6=%d, want 1/1", fb.count(vpp.IPv4), fb.count(vpp.IPv6))
	}
}

// §12: unsupported rules produce an ignored metric and no entry.
func TestUnsupported_IgnoredMetric(t *testing.T) {
	fb := newFake()
	mx := newMetrics()
	m := New(fb, mx, nil)
	ctx := context.Background()

	// redirect-style unsupported action.
	bad := &flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: flowspec.Action{Kind: flowspec.ActionUnsupported, Desc: "redirect"},
		Match:  flowspec.Match{HasDst: true, Dst: pfx(t, "203.0.113.10/32")},
	}
	m.Apply(ctx, ann("s1", "10.0.0.1", bad))

	if fb.count(vpp.IPv4) != 0 {
		t.Fatalf("unsupported produced %d entries, want 0", fb.count(vpp.IPv4))
	}
	if mx.ignored["unsupported_action/ipv4/10.0.0.1"] != 1 {
		t.Fatalf("ignored metric not recorded: %+v", mx.ignored)
	}
	if mx.applied["ipv4/10.0.0.1"] != 0 {
		t.Fatalf("applied metric should be 0 for ignored rule")
	}
}

func TestAnnounce_ReplacesSameNLRIWithUnsupported(t *testing.T) {
	fb := newFake()
	mx := newMetrics()
	m := New(fb, mx, nil)
	ctx := context.Background()

	good := v4UDPRule(t, "203.0.113.10/32", 443)
	good.Raw = "same-nlri"
	bad := *good
	bad.Action = flowspec.Action{Kind: flowspec.ActionUnsupported, Desc: "redirect"}

	m.Apply(ctx, ann("s1", "10.0.0.1", good))
	if got := fb.count(vpp.IPv4); got != 1 {
		t.Fatalf("setup entries = %d, want 1", got)
	}

	m.Apply(ctx, ann("s1", "10.0.0.1", &bad))

	if got := fb.count(vpp.IPv4); got != 0 {
		t.Fatalf("unsupported replacement left %d entries, want 0", got)
	}
	if mx.ignored["unsupported_action/ipv4/10.0.0.1"] != 1 {
		t.Fatalf("ignored metric not recorded: %+v", mx.ignored)
	}
}

func TestAnnounce_AppliedMetricOnlyForNewOwner(t *testing.T) {
	fb := newFake()
	mx := newMetrics()
	m := New(fb, mx, nil)
	ctx := context.Background()

	r := v4UDPRule(t, "203.0.113.10/32", 443)

	m.Apply(ctx, ann("s1", "10.0.0.1", r))
	m.Apply(ctx, ann("s1", "10.0.0.1", r))

	if got := mx.applied["ipv4/10.0.0.1"]; got != 1 {
		t.Fatalf("applied metric = %d, want 1 after duplicate announce", got)
	}
}
