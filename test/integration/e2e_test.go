// Package integration exercises the full control-plane pipeline end to end:
// GoBGP FlowSpec NLRI -> flowspec.ParseNLRI -> bgp.Update -> manager refcount /
// reconcile -> VPP backend. It uses a fake VPP backend (no live VPP) and builds
// real GoBGP NLRI, covering the §15 acceptance scenarios that do not require a
// running VPP or live BGP peers.
package integration

import (
	"context"
	"sync"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	bgpsrc "github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/manager"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vpp"
)

// --- fake VPP backend ---

type fakeVPP struct {
	mu    sync.Mutex
	rules map[vpp.Family][]vpp.ACLRule
}

func newVPP() *fakeVPP { return &fakeVPP{rules: map[vpp.Family][]vpp.ACLRule{}} }

func (f *fakeVPP) ReplaceACL(_ context.Context, fam vpp.Family, rules []vpp.ACLRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[fam] = append([]vpp.ACLRule(nil), rules...)
	return nil
}
func (f *fakeVPP) Close() {}
func (f *fakeVPP) get(fam vpp.Family) []vpp.ACLRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules[fam]
}

type metricRec struct {
	applied, ignored int
	lastIgnoreReason string
}

func (m *metricRec) RuleApplied(string, string) { m.applied++ }
func (m *metricRec) RuleIgnored(r, _, _ string) { m.ignored++; m.lastIgnoreReason = r }
func (m *metricRec) SetACLEntries(string, int)  {}

// --- NLRI builders ---

func eqItem(v uint64) []*bgp.FlowSpecComponentItem {
	return []*bgp.FlowSpecComponentItem{bgp.NewFlowSpecComponentItem(0x01, v)} // EQ
}

func v4(comps ...bgp.FlowSpecComponentInterface) bgp.AddrPrefixInterface {
	return bgp.NewFlowSpecIPv4Unicast(comps)
}
func v6(comps ...bgp.FlowSpecComponentInterface) bgp.AddrPrefixInterface {
	return bgp.NewFlowSpecIPv6Unicast(comps)
}

func dropAttrs() []bgp.PathAttributeInterface {
	return []bgp.PathAttributeInterface{
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
			bgp.NewTrafficRateExtended(0, 0),
		}),
	}
}

// feed parses an NLRI and applies it to the manager as one session's announce.
func feed(t *testing.T, m *manager.Manager, session string, op bgpsrc.Op,
	nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface) {
	t.Helper()
	rule, err := flowspec.ParseNLRI(nlri, attrs)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m.Apply(context.Background(), bgpsrc.Update{
		Session: bgpsrc.SessionID(session), Peer: session, Op: op, Rule: rule,
	})
}

func TestE2E_IPv4_UDP_DportDrop(t *testing.T) {
	fb := newVPP()
	m := manager.New(fb, nil, nil)

	nlri := v4(
		bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(32, "203.0.113.10")),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, eqItem(17)),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DST_PORT, eqItem(443)),
	)
	feed(t, m, "s1", bgpsrc.OpAnnounce, nlri, dropAttrs())

	rules := fb.get(vpp.IPv4)
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if r.IsIPv6 || r.Permit || r.Proto != 17 {
		t.Errorf("rule = %+v", r)
	}
	if r.Dst.String() != "203.0.113.10/32" || r.Src.String() != "0.0.0.0/0" {
		t.Errorf("prefixes: dst=%s src=%s", r.Dst, r.Src)
	}
	if r.DstPortOrICMPCodeFirst != 443 || r.DstPortOrICMPCodeLast != 443 {
		t.Errorf("dport = %d-%d", r.DstPortOrICMPCodeFirst, r.DstPortOrICMPCodeLast)
	}
}

func TestE2E_IPv6_TCPFlagsDrop(t *testing.T) {
	fb := newVPP()
	m := manager.New(fb, nil, nil)

	// dst 2001:db8::10/128, proto tcp, dport 443, tcp flags syn,!ack
	nlri := v6(
		bgp.NewFlowSpecDestinationPrefix6(bgp.NewIPv6AddrPrefix(128, "2001:db8::10"), 0),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, eqItem(6)),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DST_PORT, eqItem(443)),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_TCP_FLAG, []*bgp.FlowSpecComponentItem{
			bgp.NewFlowSpecComponentItem(0x00, 0x02),      // SYN must be set
			bgp.NewFlowSpecComponentItem(0x40|0x02, 0x10), // AND, NOT ACK
		}),
	)
	feed(t, m, "s1", bgpsrc.OpAnnounce, nlri, dropAttrs())

	rules := fb.get(vpp.IPv6)
	if len(rules) != 1 {
		t.Fatalf("got %d ipv6 rules, want 1", len(rules))
	}
	r := rules[0]
	if !r.IsIPv6 || r.Proto != 6 {
		t.Errorf("rule = %+v", r)
	}
	if r.TCPFlagsValue != 0x02 || r.TCPFlagsMask != (0x02|0x10) {
		t.Errorf("tcp flags value=%#x mask=%#x, want value=0x02 mask=0x12", r.TCPFlagsValue, r.TCPFlagsMask)
	}
}

func TestE2E_Withdraw(t *testing.T) {
	fb := newVPP()
	m := manager.New(fb, nil, nil)
	build := func() bgp.AddrPrefixInterface {
		return v4(
			bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(32, "203.0.113.10")),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, eqItem(17)),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DST_PORT, eqItem(443)),
		)
	}
	feed(t, m, "s1", bgpsrc.OpAnnounce, build(), dropAttrs())
	if len(fb.get(vpp.IPv4)) != 1 {
		t.Fatal("announce did not create entry")
	}
	// Withdraw carries no action attributes.
	feed(t, m, "s1", bgpsrc.OpWithdraw, build(), nil)
	if len(fb.get(vpp.IPv4)) != 0 {
		t.Fatal("withdraw did not remove entry")
	}
}

func TestE2E_MultiSessionDedupAndPartialWithdraw(t *testing.T) {
	fb := newVPP()
	m := manager.New(fb, nil, nil)
	build := func() bgp.AddrPrefixInterface {
		return v4(
			bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(32, "203.0.113.10")),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, eqItem(17)),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DST_PORT, eqItem(443)),
		)
	}
	feed(t, m, "s1", bgpsrc.OpAnnounce, build(), dropAttrs())
	feed(t, m, "s2", bgpsrc.OpAnnounce, build(), dropAttrs())
	if got := len(fb.get(vpp.IPv4)); got != 1 {
		t.Fatalf("dedup: %d rules, want 1", got)
	}
	feed(t, m, "s1", bgpsrc.OpWithdraw, build(), nil)
	if got := len(fb.get(vpp.IPv4)); got != 1 {
		t.Fatalf("partial withdraw: %d rules, want 1 (s2 holds)", got)
	}
	feed(t, m, "s2", bgpsrc.OpWithdraw, build(), nil)
	if got := len(fb.get(vpp.IPv4)); got != 0 {
		t.Fatalf("final withdraw: %d rules, want 0", got)
	}
}

func TestE2E_FragmentIgnoredWithMetric(t *testing.T) {
	fb := newVPP()
	mx := &metricRec{}
	m := manager.New(fb, mx, nil)

	nlri := v4(
		bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(32, "203.0.113.10")),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_FRAGMENT, []*bgp.FlowSpecComponentItem{
			bgp.NewFlowSpecComponentItem(0x00, 0x02), // is-fragment
		}),
	)
	feed(t, m, "s1", bgpsrc.OpAnnounce, nlri, dropAttrs())

	if got := len(fb.get(vpp.IPv4)); got != 0 {
		t.Fatalf("fragment rule produced %d entries, want 0", got)
	}
	if mx.ignored != 1 || mx.lastIgnoreReason != "unsupported_component" {
		t.Fatalf("ignored=%d reason=%q, want 1/unsupported_component", mx.ignored, mx.lastIgnoreReason)
	}
}
