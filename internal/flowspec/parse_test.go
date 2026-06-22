package flowspec

import (
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// item builds a numeric component item with the given op bits and value.
func numItem(op uint8, val uint64) *bgp.FlowSpecComponentItem {
	return bgp.NewFlowSpecComponentItem(op, val)
}

func TestParseNLRI_IPv4_UDP_DropRule(t *testing.T) {
	// dst 203.0.113.10/32, proto udp(17), dport 443, traffic-rate 0.
	comps := []bgp.FlowSpecComponentInterface{
		bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(32, "203.0.113.10")),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, []*bgp.FlowSpecComponentItem{numItem(numOpEQ, 17)}),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DST_PORT, []*bgp.FlowSpecComponentItem{numItem(numOpEQ, 443)}),
	}
	nlri := bgp.NewFlowSpecIPv4Unicast(comps)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
			bgp.NewTrafficRateExtended(0, 0),
		}),
	}

	rule, err := ParseNLRI(nlri, attrs)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Family != FamilyIPv4 {
		t.Errorf("family = %v, want ipv4", rule.Family)
	}
	if rule.Action.Kind != ActionDrop {
		t.Errorf("action = %v (%s), want drop", rule.Action.Kind, rule.Action.Desc)
	}
	if !rule.Match.HasDst || rule.Match.Dst.String() != "203.0.113.10/32" {
		t.Errorf("dst = %v/%s", rule.Match.HasDst, rule.Match.Dst)
	}
	if len(rule.Match.Proto) != 1 || !rule.Match.Proto[0].EQ || rule.Match.Proto[0].Value != 17 {
		t.Errorf("proto ops = %+v", rule.Match.Proto)
	}
	if len(rule.Match.DstPort) != 1 || rule.Match.DstPort[0].Value != 443 {
		t.Errorf("dport ops = %+v", rule.Match.DstPort)
	}
}

func TestParseNLRI_UnsupportedAction(t *testing.T) {
	comps := []bgp.FlowSpecComponentInterface{
		bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(32, "203.0.113.10")),
	}
	nlri := bgp.NewFlowSpecIPv4Unicast(comps)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
			bgp.NewTrafficRateExtended(65000, 1000000), // rate-limit, not drop
		}),
	}
	rule, err := ParseNLRI(nlri, attrs)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Action.Kind != ActionUnsupported {
		t.Errorf("action = %v, want unsupported", rule.Action.Kind)
	}
}

func TestParseNLRI_IPv6_Fragment(t *testing.T) {
	comps := []bgp.FlowSpecComponentInterface{
		bgp.NewFlowSpecDestinationPrefix6(bgp.NewIPv6AddrPrefix(128, "2001:db8::10"), 0),
		bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_FRAGMENT, []*bgp.FlowSpecComponentItem{numItem(0, 2)}),
	}
	nlri := bgp.NewFlowSpecIPv6Unicast(comps)
	rule, err := ParseNLRI(nlri, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Family != FamilyIPv6 {
		t.Errorf("family = %v, want ipv6", rule.Family)
	}
	if len(rule.Match.Fragment) == 0 {
		t.Errorf("fragment component not parsed")
	}
}
