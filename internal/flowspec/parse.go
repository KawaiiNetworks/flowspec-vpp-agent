package flowspec

import (
	"fmt"
	"net/netip"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// FlowSpec numeric operator bits (RFC 8955 §4.2.1.1) as encoded by GoBGP.
const (
	numOpEQ  = 0x01
	numOpGT  = 0x02
	numOpLT  = 0x04
	numOpAND = 0x40
)

// FlowSpec bitmask operator bits (RFC 8955 §4.2.1.2) as encoded by GoBGP.
const (
	bitOpMatch = 0x01
	bitOpNot   = 0x02
	bitOpAnd   = 0x40
)

// ParseNLRI converts a GoBGP FlowSpec NLRI plus its path attributes into the
// agent's internal Rule. It preserves raw operator lists and records unsupported
// components as markers rather than dropping them — translate decides the rule's
// fate (§12). It returns an error only when the NLRI is not a FlowSpec route or
// is structurally unusable.
func ParseNLRI(nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface) (*Rule, error) {
	var family Family
	var comps []bgp.FlowSpecComponentInterface

	switch n := nlri.(type) {
	case *bgp.FlowSpecIPv4Unicast:
		family = FamilyIPv4
		comps = n.Value
	case *bgp.FlowSpecIPv6Unicast:
		family = FamilyIPv6
		comps = n.Value
	default:
		return nil, fmt.Errorf("not a flowspec NLRI: %T", nlri)
	}

	m, err := parseComponents(comps)
	if err != nil {
		return nil, err
	}

	return &Rule{
		Family: family,
		Match:  m,
		Action: parseAction(attrs),
		Raw:    nlri.String(),
	}, nil
}

func parseComponents(comps []bgp.FlowSpecComponentInterface) (Match, error) {
	var m Match
	for _, comp := range comps {
		switch c := comp.(type) {
		case *bgp.FlowSpecDestinationPrefix:
			p, err := parsePrefix(c.Prefix)
			if err != nil {
				return m, err
			}
			m.HasDst, m.Dst = true, p
		case *bgp.FlowSpecSourcePrefix:
			p, err := parsePrefix(c.Prefix)
			if err != nil {
				return m, err
			}
			m.HasSrc, m.Src = true, p
		case *bgp.FlowSpecDestinationPrefix6:
			p, err := parsePrefix(c.Prefix)
			if err != nil {
				return m, err
			}
			m.HasDst, m.Dst, m.DstOffset = true, p, c.Offset
		case *bgp.FlowSpecSourcePrefix6:
			p, err := parsePrefix(c.Prefix)
			if err != nil {
				return m, err
			}
			m.HasSrc, m.Src, m.SrcOffset = true, p, c.Offset
		case *bgp.FlowSpecComponent:
			parseGenericComponent(&m, c)
		default:
			m.HasUnknownComponent = true
		}
	}
	return m, nil
}

func parseGenericComponent(m *Match, c *bgp.FlowSpecComponent) {
	switch c.Type() {
	case bgp.FLOW_SPEC_TYPE_IP_PROTO:
		m.Proto = numericOps(c.Items)
	case bgp.FLOW_SPEC_TYPE_DST_PORT:
		m.DstPort = numericOps(c.Items)
	case bgp.FLOW_SPEC_TYPE_SRC_PORT:
		m.SrcPort = numericOps(c.Items)
	case bgp.FLOW_SPEC_TYPE_ICMP_TYPE:
		m.ICMPType = numericOps(c.Items)
	case bgp.FLOW_SPEC_TYPE_ICMP_CODE:
		m.ICMPCode = numericOps(c.Items)
	case bgp.FLOW_SPEC_TYPE_TCP_FLAG:
		m.TCPFlags = bitmaskOps(c.Items)
	case bgp.FLOW_SPEC_TYPE_FRAGMENT:
		m.Fragment = bitmaskOps(c.Items)
	case bgp.FLOW_SPEC_TYPE_PORT:
		m.HasGenericPort = true
	case bgp.FLOW_SPEC_TYPE_PKT_LEN:
		m.HasPacketLen = true
	case bgp.FLOW_SPEC_TYPE_DSCP:
		m.HasDSCP = true
	case bgp.FLOW_SPEC_TYPE_LABEL:
		m.HasFlowLabel = true
	default:
		m.HasUnknownComponent = true
	}
}

func numericOps(items []*bgp.FlowSpecComponentItem) []NumericOp {
	out := make([]NumericOp, 0, len(items))
	for _, it := range items {
		out = append(out, NumericOp{
			And:   it.Op&numOpAND != 0,
			EQ:    it.Op&numOpEQ != 0,
			GT:    it.Op&numOpGT != 0,
			LT:    it.Op&numOpLT != 0,
			Value: it.Value,
		})
	}
	return out
}

func bitmaskOps(items []*bgp.FlowSpecComponentItem) []BitmaskOp {
	out := make([]BitmaskOp, 0, len(items))
	for _, it := range items {
		out = append(out, BitmaskOp{
			And:   it.Op&bitOpAnd != 0,
			Not:   it.Op&bitOpNot != 0,
			Match: it.Op&bitOpMatch != 0,
			Value: it.Value,
		})
	}
	return out
}

// parsePrefix converts a GoBGP prefix NLRI (e.g. *bgp.IPAddrPrefix) to netip.
func parsePrefix(p bgp.AddrPrefixInterface) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(p.String())
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse prefix %q: %w", p.String(), err)
	}
	return pfx, nil
}

// parseAction interprets the FlowSpec action extended communities (§10). Only a
// pure drop (traffic-rate 0 / discard) is supported; anything else is recorded
// as an unsupported action so the rule is ignored rather than misapplied.
func parseAction(attrs []bgp.PathAttributeInterface) Action {
	foundDrop := false
	unsupportedDesc := ""

	for _, attr := range attrs {
		ext, ok := attr.(*bgp.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, ec := range ext.Value {
			switch e := ec.(type) {
			case *bgp.TrafficRateExtended:
				if e.Rate == 0 {
					foundDrop = true
				} else {
					unsupportedDesc = fmt.Sprintf("traffic-rate=%v", e.Rate)
				}
			case *bgp.TrafficActionExtended:
				unsupportedDesc = "traffic-action(sample/terminal)"
			case *bgp.TrafficRemarkExtended:
				unsupportedDesc = "traffic-marking(dscp)"
			case *bgp.RedirectTwoOctetAsSpecificExtended,
				*bgp.RedirectIPv4AddressSpecificExtended,
				*bgp.RedirectIPv6AddressSpecificExtended,
				*bgp.RedirectFourOctetAsSpecificExtended:
				unsupportedDesc = "redirect"
			}
		}
	}

	switch {
	case unsupportedDesc != "":
		return Action{Kind: ActionUnsupported, Desc: unsupportedDesc}
	case foundDrop:
		return Action{Kind: ActionDrop, Desc: "traffic-rate=0"}
	default:
		// No recognized action community: cannot assume drop.
		return Action{Kind: ActionUnknown, Desc: "no action"}
	}
}
