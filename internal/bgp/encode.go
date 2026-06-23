package bgp

import (
	"fmt"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// FlowSpec operator bits (RFC 8955 §4.2.1), mirroring the decode constants in
// flowspec/parse.go. GoBGP derives the value-length bits and the end-of-list bit
// itself (NewFlowSpecComponentItem / NewFlowSpecComponent), so we only set the
// comparison/logic bits here.
const (
	encNumEQ  = 0x01
	encNumGT  = 0x02
	encNumLT  = 0x04
	encNumAND = 0x40

	encBitMatch = 0x01
	encBitNot   = 0x02
	encBitAnd   = 0x40
)

// encodeNLRI builds a GoBGP FlowSpec NLRI from an internal rule's match. It is the
// inverse of flowspec.ParseNLRI for every component the agent originates, and
// preserves the raw operator lists so a re-advertised rule is byte-faithful.
func encodeNLRI(r flowspec.Rule) (gobgp.AddrPrefixInterface, error) {
	v6 := r.Family == flowspec.FamilyIPv6
	m := r.Match
	var comps []gobgp.FlowSpecComponentInterface

	if m.HasDst {
		p, err := prefixNLRI(m.Dst, v6)
		if err != nil {
			return nil, err
		}
		if v6 {
			comps = append(comps, gobgp.NewFlowSpecDestinationPrefix6(p, m.DstOffset))
		} else {
			comps = append(comps, gobgp.NewFlowSpecDestinationPrefix(p))
		}
	}
	if m.HasSrc {
		p, err := prefixNLRI(m.Src, v6)
		if err != nil {
			return nil, err
		}
		if v6 {
			comps = append(comps, gobgp.NewFlowSpecSourcePrefix6(p, m.SrcOffset))
		} else {
			comps = append(comps, gobgp.NewFlowSpecSourcePrefix(p))
		}
	}
	comps = appendNumeric(comps, gobgp.FLOW_SPEC_TYPE_IP_PROTO, m.Proto)
	comps = appendNumeric(comps, gobgp.FLOW_SPEC_TYPE_DST_PORT, m.DstPort)
	comps = appendNumeric(comps, gobgp.FLOW_SPEC_TYPE_SRC_PORT, m.SrcPort)
	comps = appendNumeric(comps, gobgp.FLOW_SPEC_TYPE_ICMP_TYPE, m.ICMPType)
	comps = appendNumeric(comps, gobgp.FLOW_SPEC_TYPE_ICMP_CODE, m.ICMPCode)
	comps = appendBitmask(comps, gobgp.FLOW_SPEC_TYPE_TCP_FLAG, m.TCPFlags)

	if len(comps) == 0 {
		return nil, fmt.Errorf("flowspec rule has no match components to advertise")
	}
	if v6 {
		return gobgp.NewFlowSpecIPv6Unicast(comps), nil
	}
	return gobgp.NewFlowSpecIPv4Unicast(comps), nil
}

func prefixNLRI(p netip.Prefix, v6 bool) (gobgp.AddrPrefixInterface, error) {
	if !p.IsValid() {
		return nil, fmt.Errorf("invalid prefix")
	}
	bits := uint8(p.Bits())
	addr := p.Addr().String()
	if v6 {
		if !p.Addr().Is6() {
			return nil, fmt.Errorf("ipv4 prefix %s in ipv6 rule", p)
		}
		return gobgp.NewIPv6AddrPrefix(bits, addr), nil
	}
	if !p.Addr().Is4() {
		return nil, fmt.Errorf("ipv6 prefix %s in ipv4 rule", p)
	}
	return gobgp.NewIPAddrPrefix(bits, addr), nil
}

func appendNumeric(comps []gobgp.FlowSpecComponentInterface, typ gobgp.BGPFlowSpecType, ops []flowspec.NumericOp) []gobgp.FlowSpecComponentInterface {
	if len(ops) == 0 {
		return comps
	}
	items := make([]*gobgp.FlowSpecComponentItem, 0, len(ops))
	for _, o := range ops {
		var op uint8
		if o.And {
			op |= encNumAND
		}
		if o.EQ {
			op |= encNumEQ
		}
		if o.GT {
			op |= encNumGT
		}
		if o.LT {
			op |= encNumLT
		}
		items = append(items, gobgp.NewFlowSpecComponentItem(op, o.Value))
	}
	return append(comps, gobgp.NewFlowSpecComponent(typ, items))
}

func appendBitmask(comps []gobgp.FlowSpecComponentInterface, typ gobgp.BGPFlowSpecType, ops []flowspec.BitmaskOp) []gobgp.FlowSpecComponentInterface {
	if len(ops) == 0 {
		return comps
	}
	items := make([]*gobgp.FlowSpecComponentItem, 0, len(ops))
	for _, o := range ops {
		var op uint8
		if o.And {
			op |= encBitAnd
		}
		if o.Not {
			op |= encBitNot
		}
		if o.Match {
			op |= encBitMatch
		}
		items = append(items, gobgp.NewFlowSpecComponentItem(op, o.Value))
	}
	return append(comps, gobgp.NewFlowSpecComponent(typ, items))
}
