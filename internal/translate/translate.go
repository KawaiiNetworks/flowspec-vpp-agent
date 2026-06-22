package translate

import (
	"fmt"
	"net/netip"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vpp"
)

const portMax = 65535

// Translate converts an internal FlowSpec Rule into a single VPP ACL rule, or
// returns an *Unsupported error if the rule cannot be mapped equivalently (§12).
// It is pure and stateless. The whole-rule rejection rule applies: if any
// component, expression or action is unsupported, the entire rule is rejected and
// no partial/approximate ACL entry is produced.
//
// The processing order follows §12: components -> expressions -> action.
func Translate(r flowspec.Rule) (vpp.ACLRule, error) {
	m := r.Match

	// 1. Action must be a pure drop (§10). Checked early but does not depend on
	//    match ordering; reported as unsupported_action.
	if r.Action.Kind != flowspec.ActionDrop {
		return vpp.ACLRule{}, unsupported(ReasonUnsupportedAction,
			fmt.Sprintf("action %q is not a pure drop", r.Action.Desc))
	}

	// 2. Reject unsupported components by mere presence (§2, §9). Fragment is
	//    parseable but unmappable: dropping it would widen the match (§9), so the
	//    whole rule is ignored.
	switch {
	case m.HasGenericPort:
		return vpp.ACLRule{}, unsupported(ReasonUnsupportedComponent, "generic port")
	case m.HasPacketLen:
		return vpp.ACLRule{}, unsupported(ReasonUnsupportedComponent, "packet length")
	case m.HasDSCP:
		return vpp.ACLRule{}, unsupported(ReasonUnsupportedComponent, "dscp")
	case m.HasFlowLabel:
		return vpp.ACLRule{}, unsupported(ReasonUnsupportedComponent, "flow label")
	case m.HasLabel:
		return vpp.ACLRule{}, unsupported(ReasonUnsupportedComponent, "label")
	case m.HasUnknownComponent:
		return vpp.ACLRule{}, unsupported(ReasonUnsupportedComponent, "unknown match component")
	case len(m.Fragment) > 0:
		return vpp.ACLRule{}, unsupported(ReasonUnsupportedComponent, "fragment")
	}

	// 3. Prefixes: only offset 0 is mappable (§3.2). Family of a present prefix
	//    must match the rule family.
	if m.HasDst && m.DstOffset != 0 {
		return vpp.ACLRule{}, unsupported(ReasonUnmappablePrefix,
			fmt.Sprintf("dst prefix offset %d != 0", m.DstOffset))
	}
	if m.HasSrc && m.SrcOffset != 0 {
		return vpp.ACLRule{}, unsupported(ReasonUnmappablePrefix,
			fmt.Sprintf("src prefix offset %d != 0", m.SrcOffset))
	}
	dst := m.DstOrDefault(r.Family)
	src := m.SrcOrDefault(r.Family)
	if err := checkFamily(r.Family, m.HasDst, dst); err != nil {
		return vpp.ACLRule{}, err
	}
	if err := checkFamily(r.Family, m.HasSrc, src); err != nil {
		return vpp.ACLRule{}, err
	}

	// 4. Protocol (§4).
	proto, protoPresent, err := reduceProto(m.Proto)
	if err != nil {
		return vpp.ACLRule{}, err
	}

	// 5. TCP flags (§7). Only meaningful for TCP. If present without a protocol,
	//    infer proto=tcp; if present with a non-TCP protocol, reject.
	tcpVal, tcpMask, tcpPresent, err := reduceTCPFlags(m.TCPFlags)
	if err != nil {
		return vpp.ACLRule{}, err
	}
	if tcpPresent {
		if !protoPresent {
			proto, protoPresent = protoTCP, true
		} else if proto != protoTCP {
			return vpp.ACLRule{}, unsupported(ReasonUnsupportedExpression,
				fmt.Sprintf("tcp-flags present but protocol is %d, not tcp", proto))
		}
	}

	// 6. ICMP type/code (§8). If present without a protocol, infer icmp/icmpv6
	//    from the family; if present with a conflicting protocol, reject.
	icmpType, icmpTypePresent, err := reduceExact(m.ICMPType, "icmp type")
	if err != nil {
		return vpp.ACLRule{}, err
	}
	icmpCode, icmpCodePresent, err := reduceExact(m.ICMPCode, "icmp code")
	if err != nil {
		return vpp.ACLRule{}, err
	}
	icmpPresent := icmpTypePresent || icmpCodePresent
	if icmpPresent {
		want := uint8(protoICMP)
		if r.Family == flowspec.FamilyIPv6 {
			want = protoICMPv6
		}
		if !protoPresent {
			proto, protoPresent = want, true
		} else if proto != want {
			return vpp.ACLRule{}, unsupported(ReasonUnsupportedExpression,
				fmt.Sprintf("icmp type/code present but protocol is %d, not %d", proto, want))
		}
	}

	out := vpp.ACLRule{
		IsIPv6: r.Family == flowspec.FamilyIPv6,
		Permit: false, // deny (§10)
		Src:    src,
		Dst:    dst,
	}
	if protoPresent {
		out.Proto = proto
	}

	if icmpPresent {
		// VPP reuses the port fields for ICMP type (src) and code (dst). Absent
		// type/code means "any", i.e. the full 0-255 range.
		out.SrcPortOrICMPTypeFirst, out.SrcPortOrICMPTypeLast = icmpRange(icmpType, icmpTypePresent)
		out.DstPortOrICMPCodeFirst, out.DstPortOrICMPCodeLast = icmpRange(icmpCode, icmpCodePresent)
	} else {
		// L4 port ranges (§5, §6). Absent -> full range.
		sLo, sHi, err := reduceRange(m.SrcPort, portMax, "source port")
		if err != nil {
			return vpp.ACLRule{}, err
		}
		dLo, dHi, err := reduceRange(m.DstPort, portMax, "destination port")
		if err != nil {
			return vpp.ACLRule{}, err
		}
		out.SrcPortOrICMPTypeFirst, out.SrcPortOrICMPTypeLast = uint16(sLo), uint16(sHi)
		out.DstPortOrICMPCodeFirst, out.DstPortOrICMPCodeLast = uint16(dLo), uint16(dHi)
	}

	if tcpPresent {
		out.TCPFlagsValue = tcpVal
		out.TCPFlagsMask = tcpMask
	}

	return out, nil
}

// icmpRange returns the VPP type/code field range: an exact value when present,
// otherwise the full 0-255 "any" range.
func icmpRange(v uint8, present bool) (first, last uint16) {
	if present {
		return uint16(v), uint16(v)
	}
	return 0, 255
}

// checkFamily ensures an explicitly-present prefix matches the rule family.
func checkFamily(f flowspec.Family, present bool, p netip.Prefix) error {
	if !present {
		return nil
	}
	if f == flowspec.FamilyIPv6 && !p.Addr().Is6() {
		return unsupported(ReasonUnmappablePrefix, "ipv4 prefix in ipv6 rule")
	}
	if f == flowspec.FamilyIPv4 && !p.Addr().Is4() {
		return unsupported(ReasonUnmappablePrefix, "ipv6 prefix in ipv4 rule")
	}
	return nil
}
