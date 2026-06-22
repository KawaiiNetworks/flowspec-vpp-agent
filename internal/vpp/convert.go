package vpp

import (
	"net/netip"

	"go.fd.io/govpp/binapi/acl_types"
	"go.fd.io/govpp/binapi/ip_types"
)

// toBinapiRule converts an internal ACLRule into the GoVPP acl_types.ACLRule.
// The field mapping is 1:1, including the VPP convention of reusing the port
// fields to carry ICMP type/code (the translate layer has already populated them
// accordingly).
func toBinapiRule(r ACLRule) (acl_types.ACLRule, error) {
	pfx, err := toBinapiPrefix(r.Dst)
	if err != nil {
		return acl_types.ACLRule{}, err
	}
	src, err := toBinapiPrefix(r.Src)
	if err != nil {
		return acl_types.ACLRule{}, err
	}
	action := acl_types.ACL_ACTION_API_DENY
	if r.Permit {
		action = acl_types.ACL_ACTION_API_PERMIT
	}
	return acl_types.ACLRule{
		IsPermit:               action,
		SrcPrefix:              src,
		DstPrefix:              pfx,
		Proto:                  ip_types.IPProto(r.Proto),
		SrcportOrIcmptypeFirst: r.SrcPortOrICMPTypeFirst,
		SrcportOrIcmptypeLast:  r.SrcPortOrICMPTypeLast,
		DstportOrIcmpcodeFirst: r.DstPortOrICMPCodeFirst,
		DstportOrIcmpcodeLast:  r.DstPortOrICMPCodeLast,
		TCPFlagsMask:           r.TCPFlagsMask,
		TCPFlagsValue:          r.TCPFlagsValue,
	}, nil
}

func toBinapiPrefix(p netip.Prefix) (ip_types.Prefix, error) {
	return ip_types.ParsePrefix(p.String())
}
