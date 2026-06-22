// Package vpp defines the VPP-facing data types and the backend interface that
// turns desired ACL state into reality. The ACLRule type below is the output
// target of the translate package and the unit of state the manager reconciles.
//
// The field layout deliberately mirrors the standard VPP ACL plugin rule
// (acl_types.ACLRule): for ICMP, VPP reuses the src/dst port fields to carry the
// ICMP type and code ranges respectively. We keep the same convention here so the
// GoVPP backend is a near 1:1 field copy.
package vpp

import (
	"fmt"
	"net/netip"
)

// ACLRule is one VPP ACL entry. First-version action is always deny (Permit=false).
//
// For L4 protocols (TCP/UDP) the SrcPort*/DstPort* fields carry port ranges.
// For ICMP/ICMPv6 they carry the ICMP type range (src fields) and code range
// (dst fields), matching the VPP ACL plugin's field reuse.
type ACLRule struct {
	IsIPv6 bool
	Permit bool // false => deny (v1 is deny-only)

	Src netip.Prefix
	Dst netip.Prefix

	Proto uint8 // IANA protocol number; 0 => any

	SrcPortOrICMPTypeFirst uint16
	SrcPortOrICMPTypeLast  uint16
	DstPortOrICMPCodeFirst uint16
	DstPortOrICMPCodeLast  uint16

	TCPFlagsMask  uint8
	TCPFlagsValue uint8
}

// Key returns a stable canonical identity for the rule. Two rules that map to
// the same VPP match (and action) share a Key and are de-duplicated by the
// manager's reference counting (§17). Since v1 is deny-only, the match fully
// determines the entry.
func (r ACLRule) Key() string {
	fam := "ip4"
	if r.IsIPv6 {
		fam = "ip6"
	}
	act := "deny"
	if r.Permit {
		act = "permit"
	}
	return fmt.Sprintf("%s|%s|src=%s|dst=%s|proto=%d|sp=%d-%d|dp=%d-%d|tcp=%02x/%02x",
		fam, act, r.Src.String(), r.Dst.String(), r.Proto,
		r.SrcPortOrICMPTypeFirst, r.SrcPortOrICMPTypeLast,
		r.DstPortOrICMPCodeFirst, r.DstPortOrICMPCodeLast,
		r.TCPFlagsValue, r.TCPFlagsMask)
}

// Family returns a short label used for metrics/log dimensions.
func (r ACLRule) Family() string {
	if r.IsIPv6 {
		return "ipv6"
	}
	return "ipv4"
}
