// Package flowspec holds the agent's internal representation of a BGP FlowSpec
// rule and the parser that builds it from BGP NLRI. The model intentionally
// preserves the *raw* FlowSpec operator lists (numeric/bitmask) so the translate
// package can decide — without losing information — whether each expression maps
// equivalently to a VPP ACL field (§2–§11). No approximation happens here.
package flowspec

import "net/netip"

// Family distinguishes the FlowSpec address family. IPv4 rules may only enter an
// IPv4 Managed ACL and IPv6 rules an IPv6 Managed ACL (§1).
type Family uint8

const (
	FamilyIPv4 Family = iota
	FamilyIPv6
)

func (f Family) String() string {
	switch f {
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// NumericOp is one item of a FlowSpec numeric operator list (RFC 8955 §4.2.1.1),
// used by protocol, ports and ICMP type/code. Items form OR-of-AND terms: an item
// with And=false starts a new OR term (the first item's And is ignored).
type NumericOp struct {
	And bool // ANDed with the previous item rather than starting a new OR term
	LT  bool // less-than bit
	GT  bool // greater-than bit
	EQ  bool // equal bit
	// Value is the comparison operand. Stored wide; callers clamp to the field.
	Value uint64
}

// BitmaskOp is one item of a FlowSpec bitmask operator list (RFC 8955 §4.2.1.2),
// used by tcp-flags and fragment.
type BitmaskOp struct {
	And   bool // ANDed with the previous item
	Not   bool // NOT bit: matched bits must be clear
	Match bool // Match bit: exact "all listed bits" match semantics
	Value uint64
}

// Match holds all FlowSpec match components, defaulted/normalized lazily by the
// translate layer. Absent components are represented by Has*=false / nil slices.
type Match struct {
	HasDst    bool
	Dst       netip.Prefix
	DstOffset uint8 // RFC 8956 IPv6 prefix offset; non-zero is unmappable (§3.2)
	HasSrc    bool
	Src       netip.Prefix
	SrcOffset uint8

	Proto    []NumericOp // type 3 (protocol / next-header)
	DstPort  []NumericOp // type 5
	SrcPort  []NumericOp // type 6
	ICMPType []NumericOp // type 7 / 10
	ICMPCode []NumericOp // type 8 / 11
	TCPFlags []BitmaskOp // type 9
	Fragment []BitmaskOp // type 12 / 13 — parsed only, never mapped (§9)

	// Unsupported components: their mere presence forces the whole rule to be
	// ignored (§2). We record them so translate can report a precise reason.
	HasGenericPort bool // type 4
	HasPacketLen   bool
	HasDSCP        bool
	HasFlowLabel   bool
	HasLabel       bool
	// HasUnknownComponent is set for any component type the agent does not model
	// at all (e.g. ethernet/vlan match types). Its presence forces the rule to be
	// ignored as unsupported_component.
	HasUnknownComponent bool
}

// ActionKind classifies the FlowSpec action after interpreting its extended
// communities (§10).
type ActionKind uint8

const (
	ActionUnknown     ActionKind = iota
	ActionDrop                   // traffic-rate 0 / traffic-rate-packets 0 / discard
	ActionUnsupported            // rate>0, redirect, marking, sample, terminal, ...
)

// Action is the (single) FlowSpec action with a human description for logging.
type Action struct {
	Kind ActionKind
	Desc string
}

// Rule is the fully parsed internal FlowSpec rule.
type Rule struct {
	Family Family
	Match  Match
	Action Action

	// Raw is the textual original FlowSpec, used for logs/metrics (§12).
	Raw string
}
