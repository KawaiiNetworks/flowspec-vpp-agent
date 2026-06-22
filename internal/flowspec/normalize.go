package flowspec

import "net/netip"

// Default prefixes used when a FlowSpec rule omits source/destination (§3).
var (
	defaultV4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0) // 0.0.0.0/0
	defaultV6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0) // ::/0
)

// DefaultPrefix returns the any-prefix for the family (0.0.0.0/0 or ::/0).
func (f Family) DefaultPrefix() netip.Prefix {
	if f == FamilyIPv6 {
		return defaultV6
	}
	return defaultV4
}

// DstOrDefault returns the destination prefix, filling the family default when
// absent (§3: "dst missing -> 0.0.0.0/0" / "::/0").
func (m Match) DstOrDefault(f Family) netip.Prefix {
	if m.HasDst {
		return m.Dst
	}
	return f.DefaultPrefix()
}

// SrcOrDefault mirrors DstOrDefault for the source prefix.
func (m Match) SrcOrDefault(f Family) netip.Prefix {
	if m.HasSrc {
		return m.Src
	}
	return f.DefaultPrefix()
}
