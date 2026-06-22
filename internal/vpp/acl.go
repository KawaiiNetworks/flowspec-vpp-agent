package vpp

import (
	"context"
	"fmt"
	"net/netip"

	"go.fd.io/govpp/binapi/acl"
	"go.fd.io/govpp/binapi/acl_types"
)

// ReplaceACL makes the Managed ACL for family hold exactly rules via a single
// acl_add_replace (§18: standard ACL plugin). The first call for a family creates
// the ACL (acl_index = ~0) and remembers the index VPP assigns; later calls
// replace its rule set in place.
func (c *Client) ReplaceACL(ctx context.Context, family Family, rules []ACLRule) error {
	binRules, err := buildACLRules(family, rules)
	if err != nil {
		return err
	}

	c.mu.Lock()
	index := c.idx[family]
	c.mu.Unlock()

	tag := c.cfg.ACLTagV4
	if family == IPv6 {
		tag = c.cfg.ACLTagV6
	}

	reply, err := c.aclc.ACLAddReplace(ctx, &acl.ACLAddReplace{
		ACLIndex: index,
		Tag:      tag,
		Count:    uint32(len(binRules)),
		R:        binRules,
	})
	if err != nil {
		return fmt.Errorf("acl_add_replace (%s): %w", family, err)
	}

	c.mu.Lock()
	c.idx[family] = reply.ACLIndex
	c.mu.Unlock()

	c.log.Debug("replaced managed ACL", "family", family.String(),
		"acl_index", reply.ACLIndex, "rules", len(binRules))
	return nil
}

// buildACLRules converts the FlowSpec-derived deny rules to binapi rules and
// appends a trailing "permit <family> any" entry.
//
// This trailing permit is essential, not cosmetic: the VPP ACL plugin is
// DEFAULT-DENY — a packet that matches no rule in the applied ACL list is
// dropped. Our Managed ACLs carry only specific FlowSpec deny rules, so without a
// final permit-any:
//   - all non-matching (legitimate) traffic of the family would be dropped, and
//   - because ACL rules are tagged per address family, a family with no rules
//     (e.g. an empty IPv6 ACL) would deny ALL of that family's traffic.
// With permit-any last, the ACL behaves as a blocklist ("drop these, permit the
// rest"), which is FlowSpec's intent. permit-any must remain the final entry; the
// deny rules above it are mutually order-independent (§17).
func buildACLRules(family Family, rules []ACLRule) ([]acl_types.ACLRule, error) {
	out := make([]acl_types.ACLRule, 0, len(rules)+1)
	for _, r := range rules {
		br, err := toBinapiRule(r)
		if err != nil {
			return nil, fmt.Errorf("convert rule: %w", err)
		}
		out = append(out, br)
	}
	permit, err := toBinapiRule(permitAny(family))
	if err != nil {
		return nil, fmt.Errorf("build permit-any: %w", err)
	}
	return append(out, permit), nil
}

// permitAny returns a "permit any" rule for the family: any src/dst prefix, any
// protocol, full port range.
func permitAny(family Family) ACLRule {
	r := ACLRule{
		IsIPv6:                 family == IPv6,
		Permit:                 true,
		Proto:                  0, // any
		SrcPortOrICMPTypeFirst: 0,
		SrcPortOrICMPTypeLast:  65535,
		DstPortOrICMPCodeFirst: 0,
		DstPortOrICMPCodeLast:  65535,
	}
	if family == IPv6 {
		r.Src = netip.PrefixFrom(netip.IPv6Unspecified(), 0) // ::/0
		r.Dst = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	} else {
		r.Src = netip.PrefixFrom(netip.IPv4Unspecified(), 0) // 0.0.0.0/0
		r.Dst = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return r
}

// aclIndices returns the currently-known Managed ACL indices, in v4,v6 order,
// skipping any that are still unset.
func (c *Client) aclIndices() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []uint32
	if c.idx[IPv4] != aclIndexUnset {
		out = append(out, c.idx[IPv4])
	}
	if c.idx[IPv6] != aclIndexUnset {
		out = append(out, c.idx[IPv6])
	}
	return out
}
