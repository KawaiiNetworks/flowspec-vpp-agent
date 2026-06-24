package manager

import (
	"context"
	"sort"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vpp"
)

// reconcile recomputes the desired rule set for one family and pushes it to the
// backend as a single acl_add_replace, then updates the entry-count gauge (§12).
//
// v1 reconciles a whole family at once: the standard VPP ACL plugin replaces all
// rules of a Managed ACL in a single call, and since every entry is a deny with
// order-independent semantics (§17), recomputing the full set on each change is
// both correct and simple.
//
// Performance note: each dirty update reconciles immediately, so a burst of
// withdraws (e.g. many detector leases expiring together) triggers one full
// acl_add_replace per withdraw. A future optimization could coalesce them: mark
// the family dirty and reconcile once on a short timer, while keeping announces
// immediate — delaying rule removal is safe, delaying rule installation is not.
// Left unimplemented because full-family replace is simple and correct and the
// rule counts here are typically small.
func (m *Manager) reconcile(ctx context.Context, fam vpp.Family) {
	rules := m.desired(fam)
	if err := m.backend.ReplaceACL(ctx, fam, rules); err != nil {
		m.log.Error("failed to replace ACL", "family", fam.String(), "error", err)
		return
	}
	m.metrics.SetACLEntries(fam.String(), len(rules))
}

// desired returns the deterministic, deduplicated rule set for a family: every
// entry of that family with at least one owner, ordered by canonical key.
func (m *Manager) desired(fam vpp.Family) []vpp.ACLRule {
	var keys []string
	for k, e := range m.entries {
		if e.family == fam && len(e.owners) > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	rules := make([]vpp.ACLRule, 0, len(keys))
	for _, k := range keys {
		rules = append(rules, m.entries[k].acl)
	}
	return rules
}
