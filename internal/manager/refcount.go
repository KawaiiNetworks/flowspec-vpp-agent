package manager

import (
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vpp"
)

// addOwner records that session advertises the rule identified by key. It returns
// true when this changed the entry from "no owners" to "has owners" — i.e. when
// the VPP ACL entry must be (re)created and the family needs reconciling (§17).
func (m *Manager) addOwner(key string, acl vpp.ACLRule, fam vpp.Family, session bgp.SessionID) bool {
	e, ok := m.entries[key]
	created := false
	if !ok {
		e = &entry{acl: acl, family: fam, owners: make(map[bgp.SessionID]struct{})}
		m.entries[key] = e
		created = true
	}
	wasEmpty := len(e.owners) == 0
	e.owners[session] = struct{}{}

	sr := m.sessionRules[session]
	if sr == nil {
		sr = make(map[string]struct{})
		m.sessionRules[session] = sr
	}
	sr[key] = struct{}{}

	// Reconcile when the entry just appeared or transitioned empty -> non-empty.
	return created || wasEmpty
}

// removeOwner drops session from the entry's owner set. It returns true when the
// entry became ownerless and was deleted — meaning the VPP ACL entry must be
// removed and the family reconciled (§17: delete only when the last holder
// withdraws).
func (m *Manager) removeOwner(key string, session bgp.SessionID) bool {
	e, ok := m.entries[key]
	if !ok {
		return false
	}
	if _, held := e.owners[session]; !held {
		return false
	}
	delete(e.owners, session)
	if sr := m.sessionRules[session]; sr != nil {
		delete(sr, key)
		if len(sr) == 0 {
			delete(m.sessionRules, session)
		}
	}
	if len(e.owners) == 0 {
		delete(m.entries, key)
		return true
	}
	return false
}
