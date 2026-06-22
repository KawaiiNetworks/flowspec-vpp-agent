package manager

import (
	"fmt"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vpp"
)

// addOwner records that session advertises the rule identified by key. It returns
// true when this changed the entry from "no owners" to "has owners" — i.e. when
// the VPP ACL entry must be (re)created and the family needs reconciling (§17).
func (m *Manager) addOwner(key string, acl vpp.ACLRule, fam vpp.Family, session bgp.SessionID) bool {
	e, ok := m.entries[key]
	created := false
	if !ok {
		e = &entry{acl: acl, family: fam, owners: make(map[bgp.SessionID]int)}
		m.entries[key] = e
		created = true
	}
	wasEmpty := len(e.owners) == 0
	e.owners[session]++

	sr := m.sessionRules[session]
	if sr == nil {
		sr = make(map[string]struct{})
		m.sessionRules[session] = sr
	}
	sr[key] = struct{}{}

	// Reconcile when the entry just appeared or transitioned empty -> non-empty.
	return created || wasEmpty
}

// removeOwner drops one route ownership from session. It returns true when the
// entry became ownerless and was deleted — meaning the VPP ACL entry must be
// removed and the family reconciled (§17: delete only when the last holder
// withdraws).
func (m *Manager) removeOwner(key string, session bgp.SessionID) bool {
	e, ok := m.entries[key]
	if !ok {
		return false
	}
	n := e.owners[session]
	if n == 0 {
		return false
	}
	if n == 1 {
		delete(e.owners, session)
	} else {
		e.owners[session] = n - 1
	}
	if sr := m.sessionRules[session]; sr != nil {
		if e.owners[session] == 0 {
			delete(sr, key)
			if len(sr) == 0 {
				delete(m.sessionRules, session)
			}
		}
	}
	if len(e.owners) == 0 {
		delete(m.entries, key)
		return true
	}
	return false
}

// removeSessionOwner removes all route ownerships for session/key. It is used
// when a session goes down and all its routes are withdrawn at once.
func (m *Manager) removeSessionOwner(key string, session bgp.SessionID) bool {
	e, ok := m.entries[key]
	if !ok {
		return false
	}
	if e.owners[session] == 0 {
		return false
	}
	delete(e.owners, session)
	if len(e.owners) == 0 {
		delete(m.entries, key)
		return true
	}
	return false
}

// replaceRoute removes the old ACL key for a session/NLRI if this announce is a
// route replacement. It returns the old key's family when that removal changed
// desired VPP state.
func (m *Manager) replaceRoute(routeID, newKey string, session bgp.SessionID) (vpp.Family, bool) {
	oldKey, ok := m.routeKey(routeID, session)
	if !ok || oldKey == newKey {
		return 0, false
	}
	return m.removeRoute(routeID, session)
}

// removeRoute forgets a session/NLRI -> key mapping and removes the matching
// rule owner. It is used when a route is withdrawn or replaced by an unsupported
// announce.
func (m *Manager) removeRoute(routeID string, session bgp.SessionID) (vpp.Family, bool) {
	key, ok := m.routeKey(routeID, session)
	if !ok {
		return 0, false
	}
	m.forgetRoute(routeID, session, key)
	e := m.entries[key]
	if e == nil {
		return 0, false
	}
	fam := e.family
	return fam, m.removeOwner(key, session)
}

func (m *Manager) routeKey(routeID string, session bgp.SessionID) (string, bool) {
	routes := m.sessionRoutes[session]
	if routes == nil {
		return "", false
	}
	key, ok := routes[routeID]
	return key, ok
}

func (m *Manager) rememberRoute(routeID, key string, session bgp.SessionID) {
	routes := m.sessionRoutes[session]
	if routes == nil {
		routes = make(map[string]string)
		m.sessionRoutes[session] = routes
	}
	routes[routeID] = key
}

func (m *Manager) forgetRoute(routeID string, session bgp.SessionID, key string) {
	routes := m.sessionRoutes[session]
	if routes == nil {
		return
	}
	if routes[routeID] != key {
		return
	}
	delete(routes, routeID)
	if len(routes) == 0 {
		delete(m.sessionRoutes, session)
	}
}

func routeIdentity(r flowspec.Rule) string {
	if r.Raw != "" {
		return r.Raw
	}
	return fmt.Sprintf("%s:%#v", r.Family.String(), r.Match)
}
