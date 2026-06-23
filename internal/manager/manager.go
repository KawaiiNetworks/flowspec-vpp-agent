// Package manager is the single owner of mutable state: the per-rule reference
// counts across multiple FlowSpec sessions (§17) and the reconciliation of the
// resulting desired ACL set against VPP. It consumes bgp.Update events on one
// goroutine (so no locking is needed), translates each rule, and asks the vpp
// backend to make reality match. It never speaks GoVPP directly.
package manager

import (
	"context"
	"log/slog"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/translate"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vpp"
)

// Metrics is the observability seam (§12). A no-op implementation is fine for
// tests; the real one is backed by Prometheus.
type Metrics interface {
	RuleApplied(family, peer string)
	RuleIgnored(reason, family, peer string)
	SetACLEntries(family string, n int)
}

// nopMetrics is used when no metrics sink is supplied.
type nopMetrics struct{}

func (nopMetrics) RuleApplied(string, string)         {}
func (nopMetrics) RuleIgnored(string, string, string) {}
func (nopMetrics) SetACLEntries(string, int)          {}

// entry is one desired VPP ACL rule plus the sessions that currently advertise
// it. The per-session count matters because one peer can announce multiple
// distinct NLRIs that collapse to the same VPP ACL rule. The rule exists in VPP
// iff owners is non-empty (§17).
type entry struct {
	acl    vpp.ACLRule
	family vpp.Family
	owners map[bgp.SessionID]int
}

// Manager holds the reference-count table and drives reconciliation.
type Manager struct {
	backend vpp.Backend
	metrics Metrics
	log     *slog.Logger

	// entries is keyed by the canonical ACL key so identical rules from
	// different sessions collapse to one entry (§17 dedup).
	entries map[string]*entry
	// sessionRules tracks which keys each session advertises, so a session
	// going down can withdraw exactly its rules (§17).
	sessionRules map[bgp.SessionID]map[string]struct{}
	// sessionRoutes tracks per-session FlowSpec NLRI replacement. A later
	// announce for the same NLRI replaces the old ACL key, even when the new rule
	// is unsupported and produces no replacement entry.
	sessionRoutes map[bgp.SessionID]map[string]string
}

// New builds a Manager. metrics may be nil.
func New(backend vpp.Backend, metrics Metrics, logger *slog.Logger) *Manager {
	if metrics == nil {
		metrics = nopMetrics{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		backend:       backend,
		metrics:       metrics,
		log:           logger,
		entries:       make(map[string]*entry),
		sessionRules:  make(map[bgp.SessionID]map[string]struct{}),
		sessionRoutes: make(map[bgp.SessionID]map[string]string),
	}
}

// Run consumes updates until the context is cancelled or the channel closes.
// All state mutation happens on this single goroutine.
func (m *Manager) Run(ctx context.Context, updates <-chan bgp.Update) {
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				return
			}
			m.Apply(ctx, u)
		}
	}
}

// Apply handles one update. It must be called from a single goroutine (Run
// guarantees this); it is also called directly by tests.
func (m *Manager) Apply(ctx context.Context, u bgp.Update) {
	switch u.Op {
	case bgp.OpAnnounce:
		m.announce(ctx, u)
	case bgp.OpWithdraw:
		m.withdraw(ctx, u)
	case bgp.OpSessionDown:
		m.sessionDown(ctx, u)
	case bgp.OpResync:
		m.resync(ctx)
	}
}

// resync re-pushes the full desired state for every family. Used after a VPP
// reconnect, where the Managed ACLs were just re-created empty (§19.3).
func (m *Manager) resync(ctx context.Context) {
	m.log.Info("resyncing all ACLs after VPP reconnect")
	m.reconcile(ctx, vpp.IPv4)
	m.reconcile(ctx, vpp.IPv6)
}

func (m *Manager) announce(ctx context.Context, u bgp.Update) {
	if u.Rule == nil {
		return
	}
	r := *u.Rule
	routeID := routeIdentity(r)
	dirtyFams := map[vpp.Family]struct{}{}
	acl, err := translate.Translate(r)
	if err != nil {
		if fam, dirty := m.removeRoute(routeID, u.Session); dirty {
			dirtyFams[fam] = struct{}{}
		}
		m.reportIgnored(r, u.Peer, err)
		for fam := range dirtyFams {
			m.reconcile(ctx, fam)
		}
		return
	}
	key := acl.Key()
	fam := familyOf(acl)

	oldKey, hadOld := m.routeKey(routeID, u.Session)
	if hadOld && oldKey == key {
		return
	}
	if oldFam, dirty := m.replaceRoute(routeID, key, u.Session); dirty {
		dirtyFams[oldFam] = struct{}{}
	}
	dirty := m.addOwner(key, acl, fam, u.Session)
	m.rememberRoute(routeID, key, u.Session)
	if dirty {
		m.metrics.RuleApplied(r.Family.String(), u.Peer)
		msg := "flowspec rule applied"
		if hadOld {
			msg = "flowspec rule updated"
		}
		m.log.Info(msg,
			"session", u.Session, "peer", u.Peer, "family", r.Family.String(), "key", key)
		dirtyFams[fam] = struct{}{}
	}
	for fam := range dirtyFams {
		m.reconcile(ctx, fam)
	}
}

func (m *Manager) withdraw(ctx context.Context, u bgp.Update) {
	if u.Rule == nil {
		return
	}
	if fam, dirty := m.removeRoute(routeIdentity(*u.Rule), u.Session); dirty {
		m.log.Info("flowspec rule withdrawn",
			"session", u.Session, "peer", u.Peer, "family", u.Rule.Family.String())
		m.reconcile(ctx, fam)
	}
}

func (m *Manager) sessionDown(ctx context.Context, u bgp.Update) {
	keys := m.sessionRules[u.Session]
	if len(keys) == 0 {
		delete(m.sessionRules, u.Session)
		return
	}
	dirty := map[vpp.Family]struct{}{}
	for key := range keys {
		if e, ok := m.entries[key]; ok {
			fam := e.family
			if m.removeSessionOwner(key, u.Session) {
				dirty[fam] = struct{}{}
			}
		}
	}
	delete(m.sessionRules, u.Session)
	delete(m.sessionRoutes, u.Session)
	for fam := range dirty {
		m.reconcile(ctx, fam)
	}
}

func (m *Manager) reportIgnored(r flowspec.Rule, peer string, err error) {
	reason := string(translate.ReasonUnsupportedComponent)
	detail := err.Error()
	if u, ok := translate.AsUnsupported(err); ok {
		reason = string(u.Reason)
		detail = u.Detail
	}
	m.metrics.RuleIgnored(reason, r.Family.String(), peer)
	m.log.Warn("flowspec rule ignored",
		"reason", reason,
		"detail", detail,
		"family", r.Family.String(),
		"peer", peer,
		"original_flowspec", r.Raw,
	)
}

func familyOf(acl vpp.ACLRule) vpp.Family {
	if acl.IsIPv6 {
		return vpp.IPv6
	}
	return vpp.IPv4
}
