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

// entry is one desired VPP ACL rule plus the set of sessions that currently
// advertise it. The rule exists in VPP iff owners is non-empty (§17).
type entry struct {
	acl    vpp.ACLRule
	family vpp.Family
	owners map[bgp.SessionID]struct{}
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
		backend:      backend,
		metrics:      metrics,
		log:          logger,
		entries:      make(map[string]*entry),
		sessionRules: make(map[bgp.SessionID]map[string]struct{}),
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
	acl, err := translate.Translate(r)
	if err != nil {
		m.reportIgnored(r, u.Peer, err)
		return
	}
	key := acl.Key()
	fam := familyOf(acl)

	dirty := m.addOwner(key, acl, fam, u.Session)
	m.metrics.RuleApplied(r.Family.String(), u.Peer)
	m.log.Debug("flowspec rule applied",
		"session", u.Session, "peer", u.Peer, "family", r.Family.String(), "key", key)
	if dirty {
		m.reconcile(ctx, fam)
	}
}

func (m *Manager) withdraw(ctx context.Context, u bgp.Update) {
	if u.Rule == nil {
		return
	}
	r := *u.Rule
	// A withdrawn path carries no action attributes; force a drop action so the
	// match translates to the same key the announce produced.
	r.Action = flowspec.Action{Kind: flowspec.ActionDrop, Desc: "withdraw"}
	acl, err := translate.Translate(r)
	if err != nil {
		// We never created an entry for an unsupported rule, so withdrawing it is
		// a no-op.
		return
	}
	key := acl.Key()
	fam := familyOf(acl)
	if m.removeOwner(key, u.Session) {
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
			if m.removeOwner(key, u.Session) {
				dirty[e.family] = struct{}{}
			}
		}
	}
	delete(m.sessionRules, u.Session)
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
