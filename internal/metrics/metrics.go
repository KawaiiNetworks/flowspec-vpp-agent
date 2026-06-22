// Package metrics exposes the observability surface required by §12: ignored and
// applied rule counters and an ACL-entry gauge, all dimensioned so an operator
// can alert on silently-dropped FlowSpec rules. The Metrics type structurally
// satisfies manager.Metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds the Prometheus collectors.
type Metrics struct {
	ignored *prometheus.CounterVec
	applied *prometheus.CounterVec
	entries *prometheus.GaugeVec
}

// New registers the collectors on the given registry and returns the Metrics.
func New(reg prometheus.Registerer) *Metrics {
	factory := promauto.With(reg)
	return &Metrics{
		// reason at least distinguishes: unsupported_component, unsupported_expression,
		// unsupported_action, unmappable_prefix (§12).
		ignored: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "flowspec_rules_ignored_total",
			Help: "FlowSpec rules ignored because they cannot be equivalently mapped to a VPP ACL.",
		}, []string{"reason", "family", "peer"}),
		applied: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "flowspec_rules_applied_total",
			Help: "FlowSpec rules accepted and applied to a Managed ACL.",
		}, []string{"family", "peer"}),
		entries: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flowspec_acl_entries",
			Help: "Current number of entries in each Managed ACL.",
		}, []string{"family"}),
	}
}

// RuleApplied increments the applied counter (§12).
func (m *Metrics) RuleApplied(family, peer string) {
	m.applied.WithLabelValues(family, peer).Inc()
}

// RuleIgnored increments the ignored counter (§12).
func (m *Metrics) RuleIgnored(reason, family, peer string) {
	m.ignored.WithLabelValues(reason, family, peer).Inc()
}

// SetACLEntries sets the per-family ACL entry-count gauge (§12).
func (m *Metrics) SetACLEntries(family string, n int) {
	m.entries.WithLabelValues(family).Set(float64(n))
}
