package main

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/localrules"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/sflow"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vppstats"
)

// statusProvider aggregates the live detector state for the JSON /status
// endpoint. Each source is set once during startup (only when the detector is
// enabled) and read at request time; atomic pointers make those concurrent
// reads race-free without coupling the HTTP server to detector wiring order.
type statusProvider struct {
	stats     atomic.Pointer[vppstats.Store]
	runner    atomic.Pointer[detector.Runner]
	leases    atomic.Pointer[localrules.Controller]
	collector atomic.Pointer[sflow.Collector]
	started   time.Time // process start, used to average drop rates
}

func (p *statusProvider) setStats(s *vppstats.Store)         { p.stats.Store(s) }
func (p *statusProvider) setRunner(r *detector.Runner)       { p.runner.Store(r) }
func (p *statusProvider) setLeases(c *localrules.Controller) { p.leases.Store(c) }
func (p *statusProvider) setCollector(c *sflow.Collector)    { p.collector.Store(c) }

// statusResponse is the JSON body served at /status: current interface traffic,
// the per-rule instance state, and the active synthetic FlowSpec leases.
type statusResponse struct {
	Time    time.Time                    `json:"time"`
	Traffic []vppstats.InterfaceSnapshot `json:"traffic"`
	Rules   []detector.RuleSnapshot      `json:"rules"`
	Active  []localrules.LeaseSnapshot   `json:"active"`
	Drops   dropStats                    `json:"drops"`
}

// dropStats reports cumulative queue-overflow drops and their average rate since
// process start. Dropped samples mean sampled traffic went unseen; dropped events
// mean a mitigation was never applied — both are operationally significant, so
// they are surfaced here as well as in Prometheus.
type dropStats struct {
	Samples       int64   `json:"samples_dropped_total"`
	SamplesPerSec float64 `json:"samples_dropped_per_sec"`
	Events        int64   `json:"events_dropped_total"`
	EventsPerSec  float64 `json:"events_dropped_per_sec"`
}

func (p *statusProvider) dropSnapshot() dropStats {
	var d dropStats
	if c := p.collector.Load(); c != nil {
		d.Samples = c.Dropped()
	}
	if r := p.runner.Load(); r != nil {
		d.Events = r.DroppedEvents()
	}
	if secs := time.Since(p.started).Seconds(); secs > 0 {
		d.SamplesPerSec = float64(d.Samples) / secs
		d.EventsPerSec = float64(d.Events) / secs
	}
	return d
}

func (p *statusProvider) handler(w http.ResponseWriter, _ *http.Request) {
	resp := statusResponse{
		Time:    time.Now(),
		Traffic: []vppstats.InterfaceSnapshot{},
		Rules:   []detector.RuleSnapshot{},
		Active:  []localrules.LeaseSnapshot{},
		Drops:   p.dropSnapshot(),
	}
	// Keep the empty-slice defaults (so each field always serializes as a JSON
	// array, never null) unless a source returns a non-nil snapshot.
	if s := p.stats.Load(); s != nil {
		if t := s.Snapshot(); t != nil {
			resp.Traffic = t
		}
	}
	if r := p.runner.Load(); r != nil {
		if rules := r.Snapshot().Rules; rules != nil {
			resp.Rules = rules
		}
	}
	if l := p.leases.Load(); l != nil {
		if active := l.Snapshot(); active != nil {
			resp.Active = active
		}
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}
