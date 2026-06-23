package vppstats

import (
	"sync"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
)

// Sample is one interface's rates at a poll instant. drop counters are
// packets-only (VPP has no byte counter for drops). SWDropPPS is /if/drops (VPP
// graph drops, includes ACL deny); HWDropPPS is /if/rx-miss (NIC ring overflow).
type Sample struct {
	At        time.Time
	Name      string   // canonical interface name (or the ifindex key when unnamed)
	Aliases   []string // extra lookup keys resolving to this interface (e.g. "ifindex:N")
	RXPPS     float64
	TXPPS     float64
	RXBPS     float64
	TXBPS     float64
	SWDropPPS float64
	HWDropPPS float64
}

// rates extracts the detector-facing rate view from a sample.
func (s Sample) rates() detector.Rates {
	return detector.Rates{
		RXPPS:     s.RXPPS,
		TXPPS:     s.TXPPS,
		RXBPS:     s.RXBPS,
		TXBPS:     s.TXBPS,
		SWDropPPS: s.SWDropPPS,
		HWDropPPS: s.HWDropPPS,
	}
}

type Store struct {
	mu sync.RWMutex
	// rings holds one ring set per interface, keyed by its canonical name.
	rings map[string]*interfaceRings
	// byAlias maps alternate keys (e.g. "ifindex:N") to the same ring set, so a
	// named interface is stored once but still found by its ifindex.
	byAlias map[string]*interfaceRings
	// total is the sum of every interface's latest rates, recomputed on each Add
	// so TotalRates() is a cheap read (rule evaluation may query it per instance).
	total  detector.Rates
	config RingConfig
}

type RingConfig struct {
	DayResolution   time.Duration
	DayDuration     time.Duration
	WeekResolution  time.Duration
	WeekDuration    time.Duration
	MonthResolution time.Duration
	MonthDuration   time.Duration
}

func DefaultRingConfig() RingConfig {
	return RingConfig{
		DayResolution:   5 * time.Second,
		DayDuration:     24 * time.Hour,
		WeekResolution:  time.Minute,
		WeekDuration:    7 * 24 * time.Hour,
		MonthResolution: 5 * time.Minute,
		MonthDuration:   30 * 24 * time.Hour,
	}
}

func NewStore(config RingConfig) *Store {
	if config.DayResolution <= 0 {
		config = DefaultRingConfig()
	}
	return &Store{
		rings:   make(map[string]*interfaceRings),
		byAlias: make(map[string]*interfaceRings),
		config:  config,
	}
}

func (s *Store) Add(sample Sample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rings[sample.Name]
	if r == nil {
		r = newInterfaceRings(s.config)
		s.rings[sample.Name] = r
	}
	r.add(sample)
	for _, a := range sample.Aliases {
		if a != "" && a != sample.Name {
			s.byAlias[a] = r
		}
	}
	s.recomputeTotal()
}

// recomputeTotal sums the latest rates of every interface. Called under the
// write lock after each Add. O(#interfaces), which is tiny and once per poll.
func (s *Store) recomputeTotal() {
	var t detector.Rates
	for _, r := range s.rings {
		t.RXPPS += r.last.RXPPS
		t.TXPPS += r.last.TXPPS
		t.RXBPS += r.last.RXBPS
		t.TXBPS += r.last.TXBPS
		t.SWDropPPS += r.last.SWDropPPS
		t.HWDropPPS += r.last.HWDropPPS
	}
	s.total = t
}

func (s *Store) Interfaces() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rings)
}

// InterfaceSnapshot is the latest per-interface rates.
type InterfaceSnapshot struct {
	Name      string    `json:"name"`
	At        time.Time `json:"at"`
	RXPPS     float64   `json:"rx_pps"`
	TXPPS     float64   `json:"tx_pps"`
	RXBPS     float64   `json:"rx_bps"`
	TXBPS     float64   `json:"tx_bps"`
	SWDropPPS float64   `json:"sw_drop_pps"`
	HWDropPPS float64   `json:"hw_drop_pps"`
}

// Snapshot returns the latest rate sample for every known interface. Safe to
// call from any goroutine.
func (s *Store) Snapshot() []InterfaceSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]InterfaceSnapshot, 0, len(s.rings))
	for name, r := range s.rings {
		out = append(out, InterfaceSnapshot{
			Name:      name,
			At:        r.last.At,
			RXPPS:     r.last.RXPPS,
			TXPPS:     r.last.TXPPS,
			RXBPS:     r.last.RXBPS,
			TXBPS:     r.last.TXBPS,
			SWDropPPS: r.last.SWDropPPS,
			HWDropPPS: r.last.HWDropPPS,
		})
	}
	return out
}

type interfaceRings struct {
	day   *ring
	week  *ring
	month *ring
	last  Sample
}

func newInterfaceRings(c RingConfig) *interfaceRings {
	return &interfaceRings{
		day:   newRing(c.DayResolution, c.DayDuration),
		week:  newRing(c.WeekResolution, c.WeekDuration),
		month: newRing(c.MonthResolution, c.MonthDuration),
	}
}

func (r *interfaceRings) add(s Sample) {
	r.last = s
	r.day.add(s)
	r.week.add(s)
	r.month.add(s)
}

// InterfaceRates returns the latest rates for one interface, found by canonical
// name or alias (e.g. "ifindex:N"). Implements detector.StatsView.
func (s *Store) InterfaceRates(name string) (detector.Rates, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.rings[name]
	if r == nil {
		r = s.byAlias[name]
	}
	if r == nil {
		return detector.Rates{}, false
	}
	return r.last.rates(), true
}

// TotalRates returns the summed latest rates across all interfaces. Implements
// detector.StatsView.
func (s *Store) TotalRates() detector.Rates {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.total
}

type ring struct {
	resolution time.Duration
	slots      []slot
}

type slot struct {
	epoch   int64
	count   uint64
	rxPPS   float64
	txPPS   float64
	dropPPS float64
}

func newRing(resolution, duration time.Duration) *ring {
	n := int(duration / resolution)
	if n < 1 {
		n = 1
	}
	return &ring{resolution: resolution, slots: make([]slot, n)}
}

// slotIndex maps an epoch onto a ring slot, folding negative epochs (timestamps
// before the Unix epoch) back into [0, n) so % never yields a negative index.
func slotIndex(epoch int64, n int) int {
	idx := epoch % int64(n)
	if idx < 0 {
		idx += int64(n)
	}
	return int(idx)
}

func (r *ring) add(s Sample) {
	epoch := s.At.UnixNano() / r.resolution.Nanoseconds()
	idx := slotIndex(epoch, len(r.slots))
	if r.slots[idx].epoch != epoch {
		r.slots[idx] = slot{epoch: epoch}
	}
	sl := &r.slots[idx]
	sl.count++
	n := float64(sl.count)
	sl.rxPPS += (s.RXPPS - sl.rxPPS) / n
	sl.txPPS += (s.TXPPS - sl.txPPS) / n
	sl.dropPPS += (s.SWDropPPS - sl.dropPPS) / n
}
