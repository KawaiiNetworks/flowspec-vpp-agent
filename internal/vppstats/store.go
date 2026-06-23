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

// RingConfig sizes the three history rings (same model as a detector rule's
// history). Each ring keeps Duration/Resolution slots; a coarser ring trades
// resolution for a longer span. A zero dimension falls back to a default.
type RingConfig struct {
	FineResolution   time.Duration
	FineDuration     time.Duration
	MediumResolution time.Duration
	MediumDuration   time.Duration
	CoarseResolution time.Duration
	CoarseDuration   time.Duration
}

// DefaultRingConfig is the built-in ring sizing: 1s×5m / 1m×1d / 1h×30d. Fine is
// kept short and high-resolution for second-scale trigger windows; medium and
// coarse retain longer history for /status and slow baselines.
func DefaultRingConfig() RingConfig {
	return RingConfig{
		FineResolution:   time.Second,
		FineDuration:     5 * time.Minute,
		MediumResolution: time.Minute,
		MediumDuration:   24 * time.Hour,
		CoarseResolution: time.Hour,
		CoarseDuration:   30 * 24 * time.Hour,
	}
}

// withDefaults fills any unset (<=0) dimension from DefaultRingConfig.
func (c RingConfig) withDefaults() RingConfig {
	d := DefaultRingConfig()
	if c.FineResolution <= 0 {
		c.FineResolution = d.FineResolution
	}
	if c.FineDuration <= 0 {
		c.FineDuration = d.FineDuration
	}
	if c.MediumResolution <= 0 {
		c.MediumResolution = d.MediumResolution
	}
	if c.MediumDuration <= 0 {
		c.MediumDuration = d.MediumDuration
	}
	if c.CoarseResolution <= 0 {
		c.CoarseResolution = d.CoarseResolution
	}
	if c.CoarseDuration <= 0 {
		c.CoarseDuration = d.CoarseDuration
	}
	return c
}

// Covers reports whether some ring can serve an aggregate over (window, offset):
// a ring whose resolution divides both and whose span >= window+offset. Used to
// validate detector vpp.* window terms against the configured rings at startup.
func (c RingConfig) Covers(window, offset time.Duration) bool {
	c = c.withDefaults()
	for _, r := range []struct{ res, dur time.Duration }{
		{c.FineResolution, c.FineDuration},
		{c.MediumResolution, c.MediumDuration},
		{c.CoarseResolution, c.CoarseDuration},
	} {
		if !ringCovers(r.res, int(r.dur/r.res), window, offset) {
			continue
		}
		return true
	}
	return false
}

// ringCovers is the shared coverage test for a resolution/slot-count pair.
func ringCovers(res time.Duration, slots int, window, offset time.Duration) bool {
	if res <= 0 || slots < 1 || res > window {
		return false
	}
	if window%res != 0 || offset%res != 0 {
		return false
	}
	span := time.Duration(slots) * res
	return span >= window+offset
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

func NewStore(config RingConfig) *Store {
	return &Store{
		rings:   make(map[string]*interfaceRings),
		byAlias: make(map[string]*interfaceRings),
		config:  config.withDefaults(),
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
		t = addRates(t, r.last.rates())
	}
	s.total = t
}

func (s *Store) Interfaces() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rings)
}

func (s *Store) findRing(name string) *interfaceRings {
	r := s.rings[name]
	if r == nil {
		r = s.byAlias[name]
	}
	return r
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

// InterfaceRates returns the latest (instant) rates for one interface, found by
// canonical name or alias. Implements detector.StatsView.
func (s *Store) InterfaceRates(name string) (detector.Rates, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.findRing(name)
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

// InterfaceWindow aggregates one interface's rates over [now-offset-window,
// now-offset], picking the coarsest ring that covers it. peak selects max-slot
// instead of mean. ok=false if the interface is unknown or no ring covers the
// window. Implements detector.StatsView.
func (s *Store) InterfaceWindow(name string, now time.Time, window, offset time.Duration, peak bool) (detector.Rates, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.findRing(name)
	if r == nil {
		return detector.Rates{}, false
	}
	ring := r.chooseRing(window, offset)
	if ring == nil {
		return detector.Rates{}, false
	}
	return ring.aggregate(now, window, offset, peak), true
}

// TotalWindow aggregates each interface over the window and sums the results.
// For peak this is the sum of per-interface peaks (an upper bound on the true
// peak of the sum). ok=false if no interface has a covering ring. Implements
// detector.StatsView.
func (s *Store) TotalWindow(now time.Time, window, offset time.Duration, peak bool) (detector.Rates, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total detector.Rates
	any := false
	for _, r := range s.rings {
		ring := r.chooseRing(window, offset)
		if ring == nil {
			continue
		}
		total = addRates(total, ring.aggregate(now, window, offset, peak))
		any = true
	}
	return total, any
}

type interfaceRings struct {
	fine   *ring
	medium *ring
	coarse *ring
	last   Sample
}

func newInterfaceRings(c RingConfig) *interfaceRings {
	return &interfaceRings{
		fine:   newRing(c.FineResolution, c.FineDuration),
		medium: newRing(c.MediumResolution, c.MediumDuration),
		coarse: newRing(c.CoarseResolution, c.CoarseDuration),
	}
}

func (r *interfaceRings) add(s Sample) {
	r.last = s
	r.fine.add(s)
	r.medium.add(s)
	r.coarse.add(s)
}

// chooseRing returns the coarsest ring covering (window, offset), or nil. Coarser
// is preferred so a wide window reads fewer slots.
func (r *interfaceRings) chooseRing(window, offset time.Duration) *ring {
	var best *ring
	for _, rg := range []*ring{r.fine, r.medium, r.coarse} {
		if !ringCovers(rg.resolution, len(rg.slots), window, offset) {
			continue
		}
		if best == nil || rg.resolution > best.resolution {
			best = rg
		}
	}
	return best
}

type ring struct {
	resolution time.Duration
	slots      []slot
}

// slot holds the running-mean rates observed during one resolution interval.
type slot struct {
	epoch int64
	count uint64
	rates detector.Rates
}

func newRing(resolution, duration time.Duration) *ring {
	n := int(duration / resolution)
	if n < 1 {
		n = 1
	}
	return &ring{resolution: resolution, slots: make([]slot, n)}
}

func (r *ring) epoch(at time.Time) int64 {
	return at.UnixNano() / r.resolution.Nanoseconds()
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
	epoch := r.epoch(s.At)
	idx := slotIndex(epoch, len(r.slots))
	if r.slots[idx].epoch != epoch {
		r.slots[idx] = slot{epoch: epoch}
	}
	sl := &r.slots[idx]
	sl.count++
	// Running mean of each rate field within the slot (multiple polls per slot
	// when the poll interval is finer than the ring resolution).
	sl.rates = meanRates(sl.rates, s.rates(), float64(sl.count))
}

// aggregate reduces [now-offset-window, now-offset] of this ring to one Rates:
// the mean of populated slots, or their per-field max when peak is set.
func (r *ring) aggregate(now time.Time, window, offset time.Duration, peak bool) detector.Rates {
	endEpoch := r.epoch(now.Add(-offset))
	count := int(window / r.resolution)
	if count < 1 {
		count = 1
	}
	startEpoch := endEpoch - int64(count) + 1
	var sum, mx detector.Rates
	n := 0
	for e := startEpoch; e <= endEpoch; e++ {
		idx := slotIndex(e, len(r.slots))
		sl := r.slots[idx]
		if sl.epoch != e {
			continue
		}
		n++
		sum = addRates(sum, sl.rates)
		mx = maxRates(mx, sl.rates)
	}
	if peak {
		return mx
	}
	if n == 0 {
		return detector.Rates{}
	}
	return scaleRates(sum, 1/float64(n))
}

// --- Rates arithmetic helpers ---

func addRates(a, b detector.Rates) detector.Rates {
	return detector.Rates{
		RXPPS:     a.RXPPS + b.RXPPS,
		TXPPS:     a.TXPPS + b.TXPPS,
		RXBPS:     a.RXBPS + b.RXBPS,
		TXBPS:     a.TXBPS + b.TXBPS,
		SWDropPPS: a.SWDropPPS + b.SWDropPPS,
		HWDropPPS: a.HWDropPPS + b.HWDropPPS,
	}
}

func maxRates(a, b detector.Rates) detector.Rates {
	return detector.Rates{
		RXPPS:     max(a.RXPPS, b.RXPPS),
		TXPPS:     max(a.TXPPS, b.TXPPS),
		RXBPS:     max(a.RXBPS, b.RXBPS),
		TXBPS:     max(a.TXBPS, b.TXBPS),
		SWDropPPS: max(a.SWDropPPS, b.SWDropPPS),
		HWDropPPS: max(a.HWDropPPS, b.HWDropPPS),
	}
}

func scaleRates(a detector.Rates, f float64) detector.Rates {
	return detector.Rates{
		RXPPS:     a.RXPPS * f,
		TXPPS:     a.TXPPS * f,
		RXBPS:     a.RXBPS * f,
		TXBPS:     a.TXBPS * f,
		SWDropPPS: a.SWDropPPS * f,
		HWDropPPS: a.HWDropPPS * f,
	}
}

// meanRates folds sample into the running mean cur after n observations.
func meanRates(cur, sample detector.Rates, n float64) detector.Rates {
	return detector.Rates{
		RXPPS:     cur.RXPPS + (sample.RXPPS-cur.RXPPS)/n,
		TXPPS:     cur.TXPPS + (sample.TXPPS-cur.TXPPS)/n,
		RXBPS:     cur.RXBPS + (sample.RXBPS-cur.RXBPS)/n,
		TXBPS:     cur.TXBPS + (sample.TXBPS-cur.TXBPS)/n,
		SWDropPPS: cur.SWDropPPS + (sample.SWDropPPS-cur.SWDropPPS)/n,
		HWDropPPS: cur.HWDropPPS + (sample.HWDropPPS-cur.HWDropPPS)/n,
	}
}
