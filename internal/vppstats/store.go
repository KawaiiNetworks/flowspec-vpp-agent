package vppstats

import (
	"sync"
	"time"
)

type Sample struct {
	At      time.Time
	Name    string
	RXPPS   float64
	TXPPS   float64
	DropPPS float64
}

type Store struct {
	mu     sync.RWMutex
	rings  map[string]*interfaceRings
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
	return &Store{rings: make(map[string]*interfaceRings), config: config}
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
}

func (s *Store) Interfaces() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rings)
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

func (s *Store) InterfaceRates(name string) (rxPPS, txPPS, dropPPS float64, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.rings[name]
	if r == nil {
		return 0, 0, 0, false
	}
	return r.last.RXPPS, r.last.TXPPS, r.last.DropPPS, true
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

func (r *ring) add(s Sample) {
	epoch := s.At.UnixNano() / r.resolution.Nanoseconds()
	idx := int(epoch % int64(len(r.slots)))
	if r.slots[idx].epoch != epoch {
		r.slots[idx] = slot{epoch: epoch}
	}
	sl := &r.slots[idx]
	sl.count++
	n := float64(sl.count)
	sl.rxPPS += (s.RXPPS - sl.rxPPS) / n
	sl.txPPS += (s.TXPPS - sl.txPPS) / n
	sl.dropPPS += (s.DropPPS - sl.dropPPS) / n
}
