package vppstats

import (
	"testing"
	"time"
)

func TestStoreFixedRingSizes(t *testing.T) {
	cfg := RingConfig{
		FineResolution:   time.Second,
		FineDuration:     10 * time.Second,
		MediumResolution: 10 * time.Second,
		MediumDuration:   time.Minute,
		CoarseResolution: time.Minute,
		CoarseDuration:   5 * time.Minute,
	}
	s := NewStore(cfg)
	now := time.Unix(1000, 0)
	for i := 0; i < 100; i++ {
		s.Add(Sample{At: now.Add(time.Duration(i) * time.Second), Name: "eth0", RXPPS: float64(i)})
	}
	if s.Interfaces() != 1 {
		t.Fatalf("interfaces = %d, want 1", s.Interfaces())
	}
	r := s.rings["eth0"]
	if len(r.fine.slots) != 10 || len(r.medium.slots) != 6 || len(r.coarse.slots) != 5 {
		t.Fatalf("ring sizes = fine %d medium %d coarse %d", len(r.fine.slots), len(r.medium.slots), len(r.coarse.slots))
	}
	rates, ok := s.InterfaceRates("eth0")
	if !ok || rates.RXPPS != 99 {
		t.Fatalf("interface rates = %v/%f, want found rx 99", ok, rates.RXPPS)
	}
}

// NewStore fills any unset ring dimension from the defaults.
func TestStoreRingDefaults(t *testing.T) {
	s := NewStore(RingConfig{FineResolution: 2 * time.Second}) // only fine resolution set
	d := DefaultRingConfig()
	if s.config.FineResolution != 2*time.Second {
		t.Errorf("fine resolution = %s, want 2s", s.config.FineResolution)
	}
	if s.config.FineDuration != d.FineDuration || s.config.MediumResolution != d.MediumResolution {
		t.Errorf("defaults not filled: %+v", s.config)
	}
}

// A windowed average over the fine ring; an offset window excludes recent slots.
func TestStoreInterfaceWindow(t *testing.T) {
	cfg := RingConfig{
		FineResolution: time.Second, FineDuration: time.Minute,
		MediumResolution: time.Minute, MediumDuration: time.Hour,
		CoarseResolution: time.Hour, CoarseDuration: 24 * time.Hour,
	}
	s := NewStore(cfg)
	base := time.Unix(10000, 0)
	// One sample per second for 10s: RXPPS = 0,10,20,...,90.
	for i := 0; i < 10; i++ {
		s.Add(Sample{At: base.Add(time.Duration(i) * time.Second), Name: "eth0", RXPPS: float64(i * 10)})
	}
	now := base.Add(9 * time.Second)

	// Mean over the last 10s = mean(0..90) = 45.
	r, ok := s.InterfaceWindow("eth0", now, 10*time.Second, 0, false)
	if !ok || r.RXPPS != 45 {
		t.Fatalf("avg window = %v/%f, want 45", ok, r.RXPPS)
	}
	// Peak over the last 10s = 90.
	r, ok = s.InterfaceWindow("eth0", now, 10*time.Second, 0, true)
	if !ok || r.RXPPS != 90 {
		t.Fatalf("peak window = %v/%f, want 90", ok, r.RXPPS)
	}
	// Window 5s ending 5s ago covers samples 0..4 (0,10,20,30,40) -> mean 20.
	r, ok = s.InterfaceWindow("eth0", now, 5*time.Second, 5*time.Second, false)
	if !ok || r.RXPPS != 20 {
		t.Fatalf("offset window = %v/%f, want 20", ok, r.RXPPS)
	}
	// A window beyond every ring's span is not covered.
	if _, ok := s.InterfaceWindow("eth0", now, 48*time.Hour, 0, false); ok {
		t.Fatal("window beyond coarse span should not be covered")
	}
}

func TestRingConfigCovers(t *testing.T) {
	c := DefaultRingConfig() // fine 1s/5m, medium 1m/1d, coarse 1h/30d
	if !c.Covers(10*time.Second, 0) {
		t.Error("10s should be covered by fine")
	}
	if !c.Covers(2*time.Hour, time.Hour) {
		t.Error("2h+1h should be covered by coarse")
	}
	if c.Covers(500*time.Millisecond, 0) {
		t.Error("sub-resolution window must not be covered")
	}
	if c.Covers(365*24*time.Hour, 0) {
		t.Error("window beyond coarse span must not be covered")
	}
}

func TestStoreAliasDedup(t *testing.T) {
	s := NewStore(DefaultRingConfig())
	now := time.Unix(1000, 0)
	s.Add(Sample{At: now, Name: "GigabitEthernet0/0/0", Aliases: []string{"ifindex:3"}, RXPPS: 42})

	// One ring despite two lookup keys.
	if s.Interfaces() != 1 {
		t.Fatalf("interfaces = %d, want 1", s.Interfaces())
	}
	if r, ok := s.InterfaceRates("GigabitEthernet0/0/0"); !ok || r.RXPPS != 42 {
		t.Fatalf("lookup by name = %v/%f, want 42", ok, r.RXPPS)
	}
	if r, ok := s.InterfaceRates("ifindex:3"); !ok || r.RXPPS != 42 {
		t.Fatalf("lookup by ifindex alias = %v/%f, want 42", ok, r.RXPPS)
	}

	// Snapshot lists the interface once, under its name.
	snap := s.Snapshot()
	if len(snap) != 1 || snap[0].Name != "GigabitEthernet0/0/0" {
		t.Fatalf("snapshot = %+v, want single named entry", snap)
	}
}

// An unnamed interface is keyed and shown by its ifindex.
func TestStoreUnnamedInterface(t *testing.T) {
	s := NewStore(DefaultRingConfig())
	now := time.Unix(1000, 0)
	s.Add(Sample{At: now, Name: "ifindex:7", RXPPS: 5})

	if r, ok := s.InterfaceRates("ifindex:7"); !ok || r.RXPPS != 5 {
		t.Fatalf("lookup by ifindex = %v/%f, want 5", ok, r.RXPPS)
	}
	snap := s.Snapshot()
	if len(snap) != 1 || snap[0].Name != "ifindex:7" {
		t.Fatalf("snapshot = %+v, want single ifindex entry", snap)
	}
}

// TotalRates sums the latest rates across all interfaces.
func TestStoreTotalRates(t *testing.T) {
	s := NewStore(DefaultRingConfig())
	now := time.Unix(1000, 0)
	s.Add(Sample{At: now, Name: "eth0", RXPPS: 10, TXPPS: 1, RXBPS: 800, SWDropPPS: 2, HWDropPPS: 3})
	s.Add(Sample{At: now, Name: "eth1", RXPPS: 20, TXPPS: 4, RXBPS: 1600, SWDropPPS: 5, HWDropPPS: 7})

	tot := s.TotalRates()
	if tot.RXPPS != 30 || tot.TXPPS != 5 || tot.RXBPS != 2400 || tot.SWDropPPS != 7 || tot.HWDropPPS != 10 {
		t.Fatalf("total = %+v", tot)
	}
}
