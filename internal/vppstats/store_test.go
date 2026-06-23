package vppstats

import (
	"testing"
	"time"
)

func TestStoreFixedRingSizes(t *testing.T) {
	cfg := RingConfig{
		DayResolution:   time.Second,
		DayDuration:     10 * time.Second,
		WeekResolution:  10 * time.Second,
		WeekDuration:    time.Minute,
		MonthResolution: time.Minute,
		MonthDuration:   5 * time.Minute,
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
	if len(r.day.slots) != 10 || len(r.week.slots) != 6 || len(r.month.slots) != 5 {
		t.Fatalf("ring sizes = day %d week %d month %d", len(r.day.slots), len(r.week.slots), len(r.month.slots))
	}
	rates, ok := s.InterfaceRates("eth0")
	if !ok || rates.RXPPS != 99 {
		t.Fatalf("interface rates = %v/%f, want found rx 99", ok, rates.RXPPS)
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
