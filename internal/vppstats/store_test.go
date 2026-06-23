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
	rx, _, _, ok := s.InterfaceRates("eth0")
	if !ok || rx != 99 {
		t.Fatalf("interface rates = %v/%f, want found rx 99", ok, rx)
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
	if rx, _, _, ok := s.InterfaceRates("GigabitEthernet0/0/0"); !ok || rx != 42 {
		t.Fatalf("lookup by name = %v/%f, want 42", ok, rx)
	}
	if rx, _, _, ok := s.InterfaceRates("ifindex:3"); !ok || rx != 42 {
		t.Fatalf("lookup by ifindex alias = %v/%f, want 42", ok, rx)
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

	if rx, _, _, ok := s.InterfaceRates("ifindex:7"); !ok || rx != 5 {
		t.Fatalf("lookup by ifindex = %v/%f, want 5", ok, rx)
	}
	snap := s.Snapshot()
	if len(snap) != 1 || snap[0].Name != "ifindex:7" {
		t.Fatalf("snapshot = %+v, want single ifindex entry", snap)
	}
}
