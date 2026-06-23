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
