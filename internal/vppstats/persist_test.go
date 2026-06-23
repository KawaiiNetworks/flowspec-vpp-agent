package vppstats

import (
	"testing"
	"time"
)

// Export then Import must restore an interface's latest rates, its rings, and its
// aliases (so detector lookups by ifindex keep working after a restart).
func TestStore_ExportImportRoundTrip(t *testing.T) {
	cfg := RingConfig{
		FineResolution: time.Second, FineDuration: time.Minute,
		MediumResolution: time.Minute, MediumDuration: time.Hour,
		CoarseResolution: time.Hour, CoarseDuration: 24 * time.Hour,
	}
	s := NewStore(cfg)
	base := time.Unix(10000, 0)
	for i := 0; i < 10; i++ {
		s.Add(Sample{
			At:   base.Add(time.Duration(i) * time.Second),
			Name: "GigabitEthernet0/0/0", Aliases: []string{"ifindex:3"},
			RXPPS: float64(i * 10), RXBPS: float64(i * 800), SWDropPPS: float64(i),
		})
	}

	st := s.Export()

	s2 := NewStore(cfg)
	s2.Import(st)

	if s2.Interfaces() != 1 {
		t.Fatalf("restored interfaces = %d, want 1", s2.Interfaces())
	}
	// Latest rates restored, reachable by name and by ifindex alias.
	for _, key := range []string{"GigabitEthernet0/0/0", "ifindex:3"} {
		r, ok := s2.InterfaceRates(key)
		if !ok || r.RXPPS != 90 || r.SWDropPPS != 9 {
			t.Fatalf("rates[%s] = %+v ok=%v, want rx 90 / swdrop 9", key, r, ok)
		}
	}
	// Windowed aggregate works on restored rings: mean rx over 10s = mean(0..90)=45.
	now := base.Add(9 * time.Second)
	if r, ok := s2.InterfaceWindow("ifindex:3", now, 10*time.Second, 0, false); !ok || r.RXPPS != 45 {
		t.Fatalf("restored window avg = %v/%f, want 45", ok, r.RXPPS)
	}
}

// An interface whose ring shape no longer matches the store config is skipped.
func TestStore_ImportSkipsReshaped(t *testing.T) {
	big := RingConfig{
		FineResolution: time.Second, FineDuration: time.Minute,
		MediumResolution: time.Minute, MediumDuration: time.Hour,
		CoarseResolution: time.Hour, CoarseDuration: 24 * time.Hour,
	}
	s := NewStore(big)
	s.Add(Sample{At: time.Unix(10000, 0), Name: "eth0", RXPPS: 5})
	st := s.Export()

	// Different fine duration -> different slot count -> skip.
	small := big
	small.FineDuration = 2 * time.Minute
	s2 := NewStore(small)
	s2.Import(st)
	if s2.Interfaces() != 0 {
		t.Fatalf("reshaped store should skip mismatched interface, got %d", s2.Interfaces())
	}
}
