package vppstats

import (
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
)

// StoreState is the serializable per-interface ring history, persisted on
// shutdown and reloaded on startup so windowed vpp.* terms and /status resume
// from recent history after a quick restart. All fields are exported for gob.
type StoreState struct {
	Interfaces []InterfaceState
}

type InterfaceState struct {
	Name    string
	Aliases []string
	Last    SampleState
	Fine    RingState
	Medium  RingState
	Coarse  RingState
}

type SampleState struct {
	At        time.Time
	RXPPS     float64
	TXPPS     float64
	RXBPS     float64
	TXBPS     float64
	SWDropPPS float64
	HWDropPPS float64
}

type RingState struct {
	Resolution time.Duration
	Slots      []VPPSlotState
}

type VPPSlotState struct {
	Epoch int64
	Count uint64
	Rates detector.Rates
}

// Export captures the latest sample and rings of every interface. Thread-safe.
func (s *Store) Export() StoreState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Reverse the alias map so each interface carries its own aliases.
	aliases := make(map[*interfaceRings][]string)
	for a, r := range s.byAlias {
		aliases[r] = append(aliases[r], a)
	}
	out := StoreState{Interfaces: make([]InterfaceState, 0, len(s.rings))}
	for name, r := range s.rings {
		out.Interfaces = append(out.Interfaces, InterfaceState{
			Name:    name,
			Aliases: aliases[r],
			Last:    sampleState(r.last),
			Fine:    exportRing(r.fine),
			Medium:  exportRing(r.medium),
			Coarse:  exportRing(r.coarse),
		})
	}
	return out
}

// Import restores interfaces whose ring shapes match this store's config; others
// are skipped. Call before the poller starts.
func (s *Store) Import(st StoreState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, is := range st.Interfaces {
		r := newInterfaceRings(s.config)
		if !importRing(r.fine, is.Fine) || !importRing(r.medium, is.Medium) || !importRing(r.coarse, is.Coarse) {
			continue // ring shape changed -> skip this interface
		}
		r.last = is.Last.sample(is.Name)
		s.rings[is.Name] = r
		for _, a := range is.Aliases {
			if a != "" && a != is.Name {
				s.byAlias[a] = r
			}
		}
	}
	s.recomputeTotal()
}

func sampleState(s Sample) SampleState {
	return SampleState{
		At: s.At, RXPPS: s.RXPPS, TXPPS: s.TXPPS, RXBPS: s.RXBPS,
		TXBPS: s.TXBPS, SWDropPPS: s.SWDropPPS, HWDropPPS: s.HWDropPPS,
	}
}

func (s SampleState) sample(name string) Sample {
	return Sample{
		At: s.At, Name: name, RXPPS: s.RXPPS, TXPPS: s.TXPPS, RXBPS: s.RXBPS,
		TXBPS: s.TXBPS, SWDropPPS: s.SWDropPPS, HWDropPPS: s.HWDropPPS,
	}
}

func exportRing(r *ring) RingState {
	out := RingState{Resolution: r.resolution, Slots: make([]VPPSlotState, len(r.slots))}
	for i, sl := range r.slots {
		out.Slots[i] = VPPSlotState{Epoch: sl.epoch, Count: sl.count, Rates: sl.rates}
	}
	return out
}

// importRing copies persisted slots into a ring of the same length, reporting
// whether the shape matched.
func importRing(r *ring, st RingState) bool {
	if len(st.Slots) != len(r.slots) {
		return false
	}
	for i, s := range st.Slots {
		r.slots[i] = slot{epoch: s.Epoch, count: s.Count, rates: s.Rates}
	}
	return true
}
