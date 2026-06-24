package detector

import (
	"encoding/binary"
	"net/netip"

	"math/bits"
)

// Spread (a.k.a. ratio / diversity) detection. A field that is aggregated away in
// the descriptor (dst collapsed to /0, src_port to "all", …) still has the real
// per-packet values flowing through it. spreadEstimator measures, over the most
// recent samples, how many of N numeric regions those values cover.
//
// It is used as a gate: an instance only counts a packet toward its history (and
// thus toward triggering) when the configured fields are sufficiently spread. This
// stops a single source/target from tripping a rule that covers a wide range — two
// hosts exchanging packets stay quiet, while many distinct hosts hammering one
// target (or one source spraying many) is admitted as the attack it is.
//
// The window is a fixed number of recent SAMPLES (not a time window), so it is
// robust to packet rate and needs no per-second timer. Resolution is at most 1/N
// (<=5%, i.e. N<=20): a small declared range (e.g. a 15-port window) uses one
// region per value (exact); a large range (an IP /0) is split into 20 regions by
// numeric value, so clustered values correctly read as low spread.

const (
	spreadMaxBuckets = 20 // 5% resolution ceiling
	spreadMinSamples = 16 // floor on the sample window when buckets is small
)

// spreadKind names the packet field a gate measures.
type spreadKind uint8

const (
	spreadSrc spreadKind = iota
	spreadDst
	spreadSrcPort
	spreadDstPort
)

// spreadField is one compiled diversity gate. Values are bucketed by NUMERIC
// region (the range split into `buckets` equal slices), not by hash, so values
// clustered in a sub-range correctly read as low spread. For an IP field, the
// region comes from the address bits BELOW the aggregate mask (the part that
// varies within the instance); for a port field, from its position in the range.
type spreadField struct {
	kind     spreadKind
	buckets  int // N
	minRatio int // percent (1-100)

	// IP fields:
	ipv6     bool
	maskBits int
	// Port fields: a value maps to (value-lo)/(size/N), or (value % size)/(size/N)
	// for a floor-bucket aggregate (where the per-instance base divides out).
	portLo   uint32
	portSize uint32
	portMod  bool
}

// bucket maps a sample's field value to a numeric region [0, buckets).
func (f spreadField) bucket(s Sample) int {
	switch f.kind {
	case spreadSrc:
		return ipRegion(s.Src, f.ipv6, f.maskBits, f.buckets)
	case spreadDst:
		return ipRegion(s.Dst, f.ipv6, f.maskBits, f.buckets)
	case spreadSrcPort:
		return portRegion(s.SrcPort, f.portLo, f.portSize, f.portMod, f.buckets)
	default:
		return portRegion(s.DstPort, f.portLo, f.portSize, f.portMod, f.buckets)
	}
}

func (f spreadField) String() string {
	switch f.kind {
	case spreadSrc:
		return "src"
	case spreadDst:
		return "dst"
	case spreadSrcPort:
		return "src_port"
	default:
		return "dst_port"
	}
}

// ipRegion returns which of n equal slices of the field's varying range the
// address falls into. The varying range is the address bits below maskBits; its
// top bits (left-justified into 64) scaled by n give the region, so adjacent
// addresses share a region and a cluster covers few regions.
func ipRegion(a netip.Addr, v6 bool, maskBits, n int) int {
	if !a.IsValid() {
		return 0
	}
	var lj uint64 // varying part, MSB aligned to bit 63
	if !v6 {
		b := a.As4()
		x := uint64(binary.BigEndian.Uint32(b[:]))
		spreadBits := 32 - maskBits // 1..32
		varying := x & ((uint64(1) << spreadBits) - 1)
		lj = varying << (64 - spreadBits)
	} else {
		b := a.As16()
		hi := binary.BigEndian.Uint64(b[0:8])
		lo := binary.BigEndian.Uint64(b[8:16])
		if maskBits < 64 {
			lj = hi << maskBits
			if maskBits > 0 {
				lj |= lo >> (64 - maskBits)
			}
		} else {
			spreadBits := 128 - maskBits // 1..64
			varying := lo & ((uint64(1) << spreadBits) - 1)
			lj = varying << (64 - spreadBits)
		}
	}
	region, _ := bits.Mul64(lj, uint64(n))
	return int(region)
}

// portRegion returns which of n equal slices of the port range the port is in.
func portRegion(p uint16, lo, size uint32, mod bool, n int) int {
	var varying uint32
	if mod {
		varying = uint32(p) % size
	} else {
		v := uint32(p)
		if v < lo {
			v = lo
		}
		varying = v - lo
		if varying >= size {
			varying = size - 1
		}
	}
	if size <= uint32(n) {
		return int(varying) // one region per value
	}
	return int(uint64(varying) * uint64(n) / uint64(size))
}

// spreadEstimator measures diversity over a sliding window of the most recent
// `window` SAMPLES (not a time window). It keeps a tiny ring of those samples'
// region indices plus a per-region occupancy count, so the distinct-region count
// is maintained in O(1) as samples enter and the oldest is evicted. Memory is a
// few dozen bytes, fixed — independent of packet rate (it stores no packets).
//
// Sample-based (rather than time-based) means a slow stream is judged on its last
// `window` samples exactly like a fast one: low pps no longer makes the estimate
// noisy, and there is no per-second timer.
type spreadEstimator struct {
	buckets  int
	window   int
	ring     []uint8 // last `window` region indices (circular)
	count    []uint8 // count[region] = occurrences within the window
	head     int
	filled   int
	distinct int
}

func newSpreadEstimator(buckets int) spreadEstimator {
	w := buckets
	if w < spreadMinSamples {
		w = spreadMinSamples
	}
	return spreadEstimator{
		buckets: buckets,
		window:  w,
		ring:    make([]uint8, w),
		count:   make([]uint8, buckets),
	}
}

// observe records one sample's region and returns the filled-region percentage
// over the last `window` samples. O(1).
func (e *spreadEstimator) observe(region int) int {
	if e.filled == e.window { // evict the oldest sample
		old := e.ring[e.head]
		e.count[old]--
		if e.count[old] == 0 {
			e.distinct--
		}
	} else {
		e.filled++
	}
	e.ring[e.head] = uint8(region)
	if e.count[region] == 0 {
		e.distinct++
	}
	e.count[region]++
	e.head++
	if e.head == e.window {
		e.head = 0
	}
	return e.distinct * 100 / e.buckets
}

// ratioPct reports the current spread without mutating (used by /status).
func (e *spreadEstimator) ratioPct() int {
	return e.distinct * 100 / e.buckets
}
