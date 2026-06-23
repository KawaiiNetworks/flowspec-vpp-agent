package detector

import (
	"math"
	"time"
)

// Sketch sizing/decay defaults. depth follows the HeavyKeeper paper; width scales
// with the instance pool so genuinely heavy targets rarely collide; the decay
// base controls collision stickiness; the half-life ages estimates toward recent
// volume.
const (
	sketchDepth      = 4
	heavyKeeperDecay = 1.08
	sketchHalfLife   = 30 * time.Second
)

// sketchWidth sizes each hash row from the instance pool: enough headroom that
// the heaviest ~maxInstances targets seldom share a bucket, with a sane floor.
func sketchWidth(maxInstances int) int {
	w := 16 * maxInstances
	if w < 1024 {
		w = 1024
	}
	return w
}

// heavyKeeper is a HeavyKeeper sketch (Gong et al., USENIX ATC 2018) used as the
// admission filter for a rule's bounded instance pool. It observes EVERY matched
// descriptor cheaply in fixed memory and yields a recency-aware weight estimate
// per descriptor, so a brand-new heavy target can be compared fairly against the
// instances we already track — without giving every target a full ring set.
//
// Counts are weighted (each sample contributes its sFlow sample-rate, i.e. an
// estimated packet count) and aged on every tick (decayAll) so the estimate
// reflects recent volume, not all-time. On a hash collision the incumbent is
// probabilistically decayed with probability decay^(-count): heavy occupants are
// effectively sticky while light ones are quickly displaced.
//
// The sketch is only touched from the engine's single Observe/Tick goroutine, so
// it needs no locking and uses a private deterministic PRNG (reproducible tests).
type heavyKeeper struct {
	depth   int
	width   int
	decay   float64 // collision-decay base b in b^(-count)
	buckets [][]hkBucket
	rng     uint64 // xorshift64 state
}

type hkBucket struct {
	fp    uint64
	count float64
}

// pruneBelow frees a bucket once its aged count drops under one packet-equivalent,
// so a target that went quiet releases its slot to newcomers.
const pruneBelow = 1.0

func newHeavyKeeper(width, depth int, decay float64) *heavyKeeper {
	if width < 1 {
		width = 1
	}
	if depth < 1 {
		depth = 1
	}
	buckets := make([][]hkBucket, depth)
	for i := range buckets {
		buckets[i] = make([]hkBucket, width)
	}
	return &heavyKeeper{
		depth:   depth,
		width:   width,
		decay:   decay,
		buckets: buckets,
		rng:     0x2545F4914F6CDD1D, // fixed seed -> deterministic
	}
}

// add folds weight for key into the sketch.
func (h *heavyKeeper) add(key uint64, weight float64) {
	for i := 0; i < h.depth; i++ {
		b := &h.buckets[i][h.index(key, i)]
		switch {
		case b.count <= 0:
			b.fp, b.count = key, weight
		case b.fp == key:
			b.count += weight
		default:
			// Collision with a different occupant: decay it with probability
			// decay^(-count). Heavy occupants (large count) almost never decay.
			if h.decayHits(b.count) {
				b.count -= weight
				if b.count <= 0 {
					b.fp, b.count = key, -b.count // intruder takes over with its residual
				}
			}
		}
	}
}

// estimate returns the recency-aware weight currently attributed to key, or 0 if
// the sketch is not tracking it (decayed out or never heavy).
func (h *heavyKeeper) estimate(key uint64) float64 {
	var best float64
	for i := 0; i < h.depth; i++ {
		if b := h.buckets[i][h.index(key, i)]; b.fp == key && b.count > best {
			best = b.count
		}
	}
	return best
}

// decayAll ages every counter by factor (0<factor<1) and frees negligible
// buckets. Called once per tick so estimates track recent volume.
func (h *heavyKeeper) decayAll(factor float64) {
	if factor <= 0 || factor >= 1 {
		return
	}
	for i := range h.buckets {
		row := h.buckets[i]
		for j := range row {
			if row[j].count == 0 {
				continue
			}
			row[j].count *= factor
			if row[j].count < pruneBelow {
				row[j] = hkBucket{}
			}
		}
	}
}

// decayHits draws whether a collision decays an occupant of the given count.
// For large counts decay^(-count) underflows to ~0, so we skip the draw.
func (h *heavyKeeper) decayHits(count float64) bool {
	p := math.Pow(h.decay, -count)
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	return h.rngFloat() < p
}

// index hashes key into a bucket of row i (independent mixing per row).
func (h *heavyKeeper) index(key uint64, i int) int {
	x := key ^ (uint64(i+1) * 0x9E3779B97F4A7C15)
	x ^= x >> 33
	x *= 0xFF51AFD7ED558CCD
	x ^= x >> 33
	return int(x % uint64(h.width))
}

// rngFloat returns a deterministic pseudo-random float in [0,1).
func (h *heavyKeeper) rngFloat() float64 {
	h.rng ^= h.rng << 13
	h.rng ^= h.rng >> 7
	h.rng ^= h.rng << 17
	return float64(h.rng>>11) / float64(uint64(1)<<53)
}
