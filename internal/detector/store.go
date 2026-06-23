package detector

import "time"

type slot struct {
	epoch   int64
	packets uint64
	bytes   uint64
}

// slotIndex maps an epoch onto a ring slot. Go's % keeps the sign of the
// dividend, so a negative epoch (a timestamp before the Unix epoch) would yield
// a negative index and panic; this folds it back into [0, n).
func slotIndex(epoch int64, n int) int {
	idx := epoch % int64(n)
	if idx < 0 {
		idx += int64(n)
	}
	return int(idx)
}

type instance struct {
	key           descriptor
	keyHash       uint64 // cached descriptor.hash() for sketch lookups
	fine          *sampleRing
	medium        *sampleRing
	coarse        *sampleRing
	lastSeen      time.Time
	lastEvent     time.Time
	trueSince     time.Time // when the trigger expression first became true
	lastIngressIf string
}

func newInstance(key descriptor, history historySpec, now time.Time) *instance {
	return &instance{
		key:      key,
		keyHash:  key.hash(),
		fine:     newSampleRing(history.fineSlots, history.fineResolution),
		medium:   newOptionalSampleRing(history.mediumSlots, history.mediumResolution),
		coarse:   newOptionalSampleRing(history.coarseSlots, history.coarseResolution),
		lastSeen: now,
	}
}

func (i *instance) add(at time.Time, packetLen uint16, weight uint64) {
	i.fine.add(at, packetLen, weight)
	if i.medium != nil {
		i.medium.add(at, packetLen, weight)
	}
	if i.coarse != nil {
		i.coarse.add(at, packetLen, weight)
	}
	i.lastSeen = at
}

// ringFor returns the instance ring a term reads from.
func (i *instance) ringFor(k ringKind) *sampleRing {
	switch k {
	case ringMedium:
		return i.medium
	case ringCoarse:
		return i.coarse
	default:
		return i.fine
	}
}

// shouldEmit throttles re-emission so a sustained finding refreshes its lease at
// a steady cadence rather than once per tick.
func (i *instance) shouldEmit(now time.Time, interval time.Duration) bool {
	if i.lastEvent.IsZero() || now.Sub(i.lastEvent) >= interval {
		i.lastEvent = now
		return true
	}
	return false
}

type sampleRing struct {
	slots      []slot
	resolution time.Duration
}

func newOptionalSampleRing(slots int, resolution time.Duration) *sampleRing {
	if slots <= 0 || resolution <= 0 {
		return nil
	}
	return newSampleRing(slots, resolution)
}

func newSampleRing(slots int, resolution time.Duration) *sampleRing {
	return &sampleRing{slots: make([]slot, slots), resolution: resolution}
}

func (r *sampleRing) epoch(at time.Time) int64 {
	return at.UnixNano() / r.resolution.Nanoseconds()
}

func (r *sampleRing) add(at time.Time, packetLen uint16, weight uint64) {
	epoch := r.epoch(at)
	idx := slotIndex(epoch, len(r.slots))
	if r.slots[idx].epoch != epoch {
		r.slots[idx] = slot{epoch: epoch}
	}
	r.slots[idx].packets += weight
	r.slots[idx].bytes += uint64(packetLen) * weight
}

// aggregate reduces the window [now-offset-window, now-offset] of this ring to a
// single value per the term's metric and aggregation.
func (r *sampleRing) aggregate(now time.Time, t *term) float64 {
	if t.slots <= 0 {
		return 0
	}
	endEpoch := r.epoch(now.Add(-t.offset))
	startEpoch := endEpoch - int64(t.slots) + 1
	var packets, bytes, maxPackets, maxBytes uint64
	for epoch := startEpoch; epoch <= endEpoch; epoch++ {
		idx := slotIndex(epoch, len(r.slots))
		if r.slots[idx].epoch != epoch {
			continue
		}
		p, b := r.slots[idx].packets, r.slots[idx].bytes
		packets += p
		bytes += b
		if p > maxPackets {
			maxPackets = p
		}
		if b > maxBytes {
			maxBytes = b
		}
	}
	bits := func(v uint64) float64 {
		if t.metric == metricBPS {
			return float64(v * 8)
		}
		return float64(v)
	}
	switch t.agg {
	case aggSum:
		if t.metric == metricBPS {
			return float64(bytes * 8)
		}
		return float64(packets)
	case aggMax:
		secs := r.resolution.Seconds()
		if secs <= 0 {
			return 0
		}
		if t.metric == metricBPS {
			return bits(maxBytes) / secs
		}
		return bits(maxPackets) / secs
	default: // aggAvg
		secs := t.window.Seconds()
		if secs <= 0 {
			return 0
		}
		if t.metric == metricBPS {
			return bits(bytes) / secs
		}
		return bits(packets) / secs
	}
}

// rate returns the average rate over the most recent `slots` slots (used for the
// eviction score).
func (r *sampleRing) rate(now time.Time, slots int, metric metricKind) float64 {
	if slots <= 0 {
		return 0
	}
	nowEpoch := r.epoch(now)
	var packets, bytes uint64
	for n := 0; n < slots; n++ {
		epoch := nowEpoch - int64(n)
		idx := slotIndex(epoch, len(r.slots))
		if r.slots[idx].epoch != epoch {
			continue
		}
		packets += r.slots[idx].packets
		bytes += r.slots[idx].bytes
	}
	seconds := r.resolution.Seconds() * float64(slots)
	if metric == metricBPS {
		return float64(bytes*8) / seconds
	}
	return float64(packets) / seconds
}

type instanceStore struct {
	max     int
	history historySpec
	items   map[descriptor]*instance
}

func newInstanceStore(history historySpec) *instanceStore {
	return &instanceStore{
		max:     history.maxInstances,
		history: history,
		items:   make(map[descriptor]*instance, history.maxInstances),
	}
}

func (s *instanceStore) len() int { return len(s.items) }

// admit returns the instance for key, creating one if there is room. When the
// pool is full it admits the candidate only if its HeavyKeeper estimate exceeds
// the weakest current instance's estimate, evicting that instance. Because the
// sketch has observed both targets over recent traffic, this is a fair
// accumulated comparison — not a single-sample one — so a genuinely heavier new
// target always displaces a lighter incumbent (and a transient one never gets a
// foothold it can't keep).
func (s *instanceStore) admit(key descriptor, sketch *heavyKeeper, now time.Time) (*instance, bool) {
	if inst := s.items[key]; inst != nil {
		return inst, true
	}
	if len(s.items) < s.max {
		inst := newInstance(key, s.history, now)
		s.items[key] = inst
		return inst, true
	}
	victimKey, victimEst, ok := s.weakest(sketch)
	if !ok || sketch.estimate(key.hash()) <= victimEst {
		return nil, false
	}
	delete(s.items, victimKey)
	inst := newInstance(key, s.history, now)
	s.items[key] = inst
	return inst, true
}

// weakest returns the tracked instance with the lowest sketch estimate.
func (s *instanceStore) weakest(sketch *heavyKeeper) (descriptor, float64, bool) {
	var victimKey descriptor
	var min float64
	found := false
	for k, inst := range s.items {
		est := sketch.estimate(inst.keyHash)
		if !found || est < min {
			victimKey, min, found = k, est, true
		}
	}
	return victimKey, min, found
}
