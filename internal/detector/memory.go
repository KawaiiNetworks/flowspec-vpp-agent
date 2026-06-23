package detector

import "unsafe"

// Per-entry map bookkeeping (bucket tophash + key copy + value pointer), a rough
// constant added on top of the measured struct sizes. The whole estimate is an
// upper bound, not an exact figure.
const mapEntryOverhead = int64(unsafe.Sizeof(descriptor{})) + 24

// MemoryEstimate returns an approximate upper bound, in bytes, on the heap this
// rule occupies once it is fully populated to max_instances. It accounts for the
// three ring backing arrays, the per-instance struct, the three ring headers, and
// map bookkeeping. It is intentionally conservative (assumes every instance slot
// is filled) and is meant for a startup sizing log, not precise accounting.
func (r *Rule) MemoryEstimate() int64 {
	slotsPer := int64(r.history.fineSlots + r.history.mediumSlots + r.history.coarseSlots)
	ringBytes := slotsPer * int64(unsafe.Sizeof(slot{}))
	ringHeaders := 3 * int64(unsafe.Sizeof(sampleRing{}))
	perInstance := ringBytes + ringHeaders + int64(unsafe.Sizeof(instance{})) + mapEntryOverhead
	return int64(r.history.maxInstances) * perInstance
}

// MemoryEstimate sums the per-rule estimates across the engine.
func (e *Engine) MemoryEstimate() int64 {
	var total int64
	for _, r := range e.all {
		total += r.MemoryEstimate()
	}
	return total
}
