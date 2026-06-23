package detector

import (
	"net/netip"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// EngineState is the serializable history of every rule's tracked instances,
// persisted on shutdown and reloaded on startup so detection resumes from recent
// history after a quick restart. The admission sketch is NOT persisted — it
// rebuilds from traffic within a half-life. All fields are exported for gob.
//
// History is keyed to absolute time (ring epochs), so a long downtime simply
// leaves the restored slots outside the trigger window (harmless; overwritten as
// new traffic arrives). Import refuses to load a rule whose name is gone or whose
// ring shape changed.
type EngineState struct {
	Rules []RuleState
}

type RuleState struct {
	Name        string
	Fingerprint string // ruleFingerprint of the rule that produced this history
	Shape       RingShapes
	Instances   []InstanceState
}

// RingShapes records a rule's ring sizing so Import can reject history written
// under a different history config.
type RingShapes struct {
	FineRes     time.Duration
	FineSlots   int
	MediumRes   time.Duration
	MediumSlots int
	CoarseRes   time.Duration
	CoarseSlots int
}

func (a RingShapes) equal(b RingShapes) bool { return a == b }

type InstanceState struct {
	Desc      DescriptorState
	LastSeen  time.Time
	LastEvent time.Time
	TrueSince time.Time
	IngressIf string
	Fine      []SlotState
	Medium    []SlotState
	Coarse    []SlotState
}

type DescriptorState struct {
	Family    uint8
	Proto     uint8
	ProtoWild bool
	Src       []byte // netip.Addr.MarshalBinary (empty for the zero address)
	Dst       []byte
	SrcPortLo uint16
	SrcPortHi uint16
	DstPortLo uint16
	DstPortHi uint16
}

type SlotState struct {
	Epoch   int64
	Packets uint64
	Bytes   uint64
}

// Export captures the current instance history of every rule. Must be called on
// the goroutine that owns the engine (the runner), or after it has stopped.
func (e *Engine) Export() EngineState {
	st := EngineState{Rules: make([]RuleState, 0, len(e.all))}
	for _, r := range e.all {
		rs := RuleState{Name: r.name, Fingerprint: r.fingerprint, Shape: r.ringShapes()}
		rs.Instances = make([]InstanceState, 0, len(r.store.items))
		for _, inst := range r.store.items {
			rs.Instances = append(rs.Instances, inst.export())
		}
		st.Rules = append(st.Rules, rs)
	}
	return st
}

// Import restores instance history into rules that still exist with an unchanged
// ring shape; everything else is skipped. Must be called before the engine starts
// observing.
func (e *Engine) Import(st EngineState) {
	byName := make(map[string]*Rule, len(e.all))
	for _, r := range e.all {
		byName[r.name] = r
	}
	for _, rs := range st.Rules {
		r, ok := byName[rs.Name]
		// The fingerprint gates on the rule's full definition (a changed rule starts
		// fresh); the ringShapes check is a defensive guard on slot layout for the
		// per-slot copy below.
		if !ok || r.fingerprint != rs.Fingerprint || !r.ringShapes().equal(rs.Shape) {
			continue // rule gone or its definition changed
		}
		for _, is := range rs.Instances {
			if len(r.store.items) >= r.store.max {
				break
			}
			d, ok := is.Desc.toDescriptor()
			if !ok {
				continue
			}
			inst := newInstance(d, r.history, is.LastSeen)
			inst.lastEvent = is.LastEvent
			inst.trueSince = is.TrueSince
			inst.lastIngressIf = is.IngressIf
			importSlots(inst.fine, is.Fine)
			importSlots(inst.medium, is.Medium)
			importSlots(inst.coarse, is.Coarse)
			r.store.items[d] = inst
		}
	}
}

func (r *Rule) ringShapes() RingShapes {
	return RingShapes{
		FineRes: r.history.fineResolution, FineSlots: r.history.fineSlots,
		MediumRes: r.history.mediumResolution, MediumSlots: r.history.mediumSlots,
		CoarseRes: r.history.coarseResolution, CoarseSlots: r.history.coarseSlots,
	}
}

func (i *instance) export() InstanceState {
	return InstanceState{
		Desc:      i.key.export(),
		LastSeen:  i.lastSeen,
		LastEvent: i.lastEvent,
		TrueSince: i.trueSince,
		IngressIf: i.lastIngressIf,
		Fine:      exportSlots(i.fine),
		Medium:    exportSlots(i.medium),
		Coarse:    exportSlots(i.coarse),
	}
}

func exportSlots(r *sampleRing) []SlotState {
	if r == nil {
		return nil
	}
	out := make([]SlotState, len(r.slots))
	for i, s := range r.slots {
		out[i] = SlotState{Epoch: s.epoch, Packets: s.packets, Bytes: s.bytes}
	}
	return out
}

// importSlots copies persisted slots into a ring of the same length (a mismatch
// is silently skipped — the rule's shape changed).
func importSlots(r *sampleRing, slots []SlotState) {
	if r == nil || len(slots) != len(r.slots) {
		return
	}
	for i, s := range slots {
		r.slots[i] = slot{epoch: s.Epoch, packets: s.Packets, bytes: s.Bytes}
	}
}

func (d descriptor) export() DescriptorState {
	src, _ := d.src.MarshalBinary()
	dst, _ := d.dst.MarshalBinary()
	return DescriptorState{
		Family:    uint8(d.family),
		Proto:     d.proto,
		ProtoWild: d.protoWild,
		Src:       src,
		Dst:       dst,
		SrcPortLo: d.srcPortLo,
		SrcPortHi: d.srcPortHi,
		DstPortLo: d.dstPortLo,
		DstPortHi: d.dstPortHi,
	}
}

func (d DescriptorState) toDescriptor() (descriptor, bool) {
	var src, dst netip.Addr
	if len(d.Src) > 0 {
		if err := src.UnmarshalBinary(d.Src); err != nil {
			return descriptor{}, false
		}
	}
	if len(d.Dst) > 0 {
		if err := dst.UnmarshalBinary(d.Dst); err != nil {
			return descriptor{}, false
		}
	}
	return descriptor{
		family:    flowspec.Family(d.Family),
		proto:     d.Proto,
		protoWild: d.ProtoWild,
		src:       src,
		dst:       dst,
		srcPortLo: d.SrcPortLo,
		srcPortHi: d.SrcPortHi,
		dstPortLo: d.DstPortLo,
		dstPortHi: d.DstPortHi,
	}, true
}
