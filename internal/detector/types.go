// Package detector contains the fixed-memory local detection engine used by
// sFlow/VPP-stats driven rules. It intentionally stays independent from BGP and
// VPP backends; callers can turn emitted Events into synthetic FlowSpec updates.
//
// Identity model: each matched packet is reduced to a comparable descriptor (the
// aggregated, FlowSpec-shaped signature). Two packets with the same descriptor
// are the same instance. The descriptor is also what the synthetic FlowSpec is
// generated from, so detection accounting and mitigation granularity stay
// aligned by construction.
//
// Evaluation model: samples only update fixed-capacity rings (the hot path does
// no trigger work). A periodic Tick walks the bounded set of instances and
// evaluates each rule's trigger expression, so arbitrary windowed comparisons
// cost the same regardless of packet rate.
package detector

import (
	"net/netip"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// Sample is the compact packet metadata consumed by compiled detection rules.
// sFlow decoding should populate this structure without carrying packet payloads
// into the detector hot path.
type Sample struct {
	At         time.Time
	Family     flowspec.Family
	Src        netip.Addr
	Dst        netip.Addr
	Proto      uint8
	SrcPort    uint16
	DstPort    uint16
	PacketLen  uint16
	TCPFlags   uint8
	IngressIf  string
	SampleRate uint32
}

// Event describes one active detector finding and the synthetic FlowSpec rule it
// wants to announce or refresh.
type Event struct {
	ID          string
	RuleName    string
	InstanceKey string
	Description string
	TTL         time.Duration
	Refresh     bool
	ObservedPPS float64
	Rule        flowspec.Rule
}

// EvalContext carries optional external signals (VPP interface counters) into
// trigger evaluation.
type EvalContext struct {
	Stats StatsView
}

// Rates holds the VPP rate signals a rule can read, for one interface or the
// total across all interfaces. drop counters are packets-only (VPP exposes no
// byte counter for drops). SWDrop is the VPP graph drop counter (/if/drops,
// which includes our own ACL deny); HWDrop is the NIC RX-ring overflow
// (/if/rx-miss), i.e. the hardware "can't keep up" signal.
type Rates struct {
	RXPPS     float64
	TXPPS     float64
	RXBPS     float64
	TXBPS     float64
	SWDropPPS float64
	HWDropPPS float64
}

// StatsView exposes VPP interface counters as rates. InterfaceRates returns the
// rates for one interface (ok=false if unknown); TotalRates returns the sum
// across all interfaces.
type StatsView interface {
	InterfaceRates(name string) (Rates, bool)
	TotalRates() Rates
}

// descriptor is the instance identity: the aggregated signature of a matched
// packet. Every matched packet carries all fields, so the descriptor always
// holds all of them; `aggregate` only changes their granularity. It is
// comparable and used directly as a map key, so the hot path stays
// allocation-free.
//
// family is always a concrete address family (IPv4 and IPv6 can never share one
// FlowSpec rule). proto is wildcard when protoWild is set. src/dst are masked
// addresses (a /0 aggregate yields the zero address). Ports are stored as the
// aggregated inclusive range [lo, hi]; an exact value is lo==hi and a wildcard
// is 0..65535. packet_len is never part of the identity because FlowSpec cannot
// carry it.
type descriptor struct {
	family flowspec.Family

	proto     uint8
	protoWild bool

	src netip.Addr
	dst netip.Addr

	srcPortLo uint16
	srcPortHi uint16
	dstPortLo uint16
	dstPortHi uint16
}

// metricKind selects which signal a trigger term aggregates.
type metricKind uint8

const (
	metricPPS metricKind = iota
	metricBPS
	// Per-interface VPP rates, keyed by the instance's packet ingress interface.
	metricIfaceRXPPS
	metricIfaceTXPPS
	metricIfaceRXBPS
	metricIfaceTXBPS
	metricIfaceSWDropPPS
	metricIfaceHWDropPPS
	// Totals across all VPP interfaces.
	metricTotalRXPPS
	metricTotalTXPPS
	metricTotalRXBPS
	metricTotalTXBPS
	metricTotalSWDropPPS
	metricTotalHWDropPPS
)

// isStats reports whether the metric reads from VPP stats (vs. this rule's own
// history rings).
func (m metricKind) isStats() bool { return m >= metricIfaceRXPPS }

// isTotal reports whether the metric is an all-interface total (vs. the
// instance's ingress interface).
func (m metricKind) isTotal() bool { return m >= metricTotalRXPPS }

// selectRate picks the field of a Rates set this metric refers to.
func (m metricKind) selectRate(r Rates) float64 {
	switch m {
	case metricIfaceRXPPS, metricTotalRXPPS:
		return r.RXPPS
	case metricIfaceTXPPS, metricTotalTXPPS:
		return r.TXPPS
	case metricIfaceRXBPS, metricTotalRXBPS:
		return r.RXBPS
	case metricIfaceTXBPS, metricTotalTXBPS:
		return r.TXBPS
	case metricIfaceSWDropPPS, metricTotalSWDropPPS:
		return r.SWDropPPS
	case metricIfaceHWDropPPS, metricTotalHWDropPPS:
		return r.HWDropPPS
	default:
		return 0
	}
}

// aggKind selects how a term reduces the slots within its window.
type aggKind uint8

const (
	aggAvg aggKind = iota // average rate over the window (packets/sec or bits/sec)
	aggMax                // peak single-slot rate within the window
	aggSum                // total packets (or bits) over the window
)

// ringKind selects which history ring a term reads from.
type ringKind uint8

const (
	ringFine ringKind = iota
	ringMedium
	ringCoarse
)
