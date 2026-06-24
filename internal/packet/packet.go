// Package packet decodes a raw L2/L3/L4 packet header (as sampled by sFlow or by
// the kernel PSAMPLE channel) into a compact detector.Sample. It is the shared
// parsing layer behind both the sFlow-over-UDP collector and the netlink PSAMPLE
// collector — only the envelope around these bytes differs between the two.
package packet

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeVLAN = 0x8100

	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	// IPv6 extension-header Next-Header values we walk over to reach the L4 header.
	extHopByHop = 0
	extRouting  = 43
	extFragment = 44
	extAH       = 51
	extDestOpts = 60
	extMobility = 135
)

// FromEthernet decodes a packet starting at the Ethernet header (as carried by a
// PSAMPLE message) and stamps the sample metadata the caller knows: timestamp,
// sampling rate (normalized to >= 1), and ingress interface name.
func FromEthernet(b []byte, at time.Time, sampleRate uint32, ingressIf string) (detector.Sample, bool) {
	s, ok := DecodeEthernet(b)
	if !ok {
		return detector.Sample{}, false
	}
	s.At = at
	s.IngressIf = ingressIf
	s.SampleRate = sampleRate
	if s.SampleRate == 0 {
		s.SampleRate = 1
	}
	return s, true
}

// DecodeEthernet peels the Ethernet (and any VLAN) header and decodes the inner
// IPv4/IPv6 packet.
func DecodeEthernet(b []byte) (detector.Sample, bool) {
	if len(b) < 14 {
		return detector.Sample{}, false
	}
	typ := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for typ == etherTypeVLAN {
		if len(b) < off+4 {
			return detector.Sample{}, false
		}
		typ = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	switch typ {
	case etherTypeIPv4:
		return DecodeIPv4(b[off:])
	case etherTypeIPv6:
		return DecodeIPv6(b[off:])
	default:
		return detector.Sample{}, false
	}
}

// DecodeIPv4 decodes an IPv4 packet header (at offset 0) into a Sample.
func DecodeIPv4(b []byte) (detector.Sample, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return detector.Sample{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return detector.Sample{}, false
	}
	totalLen := binary.BigEndian.Uint16(b[2:4])
	proto := b[9]
	src := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	dst := netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]})
	s := detector.Sample{
		Family:    flowspec.FamilyIPv4,
		Src:       src,
		Dst:       dst,
		Proto:     proto,
		PacketLen: totalLen,
	}
	// Only the first fragment (fragment offset 0) carries the L4 header. Reading
	// ports from a later fragment would parse payload bytes as a TCP/UDP header and
	// fabricate ports, so skip them for non-initial fragments.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff == 0 {
		fillPorts(&s, b[ihl:])
	}
	return s, true
}

// DecodeIPv6 decodes an IPv6 packet header (at offset 0) into a Sample.
func DecodeIPv6(b []byte) (detector.Sample, bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return detector.Sample{}, false
	}
	payloadLen := binary.BigEndian.Uint16(b[4:6])
	var srcBytes, dstBytes [16]byte
	copy(srcBytes[:], b[8:24])
	copy(dstBytes[:], b[24:40])
	// Walk any IPv6 extension headers so Proto/ports reflect the real L4 header
	// rather than the first extension header.
	proto, l4 := skipIPv6ExtHeaders(b[6], b[40:])
	s := detector.Sample{
		Family:    flowspec.FamilyIPv6,
		Src:       netip.AddrFrom16(srcBytes),
		Dst:       netip.AddrFrom16(dstBytes),
		Proto:     proto,
		PacketLen: ClampU16(uint32(payloadLen) + 40),
	}
	fillPorts(&s, l4)
	return s, true
}

// skipIPv6ExtHeaders advances past IPv6 extension headers starting at Next-Header
// value next over rest, returning the upper-layer protocol number and the bytes
// at the L4 header. It stops at the first non-extension header (or when it cannot
// continue, e.g. ESP/encrypted or a truncated header), in which case l4 may be
// nil and fillPorts simply reads nothing.
func skipIPv6ExtHeaders(next byte, rest []byte) (proto byte, l4 []byte) {
	// Each iteration shrinks rest, so this terminates; the cap just bounds work
	// on a pathological header chain.
	for i := 0; i < 8; i++ {
		var hdrLen int
		switch next {
		case extHopByHop, extRouting, extDestOpts, extMobility:
			if len(rest) < 2 {
				return next, nil
			}
			hdrLen = (int(rest[1]) + 1) * 8
		case extFragment:
			if len(rest) < 8 {
				return next, nil
			}
			// Only the first fragment (offset 0) carries the L4 header. For a later
			// fragment the real upper-layer protocol is still known (the Fragment
			// header's Next Header), but there are no ports to read.
			if binary.BigEndian.Uint16(rest[2:4])>>3 != 0 {
				return rest[0], nil
			}
			hdrLen = 8 // fixed length; rest[1] is reserved, not a length field
		case extAH:
			if len(rest) < 2 {
				return next, nil
			}
			hdrLen = (int(rest[1]) + 2) * 4 // AH payload length is in 4-octet units
		default:
			return next, rest // upper-layer protocol (or unparseable): stop here
		}
		if hdrLen <= 0 || len(rest) < hdrLen {
			return next, nil
		}
		next = rest[0]
		rest = rest[hdrLen:]
	}
	return next, rest
}

func fillPorts(s *detector.Sample, payload []byte) {
	switch s.Proto {
	case protoTCP:
		if len(payload) < 14 {
			return
		}
		s.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		s.DstPort = binary.BigEndian.Uint16(payload[2:4])
		s.TCPFlags = payload[13]
	case protoUDP:
		if len(payload) < 4 {
			return
		}
		s.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		s.DstPort = binary.BigEndian.Uint16(payload[2:4])
	case protoICMP, protoICMPv6:
		// ICMP type/code are the first two bytes of the L4 header — the same
		// offset the port fields would occupy.
		if len(payload) < 2 {
			return
		}
		s.ICMPType = payload[0]
		s.ICMPCode = payload[1]
	}
}

// ClampU16 saturates a uint32 length to the uint16 range used by Sample.PacketLen.
func ClampU16(v uint32) uint16 {
	if v > 0xffff {
		return 0xffff
	}
	return uint16(v)
}
