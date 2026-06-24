package sflow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

const (
	datagramVersion5 = 5

	sampleFlowSample         = 1
	sampleExpandedFlowSample = 3

	recordRawPacketHeader = 1

	headerEthernetISO8023 = 1
	headerIPv4            = 11
	headerIPv6            = 12

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

// Decoder extracts compact detector samples from sFlow v5 datagrams.
type Decoder struct{}

// Decode parses one sFlow datagram. It keeps only sampled packet metadata and
// skips unsupported sample/record types.
func (Decoder) Decode(data []byte, now time.Time) ([]detector.Sample, error) {
	r := reader{b: data}
	version, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short sflow datagram")
	}
	if version != datagramVersion5 {
		return nil, fmt.Errorf("unsupported sflow version %d", version)
	}
	if _, ok := readAgent(&r); !ok {
		return nil, fmt.Errorf("short sflow agent address")
	}
	if _, ok := r.u32(); !ok { // sub-agent id
		return nil, fmt.Errorf("short sflow sub-agent id")
	}
	if _, ok := r.u32(); !ok { // sequence number
		return nil, fmt.Errorf("short sflow sequence")
	}
	if _, ok := r.u32(); !ok { // uptime
		return nil, fmt.Errorf("short sflow uptime")
	}
	n, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short sflow sample count")
	}
	var samples []detector.Sample
	for i := uint32(0); i < n; i++ {
		format, ok := r.u32()
		if !ok {
			return nil, fmt.Errorf("short sflow sample type")
		}
		l, ok := r.u32()
		if !ok || int(l) > r.left() {
			return nil, fmt.Errorf("short sflow sample payload")
		}
		payload := r.take(int(l))
		if !r.skip(pad4(int(l))) {
			return nil, fmt.Errorf("short sflow sample padding")
		}
		decoded, err := decodeSample(format&0x00000fff, payload, now)
		if err != nil {
			return nil, err
		}
		samples = append(samples, decoded...)
	}
	return samples, nil
}

func decodeSample(format uint32, data []byte, now time.Time) ([]detector.Sample, error) {
	r := reader{b: data}
	var sampleRate uint32
	var inputIf string
	switch format {
	case sampleFlowSample:
		if _, ok := r.u32(); !ok { // sequence
			return nil, fmt.Errorf("short flow sample sequence")
		}
		if _, ok := r.u32(); !ok { // source id
			return nil, fmt.Errorf("short flow sample source id")
		}
		var ok bool
		if sampleRate, ok = r.u32(); !ok {
			return nil, fmt.Errorf("short flow sample rate")
		}
		if _, ok := r.u32(); !ok { // sample pool
			return nil, fmt.Errorf("short flow sample pool")
		}
		if _, ok := r.u32(); !ok { // drops
			return nil, fmt.Errorf("short flow sample drops")
		}
		input, ok := r.u32()
		if !ok {
			return nil, fmt.Errorf("short flow sample input")
		}
		inputIf = ifIndexName(input)
		if _, ok := r.u32(); !ok { // output
			return nil, fmt.Errorf("short flow sample output")
		}
	case sampleExpandedFlowSample:
		if _, ok := r.u32(); !ok { // sequence
			return nil, fmt.Errorf("short expanded flow sample sequence")
		}
		if _, ok := r.u32(); !ok { // source id class
			return nil, fmt.Errorf("short expanded flow sample source id class")
		}
		if _, ok := r.u32(); !ok { // source id index
			return nil, fmt.Errorf("short expanded flow sample source id index")
		}
		var ok bool
		if sampleRate, ok = r.u32(); !ok {
			return nil, fmt.Errorf("short expanded flow sample rate")
		}
		if _, ok := r.u32(); !ok { // sample pool
			return nil, fmt.Errorf("short expanded flow sample pool")
		}
		if _, ok := r.u32(); !ok { // drops
			return nil, fmt.Errorf("short expanded flow sample drops")
		}
		if _, ok := r.u32(); !ok { // input format
			return nil, fmt.Errorf("short expanded flow sample input format")
		}
		input, ok := r.u32()
		if !ok {
			return nil, fmt.Errorf("short expanded flow sample input value")
		}
		inputIf = ifIndexName(input)
		if _, ok := r.u32(); !ok { // output format
			return nil, fmt.Errorf("short expanded flow sample output format")
		}
		if _, ok := r.u32(); !ok { // output value
			return nil, fmt.Errorf("short expanded flow sample output value")
		}
	default:
		return nil, nil
	}
	records, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short flow sample record count")
	}
	var out []detector.Sample
	for i := uint32(0); i < records; i++ {
		recordFormat, ok := r.u32()
		if !ok {
			return nil, fmt.Errorf("short flow record type")
		}
		l, ok := r.u32()
		if !ok || int(l) > r.left() {
			return nil, fmt.Errorf("short flow record payload")
		}
		payload := r.take(int(l))
		if !r.skip(pad4(int(l))) {
			return nil, fmt.Errorf("short flow record padding")
		}
		if recordFormat&0x00000fff != recordRawPacketHeader {
			continue
		}
		s, ok := decodeRawHeader(payload, now, sampleRate, inputIf)
		if ok {
			out = append(out, s)
		}
	}
	return out, nil
}

func decodeRawHeader(data []byte, now time.Time, sampleRate uint32, inputIf string) (detector.Sample, bool) {
	r := reader{b: data}
	headerProtocol, ok := r.u32()
	if !ok {
		return detector.Sample{}, false
	}
	frameLen, ok := r.u32()
	if !ok {
		return detector.Sample{}, false
	}
	if _, ok := r.u32(); !ok { // stripped
		return detector.Sample{}, false
	}
	headerLen, ok := r.u32()
	if !ok || int(headerLen) > r.left() {
		return detector.Sample{}, false
	}
	header := r.take(int(headerLen))
	var s detector.Sample
	switch headerProtocol {
	case headerEthernetISO8023:
		var ok bool
		s, ok = decodeEthernet(header)
		if !ok {
			return detector.Sample{}, false
		}
	case headerIPv4:
		var ok bool
		s, ok = decodeIPv4(header)
		if !ok {
			return detector.Sample{}, false
		}
	case headerIPv6:
		var ok bool
		s, ok = decodeIPv6(header)
		if !ok {
			return detector.Sample{}, false
		}
	default:
		return detector.Sample{}, false
	}
	s.At = now
	s.PacketLen = clampU16(frameLen)
	s.IngressIf = inputIf
	s.SampleRate = sampleRate
	if s.SampleRate == 0 {
		s.SampleRate = 1
	}
	return s, true
}

func decodeEthernet(b []byte) (detector.Sample, bool) {
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
		return decodeIPv4(b[off:])
	case etherTypeIPv6:
		return decodeIPv6(b[off:])
	default:
		return detector.Sample{}, false
	}
}

func decodeIPv4(b []byte) (detector.Sample, bool) {
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

func decodeIPv6(b []byte) (detector.Sample, bool) {
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
		PacketLen: clampU16(uint32(payloadLen) + 40),
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

func readAgent(r *reader) (netip.Addr, bool) {
	typ, ok := r.u32()
	if !ok {
		return netip.Addr{}, false
	}
	switch typ {
	case 1:
		b, ok := r.bytes(4)
		if !ok {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}), true
	case 2:
		b, ok := r.bytes(16)
		if !ok {
			return netip.Addr{}, false
		}
		var a [16]byte
		copy(a[:], b)
		return netip.AddrFrom16(a), true
	default:
		return netip.Addr{}, false
	}
}

func ifIndexName(v uint32) string {
	if v == 0 || v == 0x3fffffff {
		return ""
	}
	return fmt.Sprintf("ifindex:%d", v&0x3fffffff)
}

func clampU16(v uint32) uint16 {
	if v > 0xffff {
		return 0xffff
	}
	return uint16(v)
}

type reader struct {
	b []byte
	n int
}

func (r *reader) left() int { return len(r.b) - r.n }

func (r *reader) u32() (uint32, bool) {
	if r.left() < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.n : r.n+4])
	r.n += 4
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.left() < n {
		return nil, false
	}
	v := r.b[r.n : r.n+n]
	r.n += n
	return v, true
}

func (r *reader) take(n int) []byte {
	v, _ := r.bytes(n)
	return v
}

func (r *reader) skip(n int) bool {
	_, ok := r.bytes(n)
	return ok
}

func pad4(n int) int {
	return (4 - (n % 4)) % 4
}
