package sflow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/packet"
)

const (
	datagramVersion5 = 5

	sampleFlowSample         = 1
	sampleExpandedFlowSample = 3

	recordRawPacketHeader = 1

	headerEthernetISO8023 = 1
	headerIPv4            = 11
	headerIPv6            = 12
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
	var ok2 bool
	switch headerProtocol {
	case headerEthernetISO8023:
		s, ok2 = packet.DecodeEthernet(header)
	case headerIPv4:
		s, ok2 = packet.DecodeIPv4(header)
	case headerIPv6:
		s, ok2 = packet.DecodeIPv6(header)
	default:
		return detector.Sample{}, false
	}
	if !ok2 {
		return detector.Sample{}, false
	}
	s.At = now
	// sFlow carries the original (pre-sampling) frame length explicitly, which is
	// more accurate than the IP header's length for a truncated header sample.
	s.PacketLen = packet.ClampU16(frameLen)
	s.IngressIf = inputIf
	s.SampleRate = sampleRate
	if s.SampleRate == 0 {
		s.SampleRate = 1
	}
	return s, true
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
