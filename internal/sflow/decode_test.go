package sflow

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

func TestDecoderDecodeRawIPv4UDP(t *testing.T) {
	now := time.Unix(1000, 0)
	dgram := buildDatagram()
	samples, err := (Decoder{}).Decode(dgram, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("decoded %d samples, want 1", len(samples))
	}
	s := samples[0]
	if s.At != now {
		t.Fatalf("time = %s, want %s", s.At, now)
	}
	if s.Family != flowspec.FamilyIPv4 {
		t.Fatalf("family = %s, want ipv4", s.Family)
	}
	if s.Src != netip.MustParseAddr("198.51.100.9") || s.Dst != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("src/dst = %s/%s", s.Src, s.Dst)
	}
	if s.Proto != protoUDP || s.SrcPort != 12345 || s.DstPort != 53 {
		t.Fatalf("proto/ports = %d/%d/%d", s.Proto, s.SrcPort, s.DstPort)
	}
	if s.PacketLen != 60 {
		t.Fatalf("packet len = %d, want 60", s.PacketLen)
	}
	if s.SampleRate != 1000 {
		t.Fatalf("sample rate = %d, want 1000", s.SampleRate)
	}
	if s.IngressIf != "ifindex:3" {
		t.Fatalf("ingress = %q, want ifindex:3", s.IngressIf)
	}
}

// The decoder pulls ICMP/ICMPv6 type and code from the same L4 offset it reads
// ports from, for both address families.
func TestDecodeICMPTypeCode(t *testing.T) {
	// IPv4 + ICMP echo-request (type 8, code 0).
	v4 := make([]byte, 20+4)
	v4[0] = 0x45
	binary.BigEndian.PutUint16(v4[2:4], uint16(len(v4)))
	v4[9] = protoICMP
	copy(v4[12:16], []byte{198, 51, 100, 1})
	copy(v4[16:20], []byte{203, 0, 113, 1})
	v4[20], v4[21] = 8, 0 // type, code
	if s, ok := decodeIPv4(v4); !ok || s.Proto != protoICMP || s.ICMPType != 8 || s.ICMPCode != 0 {
		t.Fatalf("v4 icmp = ok %v proto %d type %d code %d", ok, s.Proto, s.ICMPType, s.ICMPCode)
	}

	// IPv6 + ICMPv6 neighbor solicitation (type 135, code 0).
	v6 := make([]byte, 40+4)
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:6], 4) // payload length
	v6[6] = protoICMPv6
	copy(v6[8:24], netip.MustParseAddr("2001:db8::99").AsSlice())
	copy(v6[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())
	v6[40], v6[41] = 135, 0 // type, code
	if s, ok := decodeIPv6(v6); !ok || s.Proto != protoICMPv6 || s.ICMPType != 135 || s.ICMPCode != 0 {
		t.Fatalf("v6 icmp = ok %v proto %d type %d code %d", ok, s.Proto, s.ICMPType, s.ICMPCode)
	}
}

func buildDatagram() []byte {
	var b builder
	b.u32(datagramVersion5)
	b.u32(1)                      // agent address type IPv4
	b.bytes([]byte{192, 0, 2, 1}) // agent address
	b.u32(0)                      // sub-agent id
	b.u32(1)                      // datagram sequence
	b.u32(100)                    // uptime
	b.u32(1)                      // sample count

	sample := buildFlowSample()
	b.u32(sampleFlowSample)
	b.u32(uint32(len(sample)))
	b.bytes(sample)
	b.pad4(len(sample))
	return b.b
}

func buildFlowSample() []byte {
	var b builder
	b.u32(1)    // sequence
	b.u32(0)    // source id
	b.u32(1000) // sampling rate
	b.u32(1000) // sample pool
	b.u32(0)    // drops
	b.u32(3)    // input ifindex
	b.u32(0)    // output
	b.u32(1)    // record count

	record := buildRawHeader()
	b.u32(recordRawPacketHeader)
	b.u32(uint32(len(record)))
	b.bytes(record)
	b.pad4(len(record))
	return b.b
}

func buildRawHeader() []byte {
	header := buildEthernetIPv4UDP()
	var b builder
	b.u32(headerEthernetISO8023)
	b.u32(60) // frame length
	b.u32(4)  // stripped
	b.u32(uint32(len(header)))
	b.bytes(header)
	return b.b
}

func buildEthernetIPv4UDP() []byte {
	b := make([]byte, 14+20+8)
	copy(b[0:6], []byte{0, 1, 2, 3, 4, 5})
	copy(b[6:12], []byte{6, 7, 8, 9, 10, 11})
	binary.BigEndian.PutUint16(b[12:14], etherTypeIPv4)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28)
	ip[8] = 64
	ip[9] = protoUDP
	copy(ip[12:16], []byte{198, 51, 100, 9})
	copy(ip[16:20], []byte{203, 0, 113, 10})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	return b
}

type builder struct {
	b []byte
}

func (b *builder) u32(v uint32) {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	b.b = append(b.b, tmp[:]...)
}

func (b *builder) bytes(v []byte) {
	b.b = append(b.b, v...)
}

func (b *builder) pad4(n int) {
	for i := 0; i < pad4(n); i++ {
		b.b = append(b.b, 0)
	}
}
