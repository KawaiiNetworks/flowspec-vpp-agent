package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// FromEthernet decodes an Ethernet+IPv4+UDP frame and stamps the caller-supplied
// sample metadata (timestamp, sample rate, ingress interface).
func TestFromEthernetIPv4UDP(t *testing.T) {
	b := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(b[12:14], etherTypeIPv4)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28) // total length
	ip[9] = protoUDP
	copy(ip[12:16], []byte{198, 51, 100, 9})
	copy(ip[16:20], []byte{203, 0, 113, 10})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 53)

	now := time.Unix(1000, 0)
	s, ok := FromEthernet(b, now, 4096, "eth0")
	if !ok {
		t.Fatal("decode failed")
	}
	if s.At != now || s.SampleRate != 4096 || s.IngressIf != "eth0" {
		t.Fatalf("metadata = %s/%d/%q", s.At, s.SampleRate, s.IngressIf)
	}
	if s.Family != flowspec.FamilyIPv4 || s.Proto != protoUDP || s.SrcPort != 12345 || s.DstPort != 53 {
		t.Fatalf("decoded = %s proto %d ports %d/%d", s.Family, s.Proto, s.SrcPort, s.DstPort)
	}
}

// A zero sample rate is normalized to 1 so weighting never multiplies by zero.
func TestFromEthernetZeroRate(t *testing.T) {
	b := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(b[12:14], etherTypeIPv4)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28)
	ip[9] = protoUDP
	if s, ok := FromEthernet(b, time.Unix(1, 0), 0, ""); !ok || s.SampleRate != 1 {
		t.Fatalf("rate = %d, want 1", s.SampleRate)
	}
}

// DecodeIPv4/DecodeIPv6 pull ICMP type/code from the same L4 offset as ports.
func TestDecodeICMPTypeCode(t *testing.T) {
	v4 := make([]byte, 20+4)
	v4[0] = 0x45
	binary.BigEndian.PutUint16(v4[2:4], uint16(len(v4)))
	v4[9] = protoICMP
	copy(v4[12:16], []byte{198, 51, 100, 1})
	copy(v4[16:20], []byte{203, 0, 113, 1})
	v4[20], v4[21] = 8, 0
	if s, ok := DecodeIPv4(v4); !ok || s.Proto != protoICMP || s.ICMPType != 8 || s.ICMPCode != 0 {
		t.Fatalf("v4 icmp = ok %v proto %d type %d code %d", ok, s.Proto, s.ICMPType, s.ICMPCode)
	}

	v6 := make([]byte, 40+4)
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:6], 4)
	v6[6] = protoICMPv6
	copy(v6[8:24], netip.MustParseAddr("2001:db8::99").AsSlice())
	copy(v6[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())
	v6[40], v6[41] = 135, 0
	if s, ok := DecodeIPv6(v6); !ok || s.Proto != protoICMPv6 || s.ICMPType != 135 || s.ICMPCode != 0 {
		t.Fatalf("v6 icmp = ok %v proto %d type %d code %d", ok, s.Proto, s.ICMPType, s.ICMPCode)
	}
}

// A non-initial IPv4 fragment (fragment offset != 0) must NOT have its payload
// parsed as an L4 header, or the decoder would fabricate ports.
func TestDecodeIPv4LaterFragmentNoPorts(t *testing.T) {
	v4 := make([]byte, 20+8)
	v4[0] = 0x45
	binary.BigEndian.PutUint16(v4[2:4], uint16(len(v4)))
	binary.BigEndian.PutUint16(v4[6:8], 10) // fragment offset != 0
	v4[9] = protoUDP
	udp := v4[20:]
	binary.BigEndian.PutUint16(udp[0:2], 12345) // would-be src port
	binary.BigEndian.PutUint16(udp[2:4], 53)    // would-be dst port
	s, ok := DecodeIPv4(v4)
	if !ok || s.Proto != protoUDP {
		t.Fatalf("decode = ok %v proto %d", ok, s.Proto)
	}
	if s.SrcPort != 0 || s.DstPort != 0 {
		t.Fatalf("later fragment fabricated ports %d/%d", s.SrcPort, s.DstPort)
	}
}

// An IPv6 packet with a Hop-by-Hop extension header must report the real L4
// protocol and ports, not the extension header.
func TestDecodeIPv6ExtensionHeader(t *testing.T) {
	// IPv6(40) + Hop-by-Hop(8) + UDP(8).
	b := make([]byte, 40+8+8)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], 8+8) // payload length
	b[6] = extHopByHop                       // first next-header
	copy(b[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(b[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	ext := b[40:]
	ext[0] = protoUDP // hop-by-hop next-header -> UDP
	ext[1] = 0        // hdr ext len: (0+1)*8 = 8 bytes
	udp := b[48:]
	binary.BigEndian.PutUint16(udp[0:2], 1111)
	binary.BigEndian.PutUint16(udp[2:4], 2222)
	s, ok := DecodeIPv6(b)
	if !ok || s.Proto != protoUDP || s.SrcPort != 1111 || s.DstPort != 2222 {
		t.Fatalf("ext-header decode = ok %v proto %d ports %d/%d", ok, s.Proto, s.SrcPort, s.DstPort)
	}
}
