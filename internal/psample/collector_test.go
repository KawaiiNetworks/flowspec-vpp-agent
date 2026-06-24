package psample

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

func ethIPv4UDP(src, dst string, sport, dport uint16) []byte {
	b := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28)
	ip[9] = 17 // UDP
	copy(ip[12:16], netip.MustParseAddr(src).AsSlice())
	copy(ip[16:20], netip.MustParseAddr(dst).AsSlice())
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	return b
}

func psampleMsg(t *testing.T, group, rate uint32, ifindex uint16, data []byte) genetlink.Message {
	t.Helper()
	ae := netlink.NewAttributeEncoder()
	ae.Uint16(attrIIFIndex, ifindex)
	ae.Uint32(attrSampleGroup, group)
	ae.Uint32(attrSampleRate, rate)
	ae.Bytes(attrData, data)
	b, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return genetlink.Message{Data: b}
}

func TestDecodeBuildsSample(t *testing.T) {
	c := New(0, nil, nil) // accept any group
	frame := ethIPv4UDP("198.51.100.9", "203.0.113.10", 12345, 53)
	now := time.Unix(5, 0)
	s, ok := c.decode(psampleMsg(t, 7, 1000, 3, frame), now)
	if !ok {
		t.Fatal("decode failed")
	}
	// IngressIf must be "ifindex:N" (not a Linux name) to match vppstats' alias.
	if s.At != now || s.SampleRate != 1000 || s.IngressIf != "ifindex:3" {
		t.Fatalf("meta = %s rate %d if %q", s.At, s.SampleRate, s.IngressIf)
	}
	if s.Src != netip.MustParseAddr("198.51.100.9") || s.Dst != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("src/dst = %s/%s", s.Src, s.Dst)
	}
	if s.Proto != 17 || s.SrcPort != 12345 || s.DstPort != 53 {
		t.Fatalf("proto/ports = %d/%d/%d", s.Proto, s.SrcPort, s.DstPort)
	}
}

func TestDecodeGroupFilter(t *testing.T) {
	c := New(5, nil, nil) // only sample-group 5
	frame := ethIPv4UDP("198.51.100.1", "203.0.113.1", 1, 2)
	now := time.Unix(1, 0)
	if _, ok := c.decode(psampleMsg(t, 9, 1000, 0, frame), now); ok {
		t.Fatal("group 9 should be rejected when configured group is 5")
	}
	if _, ok := c.decode(psampleMsg(t, 5, 1000, 0, frame), now); !ok {
		t.Fatal("group 5 should be accepted")
	}
}

func TestDecodeNoData(t *testing.T) {
	c := New(0, nil, nil)
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(attrSampleRate, 1000) // no DATA attribute
	b, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.decode(genetlink.Message{Data: b}, time.Unix(1, 0)); ok {
		t.Fatal("message without packet data should be rejected")
	}
}
