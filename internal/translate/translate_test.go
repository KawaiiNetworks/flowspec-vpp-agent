package translate

import (
	"net/netip"
	"testing"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

func drop() flowspec.Action { return flowspec.Action{Kind: flowspec.ActionDrop, Desc: "discard"} }

func eq(v uint64) []flowspec.NumericOp  { return []flowspec.NumericOp{{EQ: true, Value: v}} }
func gt(v uint64) []flowspec.NumericOp  { return []flowspec.NumericOp{{GT: true, Value: v}} }
func lt(v uint64) []flowspec.NumericOp  { return []flowspec.NumericOp{{LT: true, Value: v}} }
func gte(v uint64) []flowspec.NumericOp { return []flowspec.NumericOp{{GT: true, EQ: true, Value: v}} }
func lte(v uint64) []flowspec.NumericOp { return []flowspec.NumericOp{{LT: true, EQ: true, Value: v}} }

// range a..b expressed as ">=a && <=b"
func rng(a, b uint64) []flowspec.NumericOp {
	return []flowspec.NumericOp{{GT: true, EQ: true, Value: a}, {And: true, LT: true, EQ: true, Value: b}}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

func TestTranslate_IPv4_UDP_DstPort(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: drop(),
		Match: flowspec.Match{
			HasDst:  true,
			Dst:     mustPrefix(t, "203.0.113.10/32"),
			Proto:   eq(17),
			DstPort: eq(443),
		},
	}
	got, err := Translate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.IsIPv6 || got.Permit {
		t.Fatalf("want ipv4 deny, got %+v", got)
	}
	if got.Proto != 17 {
		t.Errorf("proto = %d, want 17", got.Proto)
	}
	if got.Dst.String() != "203.0.113.10/32" {
		t.Errorf("dst = %s", got.Dst)
	}
	if got.Src.String() != "0.0.0.0/0" {
		t.Errorf("src default = %s, want 0.0.0.0/0", got.Src)
	}
	if got.DstPortOrICMPCodeFirst != 443 || got.DstPortOrICMPCodeLast != 443 {
		t.Errorf("dport = %d-%d", got.DstPortOrICMPCodeFirst, got.DstPortOrICMPCodeLast)
	}
	if got.SrcPortOrICMPTypeFirst != 0 || got.SrcPortOrICMPTypeLast != 65535 {
		t.Errorf("sport default = %d-%d, want 0-65535", got.SrcPortOrICMPTypeFirst, got.SrcPortOrICMPTypeLast)
	}
}

func TestTranslate_IPv4_UDP_SrcPort(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: drop(),
		Match: flowspec.Match{
			HasDst: true, Dst: mustPrefix(t, "203.0.113.10/32"),
			Proto: eq(17), SrcPort: eq(123),
		},
	}
	got, err := Translate(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.SrcPortOrICMPTypeFirst != 123 || got.SrcPortOrICMPTypeLast != 123 {
		t.Errorf("sport = %d-%d, want 123-123", got.SrcPortOrICMPTypeFirst, got.SrcPortOrICMPTypeLast)
	}
}

func TestTranslate_TCPFlags_InferProto(t *testing.T) {
	// syn,!ack with no explicit protocol -> proto inferred as tcp.
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: drop(),
		Match: flowspec.Match{
			HasDst: true, Dst: mustPrefix(t, "203.0.113.10/32"),
			DstPort: eq(80),
			TCPFlags: []flowspec.BitmaskOp{
				{Value: tcpSYN},
				{And: true, Not: true, Value: tcpACK},
			},
		},
	}
	got, err := Translate(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Proto != protoTCP {
		t.Errorf("proto = %d, want %d (tcp inferred)", got.Proto, protoTCP)
	}
	if got.TCPFlagsValue != tcpSYN {
		t.Errorf("tcp value = %#x, want syn %#x", got.TCPFlagsValue, tcpSYN)
	}
	if got.TCPFlagsMask != (tcpSYN | tcpACK) {
		t.Errorf("tcp mask = %#x, want syn|ack %#x", got.TCPFlagsMask, tcpSYN|tcpACK)
	}
}

func TestTranslate_TCPFlags_NonTCPProto_Rejected(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: drop(),
		Match: flowspec.Match{
			Proto:    eq(17), // udp
			TCPFlags: []flowspec.BitmaskOp{{Value: tcpSYN}},
		},
	}
	_, err := Translate(r)
	assertReason(t, err, ReasonUnsupportedExpression)
}

func TestTranslate_TCPFlags_MultiBitAnyRejected(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: drop(),
		Match: flowspec.Match{
			Proto:    eq(protoTCP),
			TCPFlags: []flowspec.BitmaskOp{{Value: tcpSYN | tcpACK}}, // m=0: SYN or ACK
		},
	}
	_, err := Translate(r)
	assertReason(t, err, ReasonUnsupportedExpression)
}

func TestTranslate_TCPFlags_MultiBitAllAccepted(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: drop(),
		Match: flowspec.Match{
			Proto:    eq(protoTCP),
			TCPFlags: []flowspec.BitmaskOp{{Match: true, Value: tcpSYN | tcpACK}},
		},
	}
	got, err := Translate(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.TCPFlagsValue != tcpSYN|tcpACK || got.TCPFlagsMask != tcpSYN|tcpACK {
		t.Fatalf("tcp flags value/mask = %#x/%#x, want %#x/%#x",
			got.TCPFlagsValue, got.TCPFlagsMask, tcpSYN|tcpACK, tcpSYN|tcpACK)
	}
}

func TestTranslate_ICMP_InferProto_V4(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv4,
		Action: drop(),
		Match: flowspec.Match{
			HasDst: true, Dst: mustPrefix(t, "203.0.113.10/32"),
			ICMPType: eq(8), ICMPCode: eq(0),
		},
	}
	got, err := Translate(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Proto != protoICMP {
		t.Errorf("proto = %d, want icmp", got.Proto)
	}
	if got.SrcPortOrICMPTypeFirst != 8 || got.SrcPortOrICMPTypeLast != 8 {
		t.Errorf("icmp type field = %d-%d, want 8", got.SrcPortOrICMPTypeFirst, got.SrcPortOrICMPTypeLast)
	}
	if got.DstPortOrICMPCodeFirst != 0 || got.DstPortOrICMPCodeLast != 0 {
		t.Errorf("icmp code field = %d-%d, want 0", got.DstPortOrICMPCodeFirst, got.DstPortOrICMPCodeLast)
	}
}

func TestTranslate_ICMPv6_InferProto(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv6,
		Action: drop(),
		Match: flowspec.Match{
			HasDst: true, Dst: mustPrefix(t, "2001:db8::10/128"),
			ICMPType: eq(128), ICMPCode: eq(0),
		},
	}
	got, err := Translate(r)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsIPv6 || got.Proto != protoICMPv6 {
		t.Errorf("want ipv6 icmpv6, got ipv6=%v proto=%d", got.IsIPv6, got.Proto)
	}
	if got.SrcPortOrICMPTypeFirst != 128 {
		t.Errorf("icmp type = %d, want 128", got.SrcPortOrICMPTypeFirst)
	}
}

func TestTranslate_IPv6_Defaults(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv6,
		Action: drop(),
		Match:  flowspec.Match{HasDst: true, Dst: mustPrefix(t, "2001:db8::/48")},
	}
	got, err := Translate(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Src.String() != "::/0" {
		t.Errorf("src default = %s, want ::/0", got.Src)
	}
}

func TestTranslate_PortInequalities(t *testing.T) {
	cases := []struct {
		name   string
		ops    []flowspec.NumericOp
		lo, hi uint16
	}{
		{"gt1024", gt(1024), 1025, 65535},
		{"lt1024", lt(1024), 0, 1023},
		{"gte1024", gte(1024), 1024, 65535},
		{"lte1024", lte(1024), 0, 1024},
		{"range", rng(10000, 20000), 10000, 20000},
		{"eq80", eq(80), 80, 80},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := flowspec.Rule{Family: flowspec.FamilyIPv4, Action: drop(),
				Match: flowspec.Match{Proto: eq(6), DstPort: c.ops}}
			got, err := Translate(r)
			if err != nil {
				t.Fatal(err)
			}
			if got.DstPortOrICMPCodeFirst != c.lo || got.DstPortOrICMPCodeLast != c.hi {
				t.Errorf("got %d-%d, want %d-%d", got.DstPortOrICMPCodeFirst, got.DstPortOrICMPCodeLast, c.lo, c.hi)
			}
		})
	}
}

func TestTranslate_NumericTrueFalse(t *testing.T) {
	r := flowspec.Rule{Family: flowspec.FamilyIPv4, Action: drop(),
		Match: flowspec.Match{Proto: eq(6), DstPort: []flowspec.NumericOp{{}}}}
	got, err := Translate(r)
	if err != nil {
		t.Fatalf("numeric true should translate: %v", err)
	}
	if got.DstPortOrICMPCodeFirst != 0 || got.DstPortOrICMPCodeLast != portMax {
		t.Fatalf("numeric true port range = %d-%d, want 0-%d",
			got.DstPortOrICMPCodeFirst, got.DstPortOrICMPCodeLast, portMax)
	}

	r.Match.DstPort = []flowspec.NumericOp{{LT: true, GT: true, EQ: true}}
	_, err = Translate(r)
	assertReason(t, err, ReasonUnsupportedExpression)
}

func TestTranslate_Unsupported(t *testing.T) {
	base := func(m flowspec.Match) flowspec.Rule {
		return flowspec.Rule{Family: flowspec.FamilyIPv4, Action: drop(), Match: m}
	}
	cases := []struct {
		name   string
		rule   flowspec.Rule
		reason Reason
	}{
		{"rate>0 action", flowspec.Rule{Family: flowspec.FamilyIPv4,
			Action: flowspec.Action{Kind: flowspec.ActionUnsupported, Desc: "traffic-rate=1000000"},
			Match:  flowspec.Match{HasDst: true, Dst: mustPrefix(t, "203.0.113.10/32")}},
			ReasonUnsupportedAction},
		{"generic port", base(flowspec.Match{HasGenericPort: true}), ReasonUnsupportedComponent},
		{"packet length", base(flowspec.Match{HasPacketLen: true}), ReasonUnsupportedComponent},
		{"dscp", base(flowspec.Match{HasDSCP: true}), ReasonUnsupportedComponent},
		{"fragment", base(flowspec.Match{Fragment: []flowspec.BitmaskOp{{Value: 2}}}), ReasonUnsupportedComponent},
		{"dport without protocol", base(flowspec.Match{DstPort: eq(443)}), ReasonUnsupportedExpression},
		{"dport with icmp protocol", base(flowspec.Match{Proto: eq(protoICMP),
			DstPort: eq(443)}), ReasonUnsupportedExpression},
		{"icmp type with dport", base(flowspec.Match{ICMPType: eq(8),
			DstPort: eq(443)}), ReasonUnsupportedExpression},
		{"dport !=", base(flowspec.Match{Proto: eq(6),
			DstPort: []flowspec.NumericOp{{LT: true, GT: true, Value: 80}}}), ReasonUnsupportedExpression},
		{"dport OR", base(flowspec.Match{Proto: eq(6),
			DstPort: []flowspec.NumericOp{{EQ: true, Value: 80}, {EQ: true, Value: 443}}}), ReasonUnsupportedExpression},
		{"dport out of range", base(flowspec.Match{Proto: eq(6),
			DstPort: eq(portMax + 1)}), ReasonUnsupportedExpression},
		{"proto >", base(flowspec.Match{Proto: gt(10)}), ReasonUnsupportedExpression},
		{"tcp-flags high bit", base(flowspec.Match{Proto: eq(6),
			TCPFlags: []flowspec.BitmaskOp{{Value: 1 << 8}}}), ReasonUnsupportedExpression},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Translate(c.rule)
			assertReason(t, err, c.reason)
		})
	}
}

func TestTranslate_IPv6OffsetIgnored(t *testing.T) {
	r := flowspec.Rule{
		Family: flowspec.FamilyIPv6,
		Action: drop(),
		Match: flowspec.Match{
			HasDst: true, Dst: mustPrefix(t, "2001:db8::/48"), DstOffset: 16,
		},
	}
	_, err := Translate(r)
	assertReason(t, err, ReasonUnmappablePrefix)
}

func assertReason(t *testing.T, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with reason %q, got nil", want)
	}
	u, ok := AsUnsupported(err)
	if !ok {
		t.Fatalf("error %v is not *Unsupported", err)
	}
	if u.Reason != want {
		t.Fatalf("reason = %q, want %q (detail: %s)", u.Reason, want, u.Detail)
	}
}
