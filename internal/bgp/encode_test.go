package bgp

import (
	"net/netip"
	"testing"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// encode then decode (via flowspec.ParseNLRI) must reproduce the rule's match,
// so a relayed/originated rule is byte-faithful to what we model.
func TestEncodeNLRI_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		rule flowspec.Rule
	}{
		{
			name: "ipv4 udp src-port to dst",
			rule: flowspec.Rule{
				Family: flowspec.FamilyIPv4,
				Match: flowspec.Match{
					HasDst:  true,
					Dst:     netip.MustParsePrefix("203.0.113.10/32"),
					Proto:   []flowspec.NumericOp{{EQ: true, Value: 17}},
					SrcPort: []flowspec.NumericOp{{EQ: true, Value: 53}},
				},
			},
		},
		{
			name: "ipv4 tcp syn flood port range",
			rule: flowspec.Rule{
				Family: flowspec.FamilyIPv4,
				Match: flowspec.Match{
					HasSrc:   true,
					Src:      netip.MustParsePrefix("198.51.100.0/24"),
					Proto:    []flowspec.NumericOp{{EQ: true, Value: 6}},
					DstPort:  []flowspec.NumericOp{{GT: true, EQ: true, Value: 1024}, {And: true, LT: true, EQ: true, Value: 2048}},
					TCPFlags: []flowspec.BitmaskOp{{Match: true, Value: 0x02}},
				},
			},
		},
		{
			name: "ipv6 dst with proto",
			rule: flowspec.Rule{
				Family: flowspec.FamilyIPv6,
				Match: flowspec.Match{
					HasDst: true,
					Dst:    netip.MustParsePrefix("2001:db8::/64"),
					Proto:  []flowspec.NumericOp{{EQ: true, Value: 58}},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nlri, err := encodeNLRI(c.rule)
			if err != nil {
				t.Fatalf("encodeNLRI: %v", err)
			}
			// Decode straight back through the production parser (no attrs needed
			// for the match portion).
			got, err := flowspec.ParseNLRI(nlri, nil)
			if err != nil {
				t.Fatalf("ParseNLRI: %v", err)
			}
			if got.Family != c.rule.Family {
				t.Errorf("family = %v, want %v", got.Family, c.rule.Family)
			}
			assertMatch(t, got.Match, c.rule.Match)
		})
	}
}

func TestEncodeNLRI_NoComponents(t *testing.T) {
	_, err := encodeNLRI(flowspec.Rule{Family: flowspec.FamilyIPv4})
	if err == nil {
		t.Fatal("expected error for rule with no match components")
	}
}

func assertMatch(t *testing.T, got, want flowspec.Match) {
	t.Helper()
	if got.HasDst != want.HasDst || got.Dst != want.Dst {
		t.Errorf("dst = %v/%v, want %v/%v", got.HasDst, got.Dst, want.HasDst, want.Dst)
	}
	if got.HasSrc != want.HasSrc || got.Src != want.Src {
		t.Errorf("src = %v/%v, want %v/%v", got.HasSrc, got.Src, want.HasSrc, want.Src)
	}
	assertNumeric(t, "proto", got.Proto, want.Proto)
	assertNumeric(t, "src_port", got.SrcPort, want.SrcPort)
	assertNumeric(t, "dst_port", got.DstPort, want.DstPort)
	assertNumeric(t, "icmp_type", got.ICMPType, want.ICMPType)
	assertNumeric(t, "icmp_code", got.ICMPCode, want.ICMPCode)
	if len(got.TCPFlags) != len(want.TCPFlags) {
		t.Errorf("tcp_flags len = %d, want %d", len(got.TCPFlags), len(want.TCPFlags))
		return
	}
	for i := range want.TCPFlags {
		if got.TCPFlags[i] != want.TCPFlags[i] {
			t.Errorf("tcp_flags[%d] = %+v, want %+v", i, got.TCPFlags[i], want.TCPFlags[i])
		}
	}
}

func assertNumeric(t *testing.T, field string, got, want []flowspec.NumericOp) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s len = %d, want %d", field, len(got), len(want))
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %+v, want %+v", field, i, got[i], want[i])
		}
	}
}
