package vpp

import (
	"net/netip"
	"testing"

	"go.fd.io/govpp/binapi/acl_types"
)

// VPP's ACL plugin is default-deny, so every Managed ACL must end with a
// permit-any of its family; otherwise non-matching (legitimate) traffic — and an
// entire family that has no FlowSpec rules — would be dropped.
func TestBuildACLRules_AppendsPermitAny(t *testing.T) {
	deny := ACLRule{
		Permit:                 false,
		Dst:                    netip.MustParsePrefix("203.0.113.10/32"),
		Src:                    netip.MustParsePrefix("0.0.0.0/0"),
		Proto:                  17,
		DstPortOrICMPCodeFirst: 443, DstPortOrICMPCodeLast: 443,
		SrcPortOrICMPTypeLast: 65535,
	}

	got, err := buildACLRules(IPv4, []ACLRule{deny})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d binapi rules, want 2 (deny + permit-any)", len(got))
	}
	if got[0].IsPermit != acl_types.ACL_ACTION_API_DENY {
		t.Errorf("rule[0] should be the deny rule, got action %v", got[0].IsPermit)
	}
	last := got[len(got)-1]
	if last.IsPermit != acl_types.ACL_ACTION_API_PERMIT {
		t.Errorf("trailing rule must be permit, got %v", last.IsPermit)
	}
	if last.Proto != 0 || last.SrcPrefix.Len != 0 || last.DstPrefix.Len != 0 {
		t.Errorf("trailing permit must be any/any/any-proto, got %+v", last)
	}
}

// An empty family ACL must still permit that family (not default-deny it).
func TestBuildACLRules_EmptyFamilyPermitsAll(t *testing.T) {
	for _, fam := range []Family{IPv4, IPv6} {
		got, err := buildACLRules(fam, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("%s: got %d rules, want 1 (permit-any only)", fam, len(got))
		}
		if got[0].IsPermit != acl_types.ACL_ACTION_API_PERMIT {
			t.Errorf("%s: empty ACL must be a single permit-any, got %v", fam, got[0].IsPermit)
		}
	}
}

// mergeManagedLast must preserve manually-configured ACLs, drop any stale managed
// ones, and place our pair last within the managed direction so manual ACLs keep
// precedence (VPP matches in list order, first match wins).
func TestMergeManagedLast(t *testing.T) {
	managed := map[uint32]bool{1: true, 2: true, 7: true} // ours=1,2; 7=orphan tag
	ours := []uint32{1, 2}

	cases := []struct {
		name       string
		cur        []uint32
		nInput     uint8
		dir        Direction
		wantAcls   []uint32
		wantNInput uint8
	}{
		{
			name: "empty interface, ingress",
			cur:  nil, nInput: 0, dir: Ingress,
			wantAcls: []uint32{1, 2}, wantNInput: 2,
		},
		{
			name: "manual input keeps precedence, ours appended last",
			cur:  []uint32{9}, nInput: 1, dir: Ingress,
			wantAcls: []uint32{9, 1, 2}, wantNInput: 3,
		},
		{
			name: "manual input and output preserved, ours into input section",
			cur:  []uint32{9, 8}, nInput: 1, dir: Ingress,
			wantAcls: []uint32{9, 1, 2, 8}, wantNInput: 3,
		},
		{
			name: "egress appends ours to the output section",
			cur:  []uint32{9, 8}, nInput: 1, dir: Egress,
			wantAcls: []uint32{9, 8, 1, 2}, wantNInput: 1,
		},
		{
			name: "re-attach is idempotent and re-orders ours to last",
			cur:  []uint32{1, 9, 2}, nInput: 3, dir: Ingress,
			wantAcls: []uint32{9, 1, 2}, wantNInput: 3,
		},
		{
			name: "stale orphan-tagged acl is stripped",
			cur:  []uint32{7, 9}, nInput: 2, dir: Ingress,
			wantAcls: []uint32{9, 1, 2}, wantNInput: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAcls, gotNInput := mergeManagedLast(tc.cur, tc.nInput, managed, ours, tc.dir)
			if gotNInput != tc.wantNInput {
				t.Errorf("nInput = %d, want %d", gotNInput, tc.wantNInput)
			}
			if len(gotAcls) != len(tc.wantAcls) {
				t.Fatalf("acls = %v, want %v", gotAcls, tc.wantAcls)
			}
			for i := range gotAcls {
				if gotAcls[i] != tc.wantAcls[i] {
					t.Fatalf("acls = %v, want %v", gotAcls, tc.wantAcls)
				}
			}
		})
	}
}
