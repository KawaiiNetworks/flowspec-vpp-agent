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
