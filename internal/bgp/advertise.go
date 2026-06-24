package bgp

import (
	"context"
	"fmt"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	gobgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// Advertiser originates FlowSpec rules upstream. The detector lease controller
// holds one (nil when BGP is disabled) and calls it as leases come and go.
type Advertiser interface {
	Advertise(ctx context.Context, r flowspec.Rule, withdraw bool) error
}

// Advertise originates (withdraw=false) or removes (withdraw=true) a FlowSpec
// discard rule in the global RIB. The configured export policy then restricts
// delivery to "send" peers only (§17). The agent only ever originates a pure
// drop (traffic-rate 0); it never originates any other action.
func (s *Server) Advertise(ctx context.Context, r flowspec.Rule, withdraw bool) error {
	if s.bgp == nil {
		return fmt.Errorf("bgp server not started")
	}
	nlri, err := encodeNLRI(r)
	if err != nil {
		return fmt.Errorf("encode flowspec nlri: %w", err)
	}
	nexthop := "0.0.0.0"
	if r.Family == flowspec.FamilyIPv6 {
		nexthop = "::"
	}
	attrs := []gobgp.PathAttributeInterface{
		gobgp.NewPathAttributeOrigin(0), // IGP
		gobgp.NewPathAttributeMpReachNLRI(nexthop, []gobgp.AddrPrefixInterface{nlri}),
		gobgp.NewPathAttributeExtendedCommunities([]gobgp.ExtendedCommunityInterface{
			// rate 0 == discard. The AS field is only 2 bytes (RFC 8955) and purely
			// informational for a discard, so a 32-bit ASN is intentionally truncated
			// here; receivers ignore it when the rate is 0. If 4-byte-ASN fidelity ever
			// matters, pass 0 instead of truncating.
			gobgp.NewTrafficRateExtended(uint16(s.opts.ASN), 0),
		}),
	}
	path, err := apiutil.NewPath(nlri, false, attrs, time.Now())
	if err != nil {
		return fmt.Errorf("build flowspec path: %w", err)
	}
	if withdraw {
		return s.bgp.DeletePath(ctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: path})
	}
	_, err = s.bgp.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: path})
	return err
}
