package bgp

import (
	"context"
	"fmt"

	api "github.com/osrg/gobgp/v3/api"
)

// Policy/defined-set names installed on the global RIB.
const (
	receiveSetName = "flowspec-receive-peers"
	sendSetName    = "flowspec-send-peers"
	importPolicy   = "flowspec-import"
	exportPolicy   = "flowspec-export"
	globalRIB      = "global"
)

// applyPolicies installs global import/export policies that gate FlowSpec
// propagation by peer direction (§17):
//
//   - EXPORT defaults to REJECT, accepting only peers in the send-set. This is
//     the per-peer isolation guarantee: a non-send peer never receives FlowSpec
//     we originate or relay, even though it negotiated the family.
//   - IMPORT defaults to REJECT, accepting only peers in the receive-set, so a
//     non-receive peer's routes never enter the loc-rib and are never relayed.
//     (VPP application is gated separately in handlePath, which reads adj-rib-in
//     before policy.)
//
// Per-neighbor policy assignment in GoBGP requires route-server clients, so we
// use global policies with neighbor-set conditions instead.
func (s *Server) applyPolicies(ctx context.Context) error {
	var receivePeers, sendPeers []string
	for _, p := range s.opts.Peers {
		if p.Receive {
			receivePeers = append(receivePeers, p.Address)
		}
		if p.Send {
			sendPeers = append(sendPeers, p.Address)
		}
	}

	importPolicies, err := s.installDirection(ctx, importPolicy, receiveSetName, receivePeers)
	if err != nil {
		return fmt.Errorf("import policy: %w", err)
	}
	exportPolicies, err := s.installDirection(ctx, exportPolicy, sendSetName, sendPeers)
	if err != nil {
		return fmt.Errorf("export policy: %w", err)
	}

	// Both directions default to REJECT; the accept-statement (when any peer
	// qualifies) is the only way through.
	if err := s.bgp.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          globalRIB,
			Direction:     api.PolicyDirection_IMPORT,
			Policies:      importPolicies,
			DefaultAction: api.RouteAction_REJECT,
		},
	}); err != nil {
		return fmt.Errorf("assign import policy: %w", err)
	}
	if err := s.bgp.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          globalRIB,
			Direction:     api.PolicyDirection_EXPORT,
			Policies:      exportPolicies,
			DefaultAction: api.RouteAction_REJECT,
		},
	}); err != nil {
		return fmt.Errorf("assign export policy: %w", err)
	}
	return nil
}

// installDirection creates a neighbor defined-set and a one-statement policy that
// accepts routes whose neighbor is in that set. It returns the policy list to
// assign (empty when no peer qualifies, leaving the direction at default REJECT).
func (s *Server) installDirection(ctx context.Context, policyName, setName string, peers []string) ([]*api.Policy, error) {
	if len(peers) == 0 {
		return nil, nil
	}
	if err := s.bgp.AddDefinedSet(ctx, &api.AddDefinedSetRequest{
		DefinedSet: &api.DefinedSet{
			DefinedType: api.DefinedType_NEIGHBOR,
			Name:        setName,
			List:        peers,
		},
	}); err != nil {
		return nil, fmt.Errorf("defined set: %w", err)
	}
	policy := &api.Policy{
		Name: policyName,
		Statements: []*api.Statement{{
			Name: policyName + "-accept",
			Conditions: &api.Conditions{
				NeighborSet: &api.MatchSet{Type: api.MatchSet_ANY, Name: setName},
			},
			Actions: &api.Actions{RouteAction: api.RouteAction_ACCEPT},
		}},
	}
	if err := s.bgp.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}); err != nil {
		return nil, fmt.Errorf("add policy: %w", err)
	}
	return []*api.Policy{policy}, nil
}
