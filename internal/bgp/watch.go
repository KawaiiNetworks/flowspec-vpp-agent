package bgp

import (
	"context"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// startWatch subscribes to the FlowSpec adj-rib-in (per-peer, so multi-session
// ownership is preserved, §17) and to peer state changes (so a session going
// down withdraws all its rules, §17). Events are delivered asynchronously.
func (s *Server) startWatch(ctx context.Context) error {
	req := &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				// ADJIN with Init=true: replay current adj-rib-in then stream changes.
				{Type: api.WatchEventRequest_Table_Filter_ADJIN, Init: true},
			},
		},
		Peer: &api.WatchEventRequest_Peer{},
	}
	return s.bgp.WatchEvent(ctx, req, func(r *api.WatchEventResponse) {
		s.handleEvent(r)
	})
}

func (s *Server) handleEvent(r *api.WatchEventResponse) {
	if te := r.GetTable(); te != nil {
		for _, path := range te.GetPaths() {
			s.handlePath(path)
		}
	}
	if pe := r.GetPeer(); pe != nil {
		s.handlePeerEvent(pe)
	}
}

func (s *Server) handlePath(path *api.Path) {
	session := path.GetNeighborIp()
	if session == "" {
		session = path.GetSourceId()
	}
	// adj-rib-in is watched pre-policy, so apply the per-peer receive gate here:
	// a non-receive peer's FlowSpec must never reach the manager / VPP.
	if !s.receivePeers[session] {
		s.log.Debug("skip path from non-receive peer", "peer", session)
		return
	}

	nlri, err := apiutil.GetNativeNlri(path)
	if err != nil {
		s.log.Debug("skip path: cannot decode NLRI", "error", err)
		return
	}
	attrs, err := apiutil.GetNativePathAttributes(path)
	if err != nil {
		s.log.Debug("skip path: cannot decode attributes", "error", err)
		return
	}

	rule, err := flowspec.ParseNLRI(nlri, attrs)
	if err != nil {
		// Not a FlowSpec route (or structurally unusable); ignore.
		s.log.Debug("skip non-flowspec path", "error", err)
		return
	}

	op := OpAnnounce
	if path.GetIsWithdraw() {
		op = OpWithdraw
	}

	s.updates <- Update{
		Session: SessionID(session),
		Op:      op,
		Rule:    rule,
		Peer:    session,
	}
}

func (s *Server) handlePeerEvent(pe *api.WatchEventResponse_PeerEvent) {
	if pe.GetType() != api.WatchEventResponse_PeerEvent_STATE {
		return
	}
	peer := pe.GetPeer()
	if peer == nil || peer.GetState() == nil {
		return
	}
	addr := peer.GetState().GetNeighborAddress()
	if peer.GetState().GetSessionState() == api.PeerState_ESTABLISHED {
		// Coming up: nothing to do here; ADJIN replay will (re)announce its rules.
		return
	}
	// Any non-established state is treated as the session withdrawing all its
	// rules (§17). The manager handles this idempotently.
	s.log.Info("session not established, withdrawing its rules", "peer", addr,
		"state", peer.GetState().GetSessionState().String())
	s.updates <- Update{Session: SessionID(addr), Op: OpSessionDown, Peer: addr}
}
