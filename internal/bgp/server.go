package bgp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
)

// Options configures the embedded GoBGP speaker (§19). It is intentionally a
// plain struct so this package does not depend on internal/config.
type Options struct {
	ASN        uint32
	RouterID   string
	ListenAddr string // listen address, e.g. 0.0.0.0
	ListenPort int32  // default 10179 (§19)
	Peers      []PeerOptions
}

// PeerOptions describes one FlowSpec session / BGP peer (§17).
type PeerOptions struct {
	Address string
	PeerASN uint32
	Port    uint16 // optional transport port
	Passive bool   // listen-only (typical for FlowSpec collectors)
	// Receive: accept this peer's FlowSpec (apply to VPP, relay onward).
	Receive bool
	// Send: advertise our whole FlowSpec table to this peer.
	Send bool
}

// Server embeds a GoBGP speaker and turns received FlowSpec routes into a stream
// of Update events.
type Server struct {
	opts    Options
	log     *slog.Logger
	bgp     *server.BgpServer
	updates chan Update
	// stopCh is closed by Stop to release any watch callback currently blocked
	// delivering an update. GoBGP runs watch callbacks on its own goroutine, so
	// this is what lets Stop return without (a) deadlocking against a blocked
	// send and (b) racing a send against a closed channel — updates is never
	// closed; the consumer stops on its own context instead.
	stopCh   chan struct{}
	stopOnce sync.Once
	// receivePeers is the set of peer addresses whose inbound FlowSpec we apply
	// to VPP. adj-rib-in is watched pre-policy, so this gates handlePath directly.
	receivePeers map[string]bool
}

// New creates a Server. Call Start to bring it up.
func New(opts Options, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	receivePeers := make(map[string]bool, len(opts.Peers))
	for _, p := range opts.Peers {
		if p.Receive {
			receivePeers[normalizeAddr(p.Address)] = true
		}
	}
	return &Server{
		opts:         opts,
		log:          logger,
		updates:      make(chan Update, 1024),
		stopCh:       make(chan struct{}),
		receivePeers: receivePeers,
	}
}

// Updates returns the channel of FlowSpec events. The consumer reads it until
// its own context is cancelled; the channel is never closed (see Stop).
func (s *Server) Updates() <-chan Update { return s.updates }

// normalizeAddr canonicalizes an IP string so equivalent spellings compare equal
// (e.g. "2001:db8:0:0::1" and "2001:db8::1"). It keys the receive-peer set and
// identifies sessions, so GoBGP's spelling of a peer address always matches the
// configured one. Non-IP identifiers are returned unchanged.
func normalizeAddr(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return s
}

// send delivers u to the updates channel. It blocks until the consumer accepts
// the update — FlowSpec must not be silently dropped, since a dropped announce
// is an unmitigated attack — or until Stop is called, whichever comes first.
// A sustained block here back-pressures GoBGP's event dispatch by design: if the
// consumer is wedged (e.g. VPP unreachable) no rule can be programmed anyway, so
// stalling is preferable to discarding rules.
func (s *Server) send(u Update) {
	select {
	case s.updates <- u:
	case <-s.stopCh:
	}
}

// Start brings up the BGP speaker, configures peers and begins watching the
// FlowSpec adj-rib-in. It returns once the speaker is listening; events arrive
// asynchronously on Updates().
func (s *Server) Start(ctx context.Context) error {
	s.bgp = server.NewBgpServer()
	go s.bgp.Serve()

	listenPort := s.opts.ListenPort
	if listenPort == 0 {
		listenPort = 10179
	}
	global := &api.Global{
		Asn:        s.opts.ASN,
		RouterId:   s.opts.RouterID,
		ListenPort: listenPort,
	}
	if s.opts.ListenAddr != "" {
		global.ListenAddresses = []string{s.opts.ListenAddr}
	}
	if err := s.bgp.StartBgp(ctx, &api.StartBgpRequest{Global: global}); err != nil {
		return fmt.Errorf("start bgp: %w", err)
	}

	// Install direction policies before peers come up, so propagation is gated
	// from the first established session.
	if err := s.applyPolicies(ctx); err != nil {
		return fmt.Errorf("apply policies: %w", err)
	}

	for _, p := range s.opts.Peers {
		if err := s.addPeer(ctx, p); err != nil {
			return fmt.Errorf("add peer %s: %w", p.Address, err)
		}
	}

	if err := s.startWatch(ctx); err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	s.log.Info("BGP speaker started", "listen_port", listenPort, "peers", len(s.opts.Peers))
	return nil
}

func (s *Server) addPeer(ctx context.Context, p PeerOptions) error {
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: p.Address,
			PeerAsn:         p.PeerASN,
		},
		Transport: &api.Transport{
			PassiveMode: p.Passive,
			RemotePort:  uint32(p.Port),
		},
		// Negotiate both IPv4 and IPv6 FlowSpec on every session (§1).
		AfiSafis: []*api.AfiSafi{
			{Config: &api.AfiSafiConfig{Family: &api.Family{
				Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: &api.Family{
				Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}, Enabled: true}},
		},
	}
	return s.bgp.AddPeer(ctx, &api.AddPeerRequest{Peer: peer})
}

// Stop shuts the speaker down. It first closes stopCh to release any watch
// callback currently blocked in send, then stops GoBGP. Order matters: GoBGP's
// Stop may wait for in-flight watch callbacks to return, and one of those could
// be blocked sending on a full updates channel — releasing send first avoids
// that deadlock. The updates channel is intentionally not closed, since GoBGP
// may still invoke callbacks while Stop runs.
func (s *Server) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	if s.bgp != nil {
		s.bgp.Stop()
	}
}
