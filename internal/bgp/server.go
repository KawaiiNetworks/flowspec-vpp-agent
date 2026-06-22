package bgp

import (
	"context"
	"fmt"
	"log/slog"

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
}

// Server embeds a GoBGP speaker and turns received FlowSpec routes into a stream
// of Update events.
type Server struct {
	opts    Options
	log     *slog.Logger
	bgp     *server.BgpServer
	updates chan Update
}

// New creates a Server. Call Start to bring it up.
func New(opts Options, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		opts:    opts,
		log:     logger,
		updates: make(chan Update, 1024),
	}
}

// Updates returns the channel of FlowSpec events. The manager consumes it.
func (s *Server) Updates() <-chan Update { return s.updates }

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

// Stop shuts the speaker down and closes the Updates channel.
func (s *Server) Stop() {
	if s.bgp != nil {
		s.bgp.Stop()
	}
	close(s.updates)
}
