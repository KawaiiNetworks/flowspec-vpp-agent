// Package config defines the agent's YAML configuration and its validation.
// See deploy/config.example.yaml for a documented example (§19.2).
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level agent configuration.
type Config struct {
	VPP        VPP        `yaml:"vpp"`
	BGP        BGP        `yaml:"bgp"`
	Interfaces Interfaces `yaml:"interfaces"`
	Metrics    Metrics    `yaml:"metrics"`
	Log        Log        `yaml:"log"`
}

// VPP holds VPP connection settings. Both sockets live under /run/vpp (§19).
type VPP struct {
	Socket      string `yaml:"socket"`
	StatsSocket string `yaml:"stats_socket"`
}

// BGP holds the embedded GoBGP speaker settings (§19).
type BGP struct {
	Listen   string `yaml:"listen"`    // host:port, default 0.0.0.0:10179
	RouterID string `yaml:"router_id"` // dotted-quad BGP router id
	ASN      uint32 `yaml:"asn"`       // local AS number
	Peers    []Peer `yaml:"peers"`     // one session per peer (§17)
}

// Peer is a single FlowSpec session (BGP peer).
type Peer struct {
	Address string `yaml:"address"`  // neighbor IP
	PeerASN uint32 `yaml:"peer_asn"` // neighbor AS
	Port    uint16 `yaml:"port"`     // optional neighbor TCP port (transport)
	Passive bool   `yaml:"passive"`  // listen-only (typical for FlowSpec collectors)
}

// Interfaces controls where the Managed ACLs are applied (§16).
type Interfaces struct {
	Mode      string   `yaml:"mode"`      // "all" (default) or "list"
	List      []string `yaml:"list"`      // explicit interface names when mode=list
	Direction string   `yaml:"direction"` // "ingress" (default) or "egress"
}

// Metrics controls the Prometheus/health HTTP endpoint.
type Metrics struct {
	Listen string `yaml:"listen"` // host:port for /metrics and /healthz
}

// Log controls logging.
type Log struct {
	Level  string `yaml:"level"`  // debug|info|warn|error
	Format string `yaml:"format"` // text|json
}

// Default values applied before unmarshalling (§19.2).
func defaults() Config {
	return Config{
		VPP: VPP{
			Socket:      "/run/vpp/api.sock",
			StatsSocket: "/run/vpp/stats.sock",
		},
		BGP: BGP{
			Listen: "0.0.0.0:10179",
		},
		Interfaces: Interfaces{
			Mode:      "all",
			Direction: "ingress",
		},
		Metrics: Metrics{
			Listen: "0.0.0.0:9469",
		},
		Log: Log{Level: "info", Format: "text"},
	}
}

// Load reads, parses and validates the YAML config at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse parses and validates YAML config bytes, applying defaults first.
func Parse(data []byte) (Config, error) {
	cfg := defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the configuration for internal consistency.
func (c Config) Validate() error {
	if c.VPP.Socket == "" {
		return fmt.Errorf("vpp.socket must be set")
	}
	if err := validateHostPort(c.BGP.Listen, "bgp.listen"); err != nil {
		return err
	}
	if c.BGP.RouterID != "" {
		addr, err := netip.ParseAddr(c.BGP.RouterID)
		if err != nil {
			return fmt.Errorf("bgp.router_id %q: %w", c.BGP.RouterID, err)
		}
		if !addr.Is4() {
			return fmt.Errorf("bgp.router_id %q must be an IPv4 address", c.BGP.RouterID)
		}
	}
	for i, p := range c.BGP.Peers {
		if _, err := netip.ParseAddr(p.Address); err != nil {
			return fmt.Errorf("bgp.peers[%d].address %q: %w", i, p.Address, err)
		}
		if p.PeerASN == 0 {
			return fmt.Errorf("bgp.peers[%d].peer_asn must be set", i)
		}
	}
	switch c.Interfaces.Mode {
	case "all":
	case "list":
		if len(c.Interfaces.List) == 0 {
			return fmt.Errorf("interfaces.mode=list requires a non-empty interfaces.list")
		}
	default:
		return fmt.Errorf("interfaces.mode %q must be 'all' or 'list'", c.Interfaces.Mode)
	}
	switch c.Interfaces.Direction {
	case "ingress", "egress":
	default:
		return fmt.Errorf("interfaces.direction %q must be 'ingress' or 'egress'", c.Interfaces.Direction)
	}
	if err := validateHostPort(c.Metrics.Listen, "metrics.listen"); err != nil {
		return err
	}
	return nil
}

func validateHostPort(hp, field string) error {
	if hp == "" {
		return fmt.Errorf("%s must be set", field)
	}
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		return fmt.Errorf("%s %q must be host:port", field, hp)
	}
	port, err := strconv.Atoi(hp[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s %q has invalid port", field, hp)
	}
	return nil
}
