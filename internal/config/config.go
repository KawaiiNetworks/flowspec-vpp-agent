// Package config defines the agent's YAML configuration and its validation.
// See deploy/config.example.yaml for a documented example (§19.2).
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

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
	RouterID string `yaml:"router_id"` // required dotted-quad BGP router id
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
	Listen string `yaml:"listen"` // host:port for /metrics and /healthz; empty disables HTTP
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
	if err := validateBGPListen(c.BGP.Listen); err != nil {
		return err
	}
	if c.BGP.RouterID == "" {
		return fmt.Errorf("bgp.router_id must be set")
	}
	addr, err := netip.ParseAddr(c.BGP.RouterID)
	if err != nil {
		return fmt.Errorf("bgp.router_id %q: %w", c.BGP.RouterID, err)
	}
	if !addr.Is4() {
		return fmt.Errorf("bgp.router_id %q must be an IPv4 address", c.BGP.RouterID)
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
	if c.Metrics.Listen != "" {
		if err := validateHostPort(c.Metrics.Listen, "metrics.listen"); err != nil {
			return err
		}
	}
	return nil
}

func validateBGPListen(hp string) error {
	host, _, err := splitHostPort(hp, "bgp.listen")
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("bgp.listen %q must include an IP address", hp)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("bgp.listen host %q must be an IP address: %w", host, err)
	}
	return nil
}

func validateHostPort(hp, field string) error {
	_, _, err := splitHostPort(hp, field)
	return err
}

func splitHostPort(hp, field string) (host string, port int, err error) {
	if hp == "" {
		return "", 0, fmt.Errorf("%s must be set", field)
	}
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, fmt.Errorf("%s %q must be host:port: %w", field, hp, err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%s %q has invalid port", field, hp)
	}
	return host, port, nil
}
