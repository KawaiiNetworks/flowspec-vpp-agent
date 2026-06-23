// Package config defines the agent's YAML configuration and its validation.
// See deploy/config.example.yaml for a documented example (§19.2).
package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/logging"
)

// Config is the top-level agent configuration.
type Config struct {
	VPP      VPP       `yaml:"vpp"`
	BGP      BGP       `yaml:"bgp"`
	ACL      ACL       `yaml:"acl"`
	Metrics  Metrics   `yaml:"metrics"`
	Detector *Detector `yaml:"detector"` // present => detector enabled
	// Persist is the path of the state dump (detector rule history + VPP stats),
	// written on shutdown and reloaded on startup. Empty => default to persist.dump
	// next to the config file (see Load). Only used when the detector runs.
	Persist string `yaml:"persist"`
	Log     Log    `yaml:"log"`
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

// Peer is a single FlowSpec session (BGP peer). A peer can receive FlowSpec
// (import it into VPP and relay it), send FlowSpec (advertise our whole table to
// it), or both — independently (§17).
type Peer struct {
	Address string `yaml:"address"`  // neighbor IP
	PeerASN uint32 `yaml:"peer_asn"` // neighbor AS
	Port    uint16 `yaml:"port"`     // optional neighbor TCP port (transport)
	Passive bool   `yaml:"passive"`  // listen-only (typical for FlowSpec collectors)
	// Receive: accept this peer's FlowSpec (apply to VPP, relay to send peers).
	// Pointer so an omitted value defaults to true, preserving receive-only behavior.
	Receive *bool `yaml:"receive"`
	// Send: advertise our entire FlowSpec table (received rules + detector-originated)
	// to this peer. Defaults to false.
	Send bool `yaml:"send"`
}

// Receives reports whether inbound FlowSpec from this peer is accepted. An
// omitted `receive` defaults to true.
func (p Peer) Receives() bool { return p.Receive == nil || *p.Receive }

// BGPEnabled reports whether the embedded BGP speaker should run. BGP is enabled
// exactly when at least one peer is configured; a speaker with no peers does
// nothing, so an empty/absent bgp section means "detector-only, no BGP".
func (c Config) BGPEnabled() bool { return len(c.BGP.Peers) > 0 }

// ACL controls how the Managed ACLs are applied to the data plane. FlowSpec
// carries no interface info, so this is purely local policy.
type ACL struct {
	Interfaces Interfaces `yaml:"interfaces"`
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

// Detector controls the optional sFlow/VPP-stats driven detector. Its mere
// presence in the config enables it — there is no `enabled` flag. Rules are
// loaded from the embedded predefined set plus an optional runtime directory;
// RulesEnabled selects which (by name) are activated.
type Detector struct {
	DryRun       bool      `yaml:"dry_run"`       // log triggered events; take no action
	RulesDir     string    `yaml:"rules_dir"`     // optional dir of user rule files (*.yaml)
	RulesEnabled []string  `yaml:"rules_enabled"` // rule names to activate
	SFlow        SFlow     `yaml:"sflow"`
	VPPStats     *VPPStats `yaml:"vpp_stats"` // present => poll VPP interface counters
	SampleQueue  int       `yaml:"sample_queue"`
	EventQueue   int       `yaml:"event_queue"`
}

type SFlow struct {
	Listen string `yaml:"listen"`
}

// VPPStats controls VPP interface-counter polling. Its presence enables polling
// (so detector rules can use vpp.* metrics); there is no `enabled` flag. The
// fine/medium/coarse rings use the same model as a rule's history, so vpp.*
// terms can aggregate over a window/offset; omitted rings fall back to defaults.
type VPPStats struct {
	Interval Duration `yaml:"interval"`
	Fine     Ring     `yaml:"fine"`
	Medium   Ring     `yaml:"medium"`
	Coarse   Ring     `yaml:"coarse"`
}

// Ring is one history ring's resolution and total retained duration. A zero
// field means "use the built-in default".
type Ring struct {
	Resolution Duration `yaml:"resolution"`
	Duration   Duration `yaml:"duration"`
}

// DetectorEnabled reports whether the detector should run. It is enabled exactly
// when a `detector:` section is present.
func (c Config) DetectorEnabled() bool { return c.Detector != nil }

// VPPStatsEnabled reports whether VPP interface-counter polling is on, i.e. a
// `vpp_stats:` block is present under the detector.
func (d *Detector) VPPStatsEnabled() bool { return d != nil && d.VPPStats != nil }

// Log configures the logging sinks. stderr is always active (defaulting to
// level info, scope all, format text); telegram is enabled only when present.
type Log struct {
	Stderr   *StderrLog   `yaml:"stderr"`   // nil => default stderr sink
	Telegram *TelegramLog `yaml:"telegram"` // nil => disabled
}

// StderrLog tunes the default stderr sink. Omitted fields use info/all/text.
type StderrLog struct {
	Level  string   `yaml:"level"`  // debug|info|warn|error (default info)
	Scope  ScopeSet `yaml:"scope"`  // all|none|name|[names] (default all)
	Format string   `yaml:"format"` // text|json (default text)
}

// TelegramLog configures a Telegram Bot sink: formatted log records are batched
// and delivered to a chat. bot_token and chat_id are required when present.
type TelegramLog struct {
	BotToken string   `yaml:"bot_token"`
	ChatID   string   `yaml:"chat_id"`
	Level    string   `yaml:"level"`  // default info
	Scope    ScopeSet `yaml:"scope"`  // default all
	Format   string   `yaml:"format"` // default text
}

// ScopeSet selects which log scopes a sink receives. In YAML it accepts a scalar
// `all` (every scope), `none` (disable the sink), a single scope name, or a list
// of names. An omitted scope (Set==false) defaults to all.
type ScopeSet struct {
	Set    bool     // whether the field was present
	All    bool     // "all"
	Scopes []string // explicit scope names ("none"/empty + !All => disabled)
}

func (s *ScopeSet) UnmarshalYAML(value *yaml.Node) error {
	s.Set = true
	var one string
	if err := value.Decode(&one); err == nil {
		switch strings.ToLower(strings.TrimSpace(one)) {
		case "all":
			s.All = true
		case "none", "":
			// disabled: All stays false, Scopes empty
		default:
			s.Scopes = []string{one}
		}
		return nil
	}
	var many []string
	if err := value.Decode(&many); err != nil {
		return fmt.Errorf("scope: expected 'all', 'none', a scope name, or a list of names")
	}
	s.Scopes = many
	return nil
}

// resolve reports the effective filter: omitted or "all" => all scopes; otherwise
// the explicit list (empty => the sink receives nothing).
func (s ScopeSet) resolve() (all bool, scopes []string) {
	if !s.Set || s.All {
		return true, nil
	}
	return false, s.Scopes
}

// Options resolves the log config into a logging.Options (filling stderr defaults
// and leaving telegram nil when absent).
func (l Log) Options() logging.Options {
	o := logging.Options{Stderr: logging.SinkSpec{Level: slog.LevelInfo, All: true, Format: "text"}}
	if l.Stderr != nil {
		o.Stderr = sinkSpec(l.Stderr.Level, l.Stderr.Format, l.Stderr.Scope)
	}
	if l.Telegram != nil {
		o.Telegram = &logging.TelegramSpec{
			SinkSpec: sinkSpec(l.Telegram.Level, l.Telegram.Format, l.Telegram.Scope),
			BotToken: l.Telegram.BotToken,
			ChatID:   l.Telegram.ChatID,
		}
	}
	return o
}

func sinkSpec(level, format string, scope ScopeSet) logging.SinkSpec {
	if format == "" {
		format = "text"
	}
	all, scopes := scope.resolve()
	return logging.SinkSpec{Level: parseLevel(level), All: all, Scopes: scopes, Format: format}
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Default values applied before unmarshalling (§19.2). The detector is left nil
// (absent => disabled); its sub-defaults are filled by applyDetectorDefaults
// only when a detector section is present.
func defaults() Config {
	return Config{
		VPP: VPP{
			Socket:      "/run/vpp/api.sock",
			StatsSocket: "/run/vpp/stats.sock",
		},
		BGP: BGP{
			Listen: "0.0.0.0:10179",
		},
		ACL: ACL{
			Interfaces: Interfaces{
				Mode:      "all",
				Direction: "ingress",
			},
		},
	}
}

// applyDetectorDefaults fills detector sub-defaults when a detector section is
// present. Absent sections stay nil (disabled).
func (c *Config) applyDetectorDefaults() {
	if c.Detector == nil {
		return
	}
	if c.Detector.SFlow.Listen == "" {
		c.Detector.SFlow.Listen = "0.0.0.0:6343"
	}
	if c.Detector.SampleQueue == 0 {
		c.Detector.SampleQueue = 65536
	}
	if c.Detector.EventQueue == 0 {
		c.Detector.EventQueue = 1024
	}
	if c.Detector.VPPStats != nil && c.Detector.VPPStats.Interval.Duration() <= 0 {
		c.Detector.VPPStats.Interval = Duration(1000000000) // 1s
	}
}

// Load reads, parses and validates the YAML config at path. When persist is left
// empty it defaults to persist.dump alongside the config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, err
	}
	if cfg.Persist == "" {
		cfg.Persist = filepath.Join(filepath.Dir(path), "persist.dump")
	}
	return cfg, nil
}

// Parse parses and validates YAML config bytes, applying defaults first.
func Parse(data []byte) (Config, error) {
	cfg := defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDetectorDefaults()
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
	// BGP is only validated and started when peers are configured. A detector-only
	// deployment needs no router_id and runs no speaker.
	if c.BGPEnabled() {
		if err := validateBGPListen(c.BGP.Listen); err != nil {
			return err
		}
		if c.BGP.RouterID == "" {
			return fmt.Errorf("bgp.router_id must be set when bgp.peers are configured")
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
			if !p.Receives() && !p.Send {
				return fmt.Errorf("bgp.peers[%d] has receive=false and send=false: nothing to do", i)
			}
		}
	}
	if !c.BGPEnabled() && !c.DetectorEnabled() {
		return fmt.Errorf("nothing to do: configure bgp.peers or add a detector section")
	}
	switch c.ACL.Interfaces.Mode {
	case "all":
	case "list":
		if len(c.ACL.Interfaces.List) == 0 {
			return fmt.Errorf("acl.interfaces.mode=list requires a non-empty acl.interfaces.list")
		}
	default:
		return fmt.Errorf("acl.interfaces.mode %q must be 'all' or 'list'", c.ACL.Interfaces.Mode)
	}
	switch c.ACL.Interfaces.Direction {
	case "ingress", "egress":
	default:
		return fmt.Errorf("acl.interfaces.direction %q must be 'ingress' or 'egress'", c.ACL.Interfaces.Direction)
	}
	if c.Metrics.Listen != "" {
		if err := validateHostPort(c.Metrics.Listen, "metrics.listen"); err != nil {
			return err
		}
	}
	if c.DetectorEnabled() {
		if len(c.Detector.RulesEnabled) == 0 {
			return fmt.Errorf("detector requires a non-empty rules_enabled list")
		}
		if c.Detector.SFlow.Listen == "" {
			return fmt.Errorf("detector.sflow.listen must be set")
		}
		if err := validateHostPort(c.Detector.SFlow.Listen, "detector.sflow.listen"); err != nil {
			return err
		}
		if c.Detector.SampleQueue <= 0 {
			return fmt.Errorf("detector.sample_queue must be > 0")
		}
		if c.Detector.EventQueue <= 0 {
			return fmt.Errorf("detector.event_queue must be > 0")
		}
		if c.Detector.VPPStatsEnabled() && c.Detector.VPPStats.Interval.Duration() <= 0 {
			return fmt.Errorf("detector.vpp_stats.interval must be > 0")
		}
	}
	if err := validateLog(c.Log); err != nil {
		return err
	}
	return nil
}

func validateLog(l Log) error {
	if l.Stderr != nil {
		if err := validateLogSink("log.stderr", l.Stderr.Level, l.Stderr.Format, l.Stderr.Scope); err != nil {
			return err
		}
	}
	if l.Telegram != nil {
		if err := validateLogSink("log.telegram", l.Telegram.Level, l.Telegram.Format, l.Telegram.Scope); err != nil {
			return err
		}
		if l.Telegram.BotToken == "" {
			return fmt.Errorf("log.telegram.bot_token must be set")
		}
		if l.Telegram.ChatID == "" {
			return fmt.Errorf("log.telegram.chat_id must be set")
		}
	}
	return nil
}

func validateLogSink(name, level, format string, scope ScopeSet) error {
	if level != "" {
		switch strings.ToLower(level) {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("%s.level %q must be debug|info|warn|error", name, level)
		}
	}
	if format != "" {
		switch strings.ToLower(format) {
		case "text", "json":
		default:
			return fmt.Errorf("%s.format %q must be text|json", name, format)
		}
	}
	for _, s := range scope.Scopes {
		if !logging.Valid(s) {
			return fmt.Errorf("%s.scope %q is not a known scope (%s)", name, s, strings.Join(logging.AllScopes, ", "))
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
