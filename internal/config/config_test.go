package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestParse_Defaults(t *testing.T) {
	cfg, err := Parse([]byte(`
bgp:
  router_id: 192.0.2.1
  asn: 65000
  peers:
    - address: 198.51.100.1
      peer_asn: 65001
      passive: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VPP.Socket != "/run/vpp/api.sock" {
		t.Errorf("default vpp.socket = %q", cfg.VPP.Socket)
	}
	if cfg.BGP.Listen != "0.0.0.0:10179" {
		t.Errorf("default bgp.listen = %q", cfg.BGP.Listen)
	}
	if cfg.ACL.Interfaces.Mode != "all" || cfg.ACL.Interfaces.Direction != "ingress" {
		t.Errorf("interface defaults = %+v", cfg.ACL.Interfaces)
	}
	if cfg.Metrics.Listen != "" {
		t.Errorf("default metrics.listen = %q, want disabled", cfg.Metrics.Listen)
	}
	if len(cfg.BGP.Peers) != 1 || !cfg.BGP.Peers[0].Passive {
		t.Errorf("peers = %+v", cfg.BGP.Peers)
	}
}

func TestParse_MetricsListenEnabled(t *testing.T) {
	cfg, err := Parse([]byte(`
bgp:
  router_id: 192.0.2.1
  peers:
    - address: 198.51.100.1
      peer_asn: 65001
metrics:
  listen: "127.0.0.1:9469"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Metrics.Listen != "127.0.0.1:9469" {
		t.Errorf("metrics.listen = %q", cfg.Metrics.Listen)
	}
}

func TestParse_Detector(t *testing.T) {
	cfg, err := Parse([]byte(`
bgp:
  router_id: 192.0.2.1
detector:
  rules_dir: /etc/flowspec-vpp-agent/rules
  rules_enabled:
    - udp-reflection-ipv4
    - tcp-scan-ipv4
  sflow:
    listen: "127.0.0.1:6343"
  sample_queue: 1024
  event_queue: 64
  vpp_stats:
    interval: 2s
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DetectorEnabled() {
		t.Fatal("detector disabled")
	}
	if !cfg.Detector.VPPStatsEnabled() {
		t.Fatal("vpp_stats should be enabled by presence")
	}
	if cfg.Detector.VPPStats.Interval.Duration().String() != "2s" {
		t.Fatalf("stats interval = %s, want 2s", cfg.Detector.VPPStats.Interval.Duration())
	}
	if len(cfg.Detector.RulesEnabled) != 2 || cfg.Detector.RulesEnabled[0] != "udp-reflection-ipv4" {
		t.Fatalf("rules_enabled = %v", cfg.Detector.RulesEnabled)
	}
	if cfg.Detector.RulesDir != "/etc/flowspec-vpp-agent/rules" {
		t.Fatalf("rules_dir = %q", cfg.Detector.RulesDir)
	}
}

// vpp_stats omitted => disabled; sub-defaults still fill in for a present detector.
func TestParse_DetectorDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
detector:
  rules_enabled: [udp-reflection-ipv4]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Detector.VPPStatsEnabled() {
		t.Error("vpp_stats should be disabled when omitted")
	}
	if cfg.Detector.SFlow.Listen != "0.0.0.0:6343" {
		t.Errorf("sflow.listen default = %q", cfg.Detector.SFlow.Listen)
	}
	if cfg.Detector.SampleQueue != 65536 || cfg.Detector.EventQueue != 1024 {
		t.Errorf("queue defaults = %d/%d", cfg.Detector.SampleQueue, cfg.Detector.EventQueue)
	}
}

func TestParse_PeerDirections(t *testing.T) {
	cfg, err := Parse([]byte(`
bgp:
  router_id: 192.0.2.1
  peers:
    - address: 198.51.100.1
      peer_asn: 65001
    - address: 203.0.113.1
      peer_asn: 65000
      receive: false
      send: true
`))
	if err != nil {
		t.Fatal(err)
	}
	// Omitted receive defaults to true; omitted send to false.
	if !cfg.BGP.Peers[0].Receives() || cfg.BGP.Peers[0].Send {
		t.Errorf("peer0 = receive %v send %v, want true/false", cfg.BGP.Peers[0].Receives(), cfg.BGP.Peers[0].Send)
	}
	if cfg.BGP.Peers[1].Receives() || !cfg.BGP.Peers[1].Send {
		t.Errorf("peer1 = receive %v send %v, want false/true", cfg.BGP.Peers[1].Receives(), cfg.BGP.Peers[1].Send)
	}
}

func TestParse_DetectorOnlyNoBGP(t *testing.T) {
	cfg, err := Parse([]byte(`
detector:
  rules_enabled: [udp-reflection-ipv4]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BGPEnabled() {
		t.Error("BGP should be disabled with no peers")
	}
	if !cfg.DetectorEnabled() {
		t.Error("detector should be enabled")
	}
}

func TestParse_IPv6Listen(t *testing.T) {
	cfg, err := Parse([]byte(`
bgp:
  listen: "[2001:db8::1]:10179"
  router_id: 192.0.2.1
  peers:
    - address: 198.51.100.1
      peer_asn: 65001
metrics:
  listen: "[::1]:9469"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BGP.Listen != "[2001:db8::1]:10179" {
		t.Errorf("bgp.listen = %q", cfg.BGP.Listen)
	}
	if cfg.Metrics.Listen != "[::1]:9469" {
		t.Errorf("metrics.listen = %q", cfg.Metrics.Listen)
	}
}

func TestValidate_Errors(t *testing.T) {
	cases := []string{
		"bgp:\n  asn: 65000\n", // missing router_id
		"bgp:\n  listen: nonsense\n",
		"bgp:\n  listen: ':10179'\n  router_id: 192.0.2.1\n",
		"bgp:\n  listen: '[not-ip]:10179'\n  router_id: 192.0.2.1\n",
		"bgp:\n  router_id: 2001:db8::1\n",
		"metrics:\n  listen: bad-port\n",
		"detector:\n  builtin_rules: false\n", // builtins off + no rules_enabled => nothing to run
		"detector:\n  rules_enabled: [x]\n  sflow:\n    listen: bad\n",
		"detector:\n  rules_enabled: [x]\n  sample_queue: -1\n",
		"detector:\n  rules_enabled: [x]\n  event_queue: -1\n",
		"acl:\n  interfaces:\n    mode: bogus\n",
		"acl:\n  interfaces:\n    mode: list\n", // list mode without list
		"bgp:\n  peers:\n    - address: notanip\n      peer_asn: 1\n",
		"bgp:\n  peers:\n    - address: 1.2.3.4\n",                                                             // missing peer_asn
		"bgp:\n  peers:\n    - address: 1.2.3.4\n      peer_asn: 1\n      receive: false\n      send: false\n", // no-op peer
		"vpp:\n  socket: /run/vpp/api.sock\n",                                                                  // nothing to do: no peers, no detector
		"detector:\n  rules_enabled: [x]\nlog:\n  stderr:\n    level: bogus\n",                                 // bad log level
		"detector:\n  rules_enabled: [x]\nlog:\n  stderr:\n    format: bogus\n",                                // bad log format
		"detector:\n  rules_enabled: [x]\nlog:\n  stderr:\n    scope: [nonsense]\n",                            // unknown scope
		"detector:\n  rules_enabled: [x]\nlog:\n  telegram:\n    chat_id: c\n",                                 // telegram missing bot_token
		"detector:\n  rules_enabled: [x]\nlog:\n  telegram:\n    bot_token: t\n",                               // telegram missing chat_id
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c)); err == nil {
			t.Errorf("expected error for config:\n%s", c)
		}
	}
}

// The log block resolves into a logging.Options with stderr defaults and an
// optional telegram sink.
func TestParse_LogSinks(t *testing.T) {
	cfg, err := Parse([]byte(`
detector:
  rules_enabled: [udp-flood-ipv4]
log:
  stderr:
    level: warn
    scope: [detector, acl]
    format: json
  telegram:
    bot_token: "123:ABC"
    chat_id: "-100"
    level: info
    scope: detector
    format: text
`))
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.Log.Options()
	if o.Stderr.Level != slog.LevelWarn || o.Stderr.All || o.Stderr.Format != "json" {
		t.Errorf("stderr spec = %+v", o.Stderr)
	}
	if len(o.Stderr.Scopes) != 2 {
		t.Errorf("stderr scopes = %v", o.Stderr.Scopes)
	}
	if o.Telegram == nil {
		t.Fatal("telegram sink should be present")
	}
	if o.Telegram.BotToken != "123:ABC" || o.Telegram.ChatID != "-100" {
		t.Errorf("telegram creds = %+v", o.Telegram)
	}
	if o.Telegram.Level != slog.LevelInfo || o.Telegram.All {
		t.Errorf("telegram spec = %+v", o.Telegram.SinkSpec)
	}
	if len(o.Telegram.Scopes) != 1 || o.Telegram.Scopes[0] != "detector" {
		t.Errorf("telegram scopes = %v", o.Telegram.Scopes)
	}
}

// Omitting the log block yields the default stderr sink (info/all/text), no telegram.
func TestParse_LogDefault(t *testing.T) {
	cfg, err := Parse([]byte("detector:\n  rules_enabled: [x]\n"))
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.Log.Options()
	if o.Stderr.Level != slog.LevelInfo || !o.Stderr.All || o.Stderr.Format != "text" {
		t.Errorf("default stderr = %+v", o.Stderr)
	}
	if o.Telegram != nil {
		t.Error("telegram should be nil by default")
	}
}

// scope: none disables a sink (not "all", empty scope set).
func TestParse_LogScopeNone(t *testing.T) {
	cfg, err := Parse([]byte("detector:\n  rules_enabled: [x]\nlog:\n  stderr:\n    scope: none\n"))
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.Log.Options()
	if o.Stderr.All || len(o.Stderr.Scopes) != 0 {
		t.Errorf("scope none => all=%v scopes=%v, want all=false empty", o.Stderr.All, o.Stderr.Scopes)
	}
}

// persist defaults to persist.dump next to the config file, and an explicit value
// is honored verbatim.
func TestLoad_PersistDefault(t *testing.T) {
	dir := t.TempDir()
	body := "detector:\n  rules_enabled: [udp-flood-ipv4]\n"

	def := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(def, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "persist.dump"); cfg.Persist != want {
		t.Errorf("default persist = %q, want %q", cfg.Persist, want)
	}

	explicit := filepath.Join(dir, "explicit.yaml")
	if err := os.WriteFile(explicit, []byte(body+"persist: /var/lib/agent/state.dump\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Persist != "/var/lib/agent/state.dump" {
		t.Errorf("explicit persist = %q", cfg.Persist)
	}
}
