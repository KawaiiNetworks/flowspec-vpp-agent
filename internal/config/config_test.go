package config

import "testing"

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
	if cfg.Interfaces.Mode != "all" || cfg.Interfaces.Direction != "ingress" {
		t.Errorf("interface defaults = %+v", cfg.Interfaces)
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

func TestParse_LocalDetector(t *testing.T) {
	cfg, err := Parse([]byte(`
bgp:
  router_id: 192.0.2.1
local_detector:
  enabled: true
  rules_dir: /etc/flowspec-vpp-agent/rules
  rules_enabled:
    - udp-small-flood
    - ssh-scan
  sflow:
    listen: "127.0.0.1:6343"
  sample_queue: 1024
  event_queue: 64
  vpp_stats:
    enabled: true
    interval: 2s
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Local.Enabled {
		t.Fatal("local detector disabled")
	}
	if cfg.Local.VPPStats.Interval.Duration().String() != "2s" {
		t.Fatalf("stats interval = %s, want 2s", cfg.Local.VPPStats.Interval.Duration())
	}
	if len(cfg.Local.RulesEnabled) != 2 || cfg.Local.RulesEnabled[0] != "udp-small-flood" {
		t.Fatalf("rules_enabled = %v", cfg.Local.RulesEnabled)
	}
	if cfg.Local.RulesDir != "/etc/flowspec-vpp-agent/rules" {
		t.Fatalf("rules_dir = %q", cfg.Local.RulesDir)
	}
}

func TestParse_IPv6Listen(t *testing.T) {
	cfg, err := Parse([]byte(`
bgp:
  listen: "[2001:db8::1]:10179"
  router_id: 192.0.2.1
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
		"local_detector:\n  enabled: true\n", // missing rules_enabled
		"local_detector:\n  enabled: true\n  rules_enabled: [x]\n  sflow:\n    listen: bad\n",
		"local_detector:\n  enabled: true\n  rules_enabled: [x]\n  sample_queue: 0\n",
		"local_detector:\n  enabled: true\n  rules_enabled: [x]\n  event_queue: 0\n",
		"interfaces:\n  mode: bogus\n",
		"interfaces:\n  mode: list\n", // list mode without list
		"bgp:\n  peers:\n    - address: notanip\n      peer_asn: 1\n",
		"bgp:\n  peers:\n    - address: 1.2.3.4\n", // missing peer_asn
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c)); err == nil {
			t.Errorf("expected error for config:\n%s", c)
		}
	}
}
