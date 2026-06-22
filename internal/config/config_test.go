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
