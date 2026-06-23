package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/config"
)

func TestRunHealthcheck_MetricsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`metrics:
  listen: ""
bgp:
  router_id: 192.0.2.1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runHealthcheck([]string{"-config", path}); code != 0 {
		t.Fatalf("healthcheck with disabled metrics = %d, want 0", code)
	}
}

func TestRunHealthcheck_ConfigError(t *testing.T) {
	if code := runHealthcheck([]string{"-config", "/no/such/config.yaml"}); code == 0 {
		t.Fatal("healthcheck with missing config succeeded, want failure")
	}
}

func TestSplitListen_IPv6(t *testing.T) {
	host, port := splitListen("[2001:db8::1]:10179")
	if host != "2001:db8::1" || port != 10179 {
		t.Fatalf("splitListen IPv6 = %q/%d, want 2001:db8::1/10179", host, port)
	}
}

func TestCompileLocalRulesBuiltin(t *testing.T) {
	rules, err := compileLocalRules(config.Local{RulesEnabled: []string{"udp-small-flood"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name() != "udp-small-flood" {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestCompileLocalRulesDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(`
rules:
  - name: file-rule
    match:
      family: ipv4
      proto: udp
    aggregate:
      src: "/32"
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 2
    trigger:
      terms:
        short: { metric: pps, window: 1s }
      expr: "short > 1"
    flowspec:
      action: drop
      ttl: 10s
      src_prefix: "{{src}}"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := compileLocalRules(config.Local{RulesDir: dir, RulesEnabled: []string{"file-rule"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name() != "file-rule" {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestCompileLocalRulesUnknown(t *testing.T) {
	if _, err := compileLocalRules(config.Local{RulesEnabled: []string{"does-not-exist"}}); err == nil {
		t.Fatal("expected error for unknown rule name")
	}
}
