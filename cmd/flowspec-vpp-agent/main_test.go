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
	rules, err := compileDetectorRules(config.Detector{RulesEnabled: []string{"udp-flood-ipv4"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name() != "udp-flood-ipv4" {
		t.Fatalf("rules = %+v", rules)
	}
}

// Every embedded rule must compile, so a broken built-in fails the build/test.
func TestAllBuiltinRulesCompile(t *testing.T) {
	defs, err := loadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) == 0 {
		t.Fatal("no embedded rules found")
	}
	names := make([]string, 0, len(defs))
	for name := range defs {
		names = append(names, name)
	}
	rules, err := compileDetectorRules(config.Detector{RulesEnabled: names})
	if err != nil {
		t.Fatalf("compiling all %d built-in rules: %v", len(names), err)
	}
	if len(rules) != len(names) {
		t.Fatalf("compiled %d rules, want %d", len(rules), len(names))
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
	rules, err := compileDetectorRules(config.Detector{RulesDir: dir, RulesEnabled: []string{"file-rule"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name() != "file-rule" {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestCompileLocalRulesUnknown(t *testing.T) {
	if _, err := compileDetectorRules(config.Detector{RulesEnabled: []string{"does-not-exist"}}); err == nil {
		t.Fatal("expected error for unknown rule name")
	}
}
