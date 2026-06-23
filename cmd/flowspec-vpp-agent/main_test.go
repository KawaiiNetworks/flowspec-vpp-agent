package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/config"
)

func TestRunHealthcheck_MetricsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`metrics:
  listen: ""
bgp:
  router_id: 192.0.2.1
  peers:
    - address: 198.51.100.1
      peer_asn: 65001
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runHealthcheck([]string{"--config", path}); code != 0 {
		t.Fatalf("healthcheck with disabled metrics = %d, want 0", code)
	}
}

func TestRunHealthcheck_ConfigError(t *testing.T) {
	if code := runHealthcheck([]string{"--config", "/no/such/config.yaml"}); code == 0 {
		t.Fatal("healthcheck with missing config succeeded, want failure")
	}
}

func TestSplitListen_IPv6(t *testing.T) {
	host, port := splitListen("[2001:db8::1]:10179")
	if host != "2001:db8::1" || port != 10179 {
		t.Fatalf("splitListen IPv6 = %q/%d, want 2001:db8::1/10179", host, port)
	}
}

func boolp(b bool) *bool { return &b }

func TestCompileLocalRulesBuiltin(t *testing.T) {
	rules, err := compileDetectorRules(&config.Detector{BuiltinRules: boolp(false), RulesEnabled: []string{"udp-flood-ipv4"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name() != "udp-flood-ipv4" {
		t.Fatalf("rules = %+v", rules)
	}
}

// builtin_rules defaults to true: omitting it (and rules_enabled) enables all
// built-ins; rules_enabled merges extra (rules_dir) rules on top.
func TestCompileDetectorRules_BuiltinToggle(t *testing.T) {
	builtin, err := loadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	nBuiltin := len(builtin)
	if nBuiltin == 0 {
		t.Fatal("no embedded rules")
	}

	// Default (builtin_rules omitted => true), empty rules_enabled => all built-ins.
	rules, err := compileDetectorRules(&config.Detector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != nBuiltin {
		t.Fatalf("default: got %d rules, want all %d built-ins", len(rules), nBuiltin)
	}

	// builtin_rules: true (default) + a user rule from rules_dir => built-ins + 1.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "u.yaml"), []byte(`
rules:
  - name: user-extra
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history: { fine: { resolution: 1s, duration: 10s }, max_instances: 2 }
    trigger:
      terms: { short: { metric: pps, window: 1s } }
      expr: "short > 1"
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{src}}" }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err = compileDetectorRules(&config.Detector{RulesDir: dir, RulesEnabled: []string{"user-extra"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != nBuiltin+1 {
		t.Fatalf("merge: got %d rules, want %d (built-ins + user-extra)", len(rules), nBuiltin+1)
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
	rules, err := compileDetectorRules(&config.Detector{RulesEnabled: names})
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
	rules, err := compileDetectorRules(&config.Detector{BuiltinRules: boolp(false), RulesDir: dir, RulesEnabled: []string{"file-rule"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name() != "file-rule" {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestCompileLocalRulesUnknown(t *testing.T) {
	if _, err := compileDetectorRules(&config.Detector{RulesEnabled: []string{"does-not-exist"}}); err == nil {
		t.Fatal("expected error for unknown rule name")
	}
}

// A rule that reads vpp.packet_iface.* must be rejected when vpp_stats is disabled,
// and accepted when it is enabled.
func TestCompileDetectorRules_VPPStatsGate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(`
rules:
  - name: vpp-rule
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
        rx: { metric: vpp.packet_iface.rx_pps }
      expr: "rx > 1000000"
    flowspec:
      action: drop
      ttl: 10s
      src_prefix: "{{src}}"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Disabled stats -> error naming the offending rule.
	_, err := compileDetectorRules(&config.Detector{BuiltinRules: boolp(false), RulesDir: dir, RulesEnabled: []string{"vpp-rule"}})
	if err == nil {
		t.Fatal("expected error: vpp.* metric with vpp_stats disabled")
	}
	if !strings.Contains(err.Error(), "vpp-rule") {
		t.Fatalf("error should name the rule, got: %v", err)
	}

	// Enabled stats -> compiles.
	rules, err := compileDetectorRules(&config.Detector{
		BuiltinRules: boolp(false), RulesDir: dir, RulesEnabled: []string{"vpp-rule"},
		VPPStats: &config.VPPStats{},
	})
	if err != nil {
		t.Fatalf("vpp-rule with stats enabled: %v", err)
	}
	if len(rules) != 1 || !rules[0].UsesVPPStats() {
		t.Fatalf("rules = %+v", rules)
	}
}

// A windowed vpp term must be covered by the configured rings.
func TestCompileDetectorRules_VPPWindowCoverage(t *testing.T) {
	dir := t.TempDir()
	write := func(window string) {
		if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(`
rules:
  - name: win-rule
    match: { family: ipv4, proto: udp }
    aggregate: { src: "/32" }
    history:
      fine: { resolution: 1s, duration: 10s }
      max_instances: 2
    trigger:
      terms:
        rx: { metric: vpp.total.rx_pps, window: `+window+` }
      expr: "rx > 1"
    flowspec: { action: drop, ttl: 10s, src_prefix: "{{src}}" }
`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// 10s is covered by the default fine ring (1s/5m).
	write("10s")
	if _, err := compileDetectorRules(&config.Detector{
		BuiltinRules: boolp(false), RulesDir: dir, RulesEnabled: []string{"win-rule"}, VPPStats: &config.VPPStats{},
	}); err != nil {
		t.Fatalf("10s window should be covered: %v", err)
	}

	// 90 days exceeds every default ring span.
	write("2160h")
	_, err := compileDetectorRules(&config.Detector{
		BuiltinRules: boolp(false), RulesDir: dir, RulesEnabled: []string{"win-rule"}, VPPStats: &config.VPPStats{},
	})
	if err == nil || !strings.Contains(err.Error(), "win-rule") {
		t.Fatalf("expected coverage error naming the rule, got: %v", err)
	}
}
