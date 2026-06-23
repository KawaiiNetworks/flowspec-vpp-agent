package main

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/config"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vppstats"
	builtinrules "github.com/kawaiinetworks/flowspec-vpp-agent/rules"
)

// compileDetectorRules gathers rule definitions from the embedded predefined set
// and the optional runtime directory (user rules override built-ins by name),
// then compiles only the rules named in rules_enabled.
func compileDetectorRules(cfg *config.Detector) ([]*detector.Rule, error) {
	defs := map[string]detector.RuleConfig{}

	builtin, err := loadEmbeddedRules()
	if err != nil {
		return nil, err
	}
	for name, rc := range builtin {
		defs[name] = rc
	}
	if cfg.RulesDir != "" {
		user, err := loadDirRules(cfg.RulesDir)
		if err != nil {
			return nil, err
		}
		for name, rc := range user {
			defs[name] = rc // user rules override built-ins of the same name
		}
	}

	// Effective enabled set: the built-ins (unless builtin_rules is false) merged
	// with everything named in rules_enabled. A user rule from rules_dir takes
	// effect by being listed in rules_enabled; with builtin_rules off, rules_enabled
	// is also how you pick a subset of built-ins.
	enabled := map[string]bool{}
	if cfg.BuiltinRulesEnabled() {
		for name := range builtin {
			enabled[name] = true
		}
	}
	for _, name := range cfg.RulesEnabled {
		if _, ok := defs[name]; !ok {
			return nil, fmt.Errorf("detector.rules_enabled: rule %q not found in built-in set or rules_dir", name)
		}
		enabled[name] = true
	}
	if len(enabled) == 0 {
		return nil, fmt.Errorf("detector: no rules enabled (builtin_rules is false and rules_enabled is empty)")
	}
	names := make([]string, 0, len(enabled))
	for name := range enabled {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic compile + log order
	selected := make([]detector.RuleConfig, 0, len(names))
	for _, name := range names {
		selected = append(selected, defs[name])
	}
	rules, err := detector.CompileRules(selected)
	if err != nil {
		return nil, fmt.Errorf("compile detector rules: %w", err)
	}
	// A rule that reads vpp.* metrics is meaningless without the stats poller:
	// those terms would silently read 0 and the rule would never fire. Reject the
	// config rather than mislead the operator.
	if !cfg.VPPStatsEnabled() {
		var offenders []string
		for _, r := range rules {
			if r.UsesVPPStats() {
				offenders = append(offenders, r.Name())
			}
		}
		if len(offenders) > 0 {
			return nil, fmt.Errorf("detector.vpp_stats is not configured but these rules use vpp.* metrics: %s", strings.Join(offenders, ", "))
		}
		return rules, nil
	}
	// vpp.* windowed terms must be covered by the configured rings, else they
	// would silently read 0. Validate up front against the effective ring sizing.
	ringCfg := vppRingConfig(cfg.VPPStats)
	for _, r := range rules {
		for _, w := range r.StatsWindows() {
			if !ringCfg.Covers(w.Window, w.Offset) {
				return nil, fmt.Errorf("rule %q: vpp window %s offset %s is not covered by the vpp_stats rings (adjust window/offset or vpp_stats.fine/medium/coarse)", r.Name(), w.Window, w.Offset)
			}
		}
	}
	return rules, nil
}

// vppRingConfig maps the YAML vpp_stats ring sizing to the vppstats ring config.
// Unset dimensions are filled with defaults by vppstats.
func vppRingConfig(v *config.VPPStats) vppstats.RingConfig {
	return vppstats.RingConfig{
		FineResolution:   v.Fine.Resolution.Duration(),
		FineDuration:     v.Fine.Duration.Duration(),
		MediumResolution: v.Medium.Resolution.Duration(),
		MediumDuration:   v.Medium.Duration.Duration(),
		CoarseResolution: v.Coarse.Resolution.Duration(),
		CoarseDuration:   v.Coarse.Duration.Duration(),
	}
}

func loadEmbeddedRules() (map[string]detector.RuleConfig, error) {
	out := map[string]detector.RuleConfig{}
	entries, err := fs.ReadDir(builtinrules.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded rules: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := builtinrules.FS.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded rule %s: %w", e.Name(), err)
		}
		if err := mergeRules(out, data, "builtin:"+e.Name()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func loadDirRules(dir string) (map[string]detector.RuleConfig, error) {
	out := map[string]detector.RuleConfig{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read detector.rules_dir %q: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read rule file %s: %w", name, err)
		}
		if err := mergeRules(out, data, name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func mergeRules(dst map[string]detector.RuleConfig, data []byte, source string) error {
	cfg, err := detector.LoadConfig(data)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	for _, rc := range cfg.Rules {
		if rc.Name == "" {
			return fmt.Errorf("%s: a rule is missing its name", source)
		}
		if _, dup := dst[rc.Name]; dup {
			return fmt.Errorf("%s: duplicate rule name %q", source, rc.Name)
		}
		dst[rc.Name] = rc
	}
	return nil
}

func logDetectorConfig(logger *slog.Logger, cfg *config.Detector, rules int) {
	logger.Info("detector enabled",
		"rules", rules,
		"builtin_rules", cfg.BuiltinRulesEnabled(),
		"rules_enabled", cfg.RulesEnabled,
		"rules_dir", cfg.RulesDir,
		"dry_run", cfg.DryRun,
		"sflow_listen", cfg.SFlow.Listen,
		"sample_queue", cfg.SampleQueue,
		"event_queue", cfg.EventQueue,
		"vpp_stats", cfg.VPPStatsEnabled(),
	)
}

// humanBytes renders a byte count as a compact human-readable string.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
