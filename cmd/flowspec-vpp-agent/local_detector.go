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
	builtinrules "github.com/kawaiinetworks/flowspec-vpp-agent/rules"
)

// compileLocalRules gathers rule definitions from the embedded predefined set and
// the optional runtime directory (user rules override built-ins by name), then
// compiles only the rules named in rules_enabled.
func compileLocalRules(cfg config.Local) ([]*detector.Rule, error) {
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

	selected := make([]detector.RuleConfig, 0, len(cfg.RulesEnabled))
	for _, name := range cfg.RulesEnabled {
		rc, ok := defs[name]
		if !ok {
			return nil, fmt.Errorf("local_detector.rules_enabled: rule %q not found in built-in set or rules_dir", name)
		}
		selected = append(selected, rc)
	}
	rules, err := detector.CompileRules(selected)
	if err != nil {
		return nil, fmt.Errorf("compile local detector rules: %w", err)
	}
	return rules, nil
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
		return nil, fmt.Errorf("read local_detector.rules_dir %q: %w", dir, err)
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

func logLocalDetectorConfig(logger *slog.Logger, cfg config.Local, rules int) {
	logger.Info("local detector enabled",
		"rules", rules,
		"rules_enabled", cfg.RulesEnabled,
		"rules_dir", cfg.RulesDir,
		"dry_run", cfg.DryRun,
		"sflow_listen", cfg.SFlow.Listen,
		"sample_queue", cfg.SampleQueue,
		"event_queue", cfg.EventQueue,
		"vpp_stats", cfg.VPPStats.Enabled,
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
