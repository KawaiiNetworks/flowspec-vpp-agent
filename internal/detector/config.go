package detector

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Config is the YAML root for a detector rules file. Each file under the rules
// directory (built-in or user-provided) carries one or more rules.
type Config struct {
	Rules []RuleConfig `yaml:"rules"`
}

// RuleConfig is the external declaration for one detector rule.
//
//   - match     filters which packets count (ranges/sets allowed; never emitted
//     unless also producing a descriptor field). packet_len is filter-only.
//   - aggregate reduces a matched field's concrete value to a coarser
//     granularity ("/24"); listed fields plus matched emittable fields form the
//     instance descriptor (its identity).
//   - flowspec  every field defaults to the descriptor value; write a template
//     (or "all") to override. action/ttl/refresh are emission metadata.
type RuleConfig struct {
	Name        string          `yaml:"name"`
	Match       MatchConfig     `yaml:"match"`
	Aggregate   AggregateConfig `yaml:"aggregate"`
	History     HistoryConfig   `yaml:"history"`
	Trigger     TriggerConfig   `yaml:"trigger"`
	FlowSpec    FlowSpecConfig  `yaml:"flowspec"`
	Description string          `yaml:"description"`
}

// MatchConfig is the packet filter. All fields are optional; an absent field
// imposes no constraint (and contributes no descriptor field).
type MatchConfig struct {
	Family    string      `yaml:"family"`
	Proto     StringList  `yaml:"proto"`
	Src       string      `yaml:"src"`
	Dst       string      `yaml:"dst"`
	SrcPort   IntList     `yaml:"src_port"`
	DstPort   IntList     `yaml:"dst_port"`
	PacketLen CompareUint `yaml:"packet_len"`
}

// AggregateConfig declares per-field granularity applied to the matched packet's
// concrete value. An omitted field passes through at full granularity (host
// /32-or-/128, exact port, exact protocol). Forms:
//
//	proto:    "exact" (default) | "all"
//	src/dst:  "/N" prefix bits ("/32"|"/128" = host, "/0" = all)
//	*_port:   "exact" (default) | "all" | "LO-HI" (fixed range) | "N" (bucket step)
//
// family is always the concrete family and cannot be aggregated.
type AggregateConfig struct {
	Proto   string `yaml:"proto"`
	Src     string `yaml:"src"`
	Dst     string `yaml:"dst"`
	SrcPort string `yaml:"src_port"`
	DstPort string `yaml:"dst_port"`
}

// CompareUint is a filter-only numeric comparison (used by packet_len).
type CompareUint struct {
	LT  uint64 `yaml:"lt"`
	LTE uint64 `yaml:"lte"`
	GT  uint64 `yaml:"gt"`
	GTE uint64 `yaml:"gte"`
}

func (c CompareUint) empty() bool {
	return c.LT == 0 && c.LTE == 0 && c.GT == 0 && c.GTE == 0
}

type HistoryConfig struct {
	Fine         RingConfig `yaml:"fine"`
	Medium       RingConfig `yaml:"medium"`
	Coarse       RingConfig `yaml:"coarse"`
	MaxInstances int        `yaml:"max_instances"`
}

type RingConfig struct {
	Resolution Duration `yaml:"resolution"`
	Duration   Duration `yaml:"duration"`
}

// TriggerConfig is the expression-based trigger. terms are named windowed
// aggregates; expr is a boolean expression over them; sustained debounces.
type TriggerConfig struct {
	Terms     map[string]TermConfig `yaml:"terms"`
	Expr      string                `yaml:"expr"`
	Sustained Duration              `yaml:"sustained"`
}

type TermConfig struct {
	Metric string   `yaml:"metric"`
	Window Duration `yaml:"window"`
	Offset Duration `yaml:"offset"`
	Agg    string   `yaml:"agg"`
}

// FlowSpecConfig is the synthetic FlowSpec emission. Match fields are flat
// templates; an empty field falls back to the descriptor value (or wildcard).
type FlowSpecConfig struct {
	Action    string   `yaml:"action"`
	TTL       Duration `yaml:"ttl"`
	Refresh   *bool    `yaml:"refresh"`
	Family    string   `yaml:"family"`
	Proto     string   `yaml:"proto"`
	SrcPrefix string   `yaml:"src_prefix"`
	DstPrefix string   `yaml:"dst_prefix"`
	SrcPort   string   `yaml:"src_port"`
	DstPort   string   `yaml:"dst_port"`
}

// StringList accepts either a scalar string or a sequence of strings in YAML.
type StringList []string

func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	var one string
	if err := value.Decode(&one); err == nil {
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := value.Decode(&many); err != nil {
		return fmt.Errorf("expected string or list of strings")
	}
	*s = StringList(many)
	return nil
}

// IntList accepts either a scalar integer or a sequence of integers in YAML.
type IntList []int

func (l *IntList) UnmarshalYAML(value *yaml.Node) error {
	var one int
	if err := value.Decode(&one); err == nil {
		*l = IntList{one}
		return nil
	}
	var many []int
	if err := value.Decode(&many); err != nil {
		return fmt.Errorf("expected integer or list of integers")
	}
	*l = IntList(many)
	return nil
}

// LoadConfig parses a detector rules file without compiling it.
func LoadConfig(data []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse detector config: %w", err)
	}
	return cfg, nil
}

// CompileConfig parses and compiles every rule in a detector rules file.
func CompileConfig(data []byte) ([]*Rule, error) {
	cfg, err := LoadConfig(data)
	if err != nil {
		return nil, err
	}
	return CompileRules(cfg.Rules)
}

// CompileRules compiles rule configs into fixed-capacity runtime rules.
func CompileRules(cfgs []RuleConfig) ([]*Rule, error) {
	rules := make([]*Rule, 0, len(cfgs))
	for i, cfg := range cfgs {
		r, err := compileRule(cfg)
		if err != nil {
			return nil, fmt.Errorf("rules[%d] %q: %w", i, cfg.Name, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}
