package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("duration must not be empty")
	}
	d, err := parseDurationValue(s)
	if err != nil {
		return 0, err
	}
	// All durations in this config are intervals/windows; a negative one is
	// always a configuration error and would otherwise corrupt ring math
	// (e.g. duration/resolution division).
	if d < 0 {
		return 0, fmt.Errorf("duration %q must not be negative", s)
	}
	return d, nil
}

func parseDurationValue(s string) (time.Duration, error) {
	if !strings.HasSuffix(s, "d") && !strings.HasSuffix(s, "w") {
		return time.ParseDuration(s)
	}
	mult := 24 * time.Hour
	if strings.HasSuffix(s, "w") {
		mult = 7 * 24 * time.Hour
	}
	n, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSuffix(s, "d"), "w"), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	// Guard the float->int64 conversion: out-of-range values wrap silently into
	// a garbage (often negative) Duration.
	ns := n * float64(mult)
	if ns > math.MaxInt64 || ns < math.MinInt64 {
		return 0, fmt.Errorf("duration %q out of range", s)
	}
	return time.Duration(ns), nil
}
