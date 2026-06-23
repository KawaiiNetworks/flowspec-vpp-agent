// Package builtinrules embeds the agent's predefined detector rule files.
// Every *.yaml in this directory is compiled into the binary and made available
// by name; an operator enables specific rules via detector.rules_enabled
// and may override or add rules at runtime through detector.rules_dir.
package builtinrules

import "embed"

// FS holds the embedded predefined rule files (one or more rules per file).
//
//go:embed *.yaml
var FS embed.FS
