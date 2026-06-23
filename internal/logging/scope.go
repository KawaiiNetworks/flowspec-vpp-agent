// Package logging builds the agent's logger from configuration. It supports
// multiple sinks (stderr plus an optional Telegram sink), each filtered by both
// level and a "scope" — a coarse category tag attached to every log record so a
// sink can subscribe to, say, only detector events and ACL changes.
//
// Scopes are assigned once per subsystem at its construction site (the cmd layer
// does logger.With(KeyScope, ScopeACL) etc.); subsystems themselves are unaware of
// scopes. This package is a leaf: it imports only the standard library.
package logging

// KeyScope is the slog attribute key carrying a record's scope.
const KeyScope = "scope"

// Scope values. Each log record belongs to exactly one scope, set by the
// subsystem that emits it. A record with no scope attribute is treated as
// ScopeCore.
const (
	ScopeCore     = "core"     // startup/shutdown, HTTP endpoint, config echo
	ScopeBGP      = "bgp"      // BGP speaker and per-peer sessions
	ScopeACL      = "acl"      // FlowSpec rule apply/withdraw/update
	ScopeVPP      = "vpp"      // VPP connect/reconnect, ACL attach/cleanup
	ScopeDetector = "detector" // detector events, sFlow, vpp-stats, leases
)

// AllScopes lists every defined scope. Order is stable for documentation.
var AllScopes = []string{ScopeCore, ScopeBGP, ScopeACL, ScopeVPP, ScopeDetector}

// Valid reports whether s is a defined scope name.
func Valid(s string) bool {
	for _, v := range AllScopes {
		if s == v {
			return true
		}
	}
	return false
}
