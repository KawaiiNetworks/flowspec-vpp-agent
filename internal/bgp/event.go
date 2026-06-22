// Package bgp is the FlowSpec source layer. It embeds a GoBGP speaker, accepts
// FlowSpec from multiple peers (each peer = one session), and emits a stream of
// source-agnostic Update events. Nothing downstream knows it is GoBGP; swapping
// the BGP integration means reimplementing only this package.
package bgp

import "github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"

// Op is the kind of change carried by an Update.
type Op uint8

const (
	// OpAnnounce: the session advertises (or re-advertises) a FlowSpec rule.
	OpAnnounce Op = iota
	// OpWithdraw: the session withdraws a previously advertised rule.
	OpWithdraw
	// OpSessionDown: the session went down / reset; treated as withdrawing all of
	// that session's rules (§17). Rule is nil for this op.
	OpSessionDown
	// OpResync: re-push all desired ACL state to VPP. Enqueued after a VPP
	// reconnect (§19.3) so the manager reconciles every family onto the freshly
	// re-created Managed ACLs. Session/Rule are unused.
	OpResync
)

func (o Op) String() string {
	switch o {
	case OpAnnounce:
		return "announce"
	case OpWithdraw:
		return "withdraw"
	case OpSessionDown:
		return "session_down"
	case OpResync:
		return "resync"
	default:
		return "unknown"
	}
}

// SessionID identifies a FlowSpec session (BGP peer). The manager reference-counts
// rule ownership per SessionID (§17).
type SessionID string

// Update is one change from one session. For OpAnnounce/OpWithdraw, Rule is the
// parsed FlowSpec rule (parse failures upstream become a dropped update, never a
// malformed Rule). For OpSessionDown, Rule is nil.
type Update struct {
	Session SessionID
	Op      Op
	Rule    *flowspec.Rule
	// Peer is the human-readable peer address, used as a metric/log dimension.
	Peer string
}
