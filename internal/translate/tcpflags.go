package translate

import "github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"

// TCP flag bit positions (§7), matching the TCP header flags byte.
const (
	tcpFIN = 1 << 0
	tcpSYN = 1 << 1
	tcpRST = 1 << 2
	tcpPSH = 1 << 3
	tcpACK = 1 << 4
	tcpURG = 1 << 5
	tcpECE = 1 << 6
	tcpCWR = 1 << 7
)

// reduceTCPFlags reduces a FlowSpec tcp-flags bitmask operator list (§7) to a
// VPP (value, mask) pair where a packet matches when (flags & mask) == value.
//
// v1 supports only the simple AND-combination of "flag must be set" and
// "flag must be clear (!flag)" items, e.g. `syn`, `syn,!ack`, `rst`, `ack`.
// Each item contributes its bits to the mask; non-NOT items also set those bits
// in value (require 1), NOT items leave them 0 (require 0). Any OR alternation
// across terms (e.g. "match any of syn,ack") is rejected as unsupported, since it
// cannot be expressed as a single value/mask without widening the match.
//
// Returns (value, mask, present, err). present=false means no tcp-flags component.
func reduceTCPFlags(ops []flowspec.BitmaskOp) (value, mask uint8, present bool, err error) {
	if len(ops) == 0 {
		return 0, 0, false, nil
	}
	for i, op := range ops {
		// A second-or-later item that does not AND with the previous one starts a
		// new OR term — not expressible as a single value/mask.
		if i > 0 && !op.And {
			return 0, 0, false, unsupported(ReasonUnsupportedExpression,
				"tcp-flags: OR alternation is not supported")
		}
		bits := uint8(op.Value & 0xff)
		if bits == 0 {
			return 0, 0, false, unsupported(ReasonUnsupportedExpression,
				"tcp-flags: empty flag set")
		}
		mask |= bits
		if !op.Not {
			value |= bits
		}
	}
	return value, mask, true, nil
}
