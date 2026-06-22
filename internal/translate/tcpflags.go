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
// v1 supports only predicates that are exactly reducible to required-set and
// required-clear bits. OR alternation across terms (e.g. "match syn OR ack") is
// rejected as unsupported, since it cannot be expressed as a single value/mask
// without widening the match.
//
// Returns (value, mask, present, err). present=false means no tcp-flags component.
func reduceTCPFlags(ops []flowspec.BitmaskOp) (value, mask uint8, present bool, err error) {
	if len(ops) == 0 {
		return 0, 0, false, nil
	}
	var setBits, clearBits uint8
	for i, op := range ops {
		// A second-or-later item that does not AND with the previous one starts a
		// new OR term — not expressible as a single value/mask.
		if i > 0 && !op.And {
			return 0, 0, false, unsupported(ReasonUnsupportedExpression,
				"tcp-flags: OR alternation is not supported")
		}
		if op.Value > 0xff {
			return 0, 0, false, unsupported(ReasonUnsupportedExpression,
				"tcp-flags: flag bits outside the TCP header flags byte")
		}
		bits := uint8(op.Value)
		if bits == 0 {
			return 0, 0, false, unsupported(ReasonUnsupportedExpression,
				"tcp-flags: empty flag set")
		}

		oneBit := bits&(bits-1) == 0
		switch {
		case op.Match && !op.Not:
			// (flags & bits) == bits: all listed bits set.
			setBits |= bits
		case op.Match && op.Not:
			// NOT((flags & bits) == bits): expressible only for one bit.
			if !oneBit {
				return 0, 0, false, unsupported(ReasonUnsupportedExpression,
					"tcp-flags: multi-bit not-all-set is not supported")
			}
			clearBits |= bits
		case !op.Match && !op.Not:
			// (flags & bits) != 0: expressible only for one bit.
			if !oneBit {
				return 0, 0, false, unsupported(ReasonUnsupportedExpression,
					"tcp-flags: multi-bit match-any is not supported")
			}
			setBits |= bits
		case !op.Match && op.Not:
			// NOT((flags & bits) != 0): none of the listed bits set.
			clearBits |= bits
		}

		if setBits&clearBits != 0 {
			return 0, 0, false, unsupported(ReasonUnsupportedExpression,
				"tcp-flags: expression matches no value")
		}
	}
	value = setBits
	mask = setBits | clearBits
	return value, mask, true, nil
}
