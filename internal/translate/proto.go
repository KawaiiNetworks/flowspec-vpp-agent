package translate

import (
	"fmt"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// IANA protocol numbers used by this version (§4).
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoGRE    = 47
	protoESP    = 50
	protoICMPv6 = 58
)

// reduceProto reduces the FlowSpec protocol / next-header operator list to a
// single exact IANA protocol number (§4). Only "= v" is supported; inequalities,
// ranges and OR of multiple protocols are rejected as unsupported expressions.
//
// Returns (proto, present, err). present=false means the component is absent
// ("proto missing -> any").
func reduceProto(ops []flowspec.NumericOp) (proto uint8, present bool, err error) {
	if len(ops) == 0 {
		return 0, false, nil
	}
	if len(ops) != 1 {
		return 0, false, unsupported(ReasonUnsupportedExpression,
			"protocol: only a single exact match is supported")
	}
	op := ops[0]
	if !op.EQ || op.LT || op.GT {
		return 0, false, unsupported(ReasonUnsupportedExpression,
			"protocol: only equality (proto = N) is supported")
	}
	if op.Value > 255 {
		return 0, false, unsupported(ReasonUnsupportedExpression,
			fmt.Sprintf("protocol: value %d out of range", op.Value))
	}
	return uint8(op.Value), true, nil
}
