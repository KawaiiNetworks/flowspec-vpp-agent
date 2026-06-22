package translate

import (
	"fmt"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// reduceExact reduces an ICMP type or code operator list to a single exact value
// (§8). Ranges, "!=" and complex numeric expressions are rejected. Returns
// (value, present, err); present=false means the component is absent.
func reduceExact(ops []flowspec.NumericOp, what string) (val uint8, present bool, err error) {
	if len(ops) == 0 {
		return 0, false, nil
	}
	if len(ops) != 1 {
		return 0, false, unsupported(ReasonUnsupportedExpression,
			what+": only a single exact match is supported")
	}
	op := ops[0]
	if !op.EQ || op.LT || op.GT {
		return 0, false, unsupported(ReasonUnsupportedExpression,
			what+": only equality is supported")
	}
	if op.Value > 255 {
		return 0, false, unsupported(ReasonUnsupportedExpression,
			fmt.Sprintf("%s: value %d out of range", what, op.Value))
	}
	return uint8(op.Value), true, nil
}
