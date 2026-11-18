package lexer

import (
	"fmt"
	"math/bits"
)

// dynamically format integers
func fmtInt32(un uint32) string {
	n := int32(un)
	if n < 0 {
		return fmt.Sprintf("%d", n)
	} else {
		return fmt.Sprintf("%#x", n)
	}
}

func fmtInt64(un uint64) string {
	nBits := bits.Len64(un)
	if nBits <= 32 {
		return fmtInt32(uint32(un))
	}
	n := int64(un)
	if n < 0 {
		return fmt.Sprintf("%d", n)
	} else {
		return fmt.Sprintf("%#x", n)
	}
}
