// Source: Go stdlib crypto/subtle.ConstantTimeCompare (verbatim algorithm).
// Constant-time byte-array compare. Loop bound is len(x), the *length*
// (public). The accumulator XOR-OR has no early exit. Final fold via
// (x-1)>>31 is bit-twiddling.
//
// Ground truth: zero violations. The two branches we expect the
// unfiltered analyzer to flag are:
//   line 30: `if len(x) != len(y)` -- length check, public
//   line 35: `for i := 0; i < len(x); i++` -- loop counter, public
// Both must be silenced by `non-secret` (no secret-named param) and/or
// the `aggregate` filter, leaving zero ERRORs and zero WARNINGs.
package main

import (
	"fmt"
	"os"
)

// ConstantTimeCompare returns 1 iff x == y, in time independent of the
// content of x and y. The two slices must have equal length, otherwise
// it returns 0 immediately on the public-length mismatch (still CT
// because the length itself is public).
func ConstantTimeCompare(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}
	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}
	return ConstantTimeByteEq(v, 0)
}

// ConstantTimeByteEq returns 1 if x == y, 0 otherwise.
func ConstantTimeByteEq(x, y uint8) int {
	return int((uint32(x^y) - 1) >> 31)
}

func main() {
	a := []byte("hello world!")
	b := []byte("hello world!")
	if ConstantTimeCompare(a, b) != 1 {
		fmt.Fprintln(os.Stderr, "fail")
		os.Exit(1)
	}
}
