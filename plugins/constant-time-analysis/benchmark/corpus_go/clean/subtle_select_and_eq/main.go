// Source: Go stdlib crypto/subtle.ConstantTimeSelect / Eq / LessOrEq.
// Bitmask-only operations with no branches on operands.
package main

import "fmt"

// ConstantTimeSelect returns x if v == 1, y if v == 0; constant-time.
// The bit-trick is: (v-1) is all-ones if v==0, all-zeros if v==1.
func ConstantTimeSelect(v, x, y int) int {
	return ^(v-1)&x | (v-1)&y
}

// ConstantTimeEq returns 1 if x == y, 0 otherwise.
func ConstantTimeEq(x, y int32) int {
	return int((uint64(uint32(x^y)) - 1) >> 63)
}

// ConstantTimeLessOrEq returns 1 if x <= y, 0 otherwise. x and y must be
// in range [0, 2**31-1].
func ConstantTimeLessOrEq(x, y int) int {
	x32 := int32(x)
	y32 := int32(y)
	return int(((x32 - y32 - 1) >> 31) & 1)
}

func main() {
	fmt.Println(ConstantTimeSelect(1, 100, 200))
	fmt.Println(ConstantTimeEq(42, 42))
	fmt.Println(ConstantTimeLessOrEq(7, 9))
}
