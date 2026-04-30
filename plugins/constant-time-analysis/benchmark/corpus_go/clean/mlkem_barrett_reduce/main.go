// Source: Barrett reduction as used in CIRCL pke/kyber/internal/common.
// Replaces `x % q` with a multiply-by-magic so the divide instruction
// never appears in the disassembly, even though semantically a modular
// reduction is performed.
package main

import "fmt"

const Q = 3329 // ML-KEM modulus (public)

// barrettReduce is the constant-time replacement for `x % Q`. Uses
// the precomputed magic 20159 = ceil(2^26 / Q).
func barrettReduce(x int16) int16 {
	return x - int16((int32(x)*20159)>>26)*Q
}

// montgomeryReduce: Montgomery form reduction. ARX-only.
func montgomeryReduce(x int32) int16 {
	const qInv = 62209
	t := int16(x * qInv)
	return int16((x - int32(t)*Q) >> 16)
}

func main() {
	for _, v := range []int16{0, 1, 100, Q - 1, Q, Q + 1, 4096, -100} {
		fmt.Println(barrettReduce(v))
	}
	for _, v := range []int32{0, 1, 1 << 16, 100} {
		fmt.Println(montgomeryReduce(v))
	}
}
