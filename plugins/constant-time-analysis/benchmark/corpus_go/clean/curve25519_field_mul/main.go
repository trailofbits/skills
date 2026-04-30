// Source: Curve25519 field-element multiply, simplified from
// golang.org/x/crypto/curve25519/internal/field. Each iteration
// multiplies and reduces in 64-bit arithmetic with no branches.
package main

import "fmt"

// FieldElement is the 5x51-bit packed representation. Real field
// multiplication is more involved; this is the structural shape.
type FieldElement struct {
	v0, v1, v2, v3, v4 uint64
}

// FeMul multiplies two field elements modulo 2^255 - 19. No
// data-dependent control flow: every uint64 multiply, every shift,
// every and-mask is constant-time. The carry-chain at the end uses
// only multiply-shift-mask.
func FeMul(out *FieldElement, x, y *FieldElement) {
	const mask = (1 << 51) - 1
	r0 := x.v0 * y.v0
	r1 := x.v0*y.v1 + x.v1*y.v0
	r2 := x.v0*y.v2 + x.v1*y.v1 + x.v2*y.v0
	r3 := x.v0*y.v3 + x.v1*y.v2 + x.v2*y.v1 + x.v3*y.v0
	r4 := x.v0*y.v4 + x.v1*y.v3 + x.v2*y.v2 + x.v3*y.v1 + x.v4*y.v0
	// Carry-chain (constant-time via mask + shift)
	c0 := r0 >> 51
	r0 &= mask
	r1 += c0
	c1 := r1 >> 51
	r1 &= mask
	r2 += c1
	c2 := r2 >> 51
	r2 &= mask
	r3 += c2
	c3 := r3 >> 51
	r3 &= mask
	r4 += c3
	c4 := r4 >> 51
	r4 &= mask
	r0 += c4 * 19
	out.v0, out.v1, out.v2, out.v3, out.v4 = r0, r1, r2, r3, r4
}

// FeCSwap is the constant-time conditional swap used in the X25519
// ladder. The mask is 0 or 0xFF...F based on b; both halves of the
// swap always execute.
func FeCSwap(a, b *FieldElement, swap uint64) {
	mask := -swap
	t := mask & (a.v0 ^ b.v0)
	a.v0, b.v0 = a.v0^t, b.v0^t
	t = mask & (a.v1 ^ b.v1)
	a.v1, b.v1 = a.v1^t, b.v1^t
	t = mask & (a.v2 ^ b.v2)
	a.v2, b.v2 = a.v2^t, b.v2^t
	t = mask & (a.v3 ^ b.v3)
	a.v3, b.v3 = a.v3^t, b.v3^t
	t = mask & (a.v4 ^ b.v4)
	a.v4, b.v4 = a.v4^t, b.v4^t
}

func main() {
	var a, b, c FieldElement
	a.v0, b.v0 = 1, 2
	FeMul(&c, &a, &b)
	FeCSwap(&a, &b, 1)
	fmt.Println(c.v0)
}
