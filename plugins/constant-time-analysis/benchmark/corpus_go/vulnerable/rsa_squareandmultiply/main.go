// Naive RSA modular exponentiation via square-and-multiply. The branch
// `if exp & 1 == 1` is on a bit of the secret exponent and reveals that
// bit's value through the timing of the multiply.
//
// This is the Kocher 1996 timing attack pattern.
package main

import "fmt"

// naiveModExp computes (base ** exponent) mod m. Ground-truth:
//   line 16: branch on secret exponent bit
//   line 19, 20: integer divides (modular reduction; m at runtime)
func naiveModExp(base, exponent, m uint64) uint64 {
	result := uint64(1)
	for exponent > 0 {
		if exponent&1 == 1 { // line 16: secret-bit branch
			result = (result * base) % m // line 17: DIV on secret-derived
		}
		exponent >>= 1
		base = (base * base) % m // line 20: DIV on secret-derived
	}
	return result
}

func main() {
	fmt.Println(naiveModExp(7, 13, 19))
}
