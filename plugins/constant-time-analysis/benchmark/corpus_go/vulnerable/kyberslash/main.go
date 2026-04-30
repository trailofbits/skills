// KyberSlash analogue: variable-time integer division on a secret-derived
// coefficient. https://kyberslash.cr.yp.to/
//
// Important Go-specific subtlety: when the divisor is a *compile-time*
// constant (e.g. `secretCoef / 3329`), Go's SSA rewrites the divide into a
// multiply-by-magic, accidentally making it CT. To force a real IDIV in
// the disassembly the divisor must be a runtime value.
package main

import "fmt"

// KyberParams holds runtime-loaded KEM parameters; from the compiler's
// view both fields are unknown at compile time, so the divide can't be
// folded.
type KyberParams struct {
	Q     int32
	GAMMA int32
}

// kyberslashCompress is the textbook (vulnerable) ML-KEM compression
// formula. The divide and modulo on the secret coefficient leak the
// coefficient through DIV/IDIV timing. Ground-truth lines: 26, 27.
func kyberslashCompress(secretCoef int32, p *KyberParams) int32 {
	num := (int32(1) << 4) * secretCoef
	q := num / p.Q       // line 26: IDIV on secret
	r := num % p.Q       // line 27: IDIV on secret
	if r >= p.Q/2 {      // line 28: branch on secret-derived r
		q++
	}
	return q & 0xf
}

// kyberslashReduce: secret % runtime-Q. Ground-truth line: 38.
func kyberslashReduce(secret int32, p *KyberParams) int32 {
	return secret % p.Q
}

func main() {
	p := &KyberParams{Q: 3329, GAMMA: 95232}
	fmt.Println(kyberslashCompress(12345, p))
	fmt.Println(kyberslashReduce(98765, p))
}
