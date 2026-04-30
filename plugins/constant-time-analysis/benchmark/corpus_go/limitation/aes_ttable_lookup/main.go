// AES T-table cache-timing leak. Indexes into the public Te0 table by
// secret state bytes (state[i] ^ keyBytes[i]). The instruction-level
// analyzer cannot see this: there is no DIV, no JCC on a secret bit;
// the leak is via cache lines touched, observable from a co-located
// attacker (Bernstein 2005).
//
// This file is the limitation case that documents the analyzer's
// blind spot: instruction-level CT does not capture cache-timing.
package main

import "fmt"

// Te0 stub (the real table is 256 uint32 entries derived from the
// AES S-box and MixColumns).
var Te0 = [256]uint32{}

func aesEncryptRound(state [16]byte, roundKey [16]byte) [16]byte {
	var out [16]byte
	for i := 0; i < 16; i++ {
		idx := state[i] ^ roundKey[i] // SECRET index
		t := Te0[idx]                  // SECRET-INDEXED LOOKUP -- cache leak
		out[i] = byte(t)
	}
	return out
}

func main() {
	for i := range Te0 {
		Te0[i] = uint32(i*0x9e3779b1) ^ 0xdeadbeef
	}
	var st, rk [16]byte
	for i := range rk {
		rk[i] = byte(i)
	}
	fmt.Printf("%x\n", aesEncryptRound(st, rk))
}
