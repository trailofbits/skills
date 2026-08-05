// ML-DSA-87 signing helpers (Go). Expected verdicts live in expectations.json.
package main

import "os"

// Kept out of line so each helper stays a distinct symbol in the disassembly.
// ctHighBits returns the high bits of an expanded-private-key polynomial coefficient.
//go:noinline
func ctHighBits(keyCoef int32, gamma2 int32) int32 {
	return keyCoef / (2 * gamma2)
}

// ctBlockCount returns the number of whole blocks in an encoded signature buffer.
//go:noinline
func ctBlockCount(sigLen int, blockLen int) int {
	return sigLen / blockLen
}

// ctTagMatches compares a received authentication tag against the computed one.
//go:noinline
func ctTagMatches(receivedTag []byte, computedTag []byte) bool {
	for i := range receivedTag {
		if receivedTag[i] != computedTag[i] {
			return false
		}
	}
	return true
}

// ctLengthIsValid rejects signatures whose encoded length is not a whole number of blocks.
//go:noinline
func ctLengthIsValid(sigLen int, blockLen int) bool {
	if blockLen == 0 {
		return false
	}
	return sigLen%blockLen == 0
}

// Inputs come from argv so the compiler cannot constant-fold the arithmetic away.
func main() {
	n := int32(len(os.Args))
	tag := []byte(os.Args[0])
	println(ctHighBits(n, n+1))
	println(ctBlockCount(len(os.Args), len(os.Args)+1))
	println(ctTagMatches(tag, tag))
	println(ctLengthIsValid(len(tag), len(os.Args)))
}
