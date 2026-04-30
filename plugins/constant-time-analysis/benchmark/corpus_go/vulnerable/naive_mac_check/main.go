// Naive MAC comparison via bytes.Equal. Despite popular belief, the Go
// stdlib does NOT promise constant time for bytes.Equal: it calls into
// `runtime.memequal` / `memequal_varlen` which has an early-exit fast
// path on mismatch. The CT-correct API is crypto/subtle.ConstantTimeCompare.
//
// Ground-truth: line 18 (bytes.Equal on secret-named MAC).
package main

import (
	"bytes"
	"fmt"
)

// authenticate verifies a tag using bytes.Equal. The "received" tag is
// attacker-controlled; the "expected" tag is computed from the secret
// MAC key. Variable-time comparison leaks the position of the first
// mismatch.
func authenticate(receivedMAC, expectedMAC []byte) bool {
	return bytes.Equal(receivedMAC, expectedMAC) // line 18: secret-named call
}

// authenticateLoop is the unrolled-loop variant; same vulnerability,
// different shape in the disassembly. Ground-truth: line 28 (early-exit).
func authenticateLoop(receivedMAC, expectedMAC []byte) bool {
	if len(receivedMAC) != len(expectedMAC) {
		return false
	}
	for i := 0; i < len(receivedMAC); i++ {
		if receivedMAC[i] != expectedMAC[i] { // line 28
			return false
		}
	}
	return true
}

func main() {
	a := []byte("expected-tag-1234")
	b := []byte("expected-tag-1234")
	fmt.Println(authenticate(a, b))
	fmt.Println(authenticateLoop(a, b))
}
