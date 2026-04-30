// Lucky13 analogue: padding-loop bound is secret-derived.
// In the original Lucky13 (Bernstein-Lange, NDSS 2013) the MAC verification
// over a TLS record runs different numbers of HMAC compression-function
// invocations depending on the padding length, which is itself derived
// from the secret-key-decrypted plaintext.
package main

import "fmt"

// validatePadding loops up to padLen times -- where padLen comes from the
// secret-decrypted last byte of the record. Each iteration's branch is
// data-dependent. Ground-truth: line 18 (loop bound on secret), line 19
// (early-exit branch on secret-byte mismatch).
func validatePadding(plaintext []byte, padLen byte) bool {
	if len(plaintext) < int(padLen)+1 {
		return false
	}
	for i := 0; i < int(padLen); i++ {
		if plaintext[len(plaintext)-1-i] != padLen {
			return false
		}
	}
	return true
}

// verifyMAC: variable-time compare on the MAC bytes. Ground-truth: line 33.
func verifyMAC(received, expected []byte) bool {
	if len(received) != len(expected) {
		return false
	}
	for i := 0; i < len(received); i++ {
		if received[i] != expected[i] {
			return false
		}
	}
	return true
}

func main() {
	pt := make([]byte, 32)
	for i := range pt {
		pt[i] = 5
	}
	fmt.Println(validatePadding(pt, 5))
	fmt.Println(verifyMAC([]byte("aaaa"), []byte("aaab")))
}
