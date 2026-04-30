// Source: HKDF-Expand from Go stdlib (golang.org/x/crypto/hkdf).
// The block-counter loop is over a public output length; HMAC update
// inside is over public counter bytes. HMAC's own keyed update would
// be CT in any production implementation, but this corpus item only
// covers the wrapper.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// HKDFExpand iterates HMAC-SHA256 to produce `length` bytes from the
// `prk` PRK and the public `info`. The loop bound is length / hashLen
// where hashLen=32 is constant; the divide is on a public quantity.
func HKDFExpand(prk, info []byte, length int) []byte {
	h := hmac.New(sha256.New, prk)
	out := make([]byte, 0, length)
	var counter byte = 1
	var prev []byte
	for len(out) < length {
		h.Reset()
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{counter})
		prev = h.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:length]
}

func main() {
	prk := []byte("super-strong-prk")
	info := []byte("ctx")
	out := HKDFExpand(prk, info, 64)
	fmt.Printf("%x\n", out[:8])
}
