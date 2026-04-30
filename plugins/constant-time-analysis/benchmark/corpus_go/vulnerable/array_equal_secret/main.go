// `[N]byte == [N]byte` on secret data. Even though Go's runtime contract
// for memequal on small fixed-size arrays is supposed to be constant-time
// at the assembly level, calling `==` from a function with secret-named
// params is the canonical pattern that EVERY production crypto reviewer
// checks for: it's a bytes.Equal in disguise. The source-level filter
// (memcmp-source) flags it as if it were a memcmp on secret-named args.
//
// Ground-truth: line 21 -- equality on secret-named MAC arrays.
package main

import "fmt"

type tag [16]byte

// authArr compares two MAC tags. The compiler emits inlined byte-by-byte
// compare or a runtime.memequal call -- in either case, source-level
// review flags it.
func authArr(receivedMAC, expectedMAC tag) bool {
	return receivedMAC == expectedMAC // line 21
}

func main() {
	var a, b tag
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(i)
	}
	fmt.Println(authArr(a, b))
}
