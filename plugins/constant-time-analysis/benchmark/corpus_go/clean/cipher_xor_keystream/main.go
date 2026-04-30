// Source: AES-CTR mode wrapper from crypto/cipher style. Branches and
// divisions are on public byte-counter / public length, never on the
// secret key. The block cipher itself is below the wrapper boundary;
// for our purposes the wrapper's loop is the only thing the analyzer
// sees.
package main

import "fmt"

// xorKeyStream applies a stream cipher's keystream to dst by XORing.
// nblocks = ceil(len(input) / blockSize) is on PUBLIC lengths.
func xorKeyStream(dst, src []byte, blockSize int, gen func() []byte) {
	if len(dst) != len(src) {
		panic("length mismatch")
	}
	var ks []byte
	for i := 0; i < len(src); i++ {
		// Refresh keystream every blockSize bytes (i % blockSize == 0).
		if i%blockSize == 0 {
			ks = gen()
		}
		dst[i] = src[i] ^ ks[i%blockSize]
	}
}

func main() {
	src := []byte("hello world! this is plaintext.")
	dst := make([]byte, len(src))
	counter := 0
	xorKeyStream(dst, src, 16, func() []byte {
		counter++
		k := make([]byte, 16)
		for i := range k {
			k[i] = byte(counter * (i + 1))
		}
		return k
	})
	fmt.Printf("%x\n", dst[:8])
}
