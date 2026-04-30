// Source: SHA-256 absorb loop from a generic block-mode digest. The
// block boundary check `idx == 64` is on a public byte-counter, and
// the inner round loop iterates a constant 64 times.
package main

import "fmt"

type sha256State struct {
	h   [8]uint32
	idx int
	buf [64]byte
}

// k is the public SHA-256 round constant table.
var k = [64]uint32{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5}

func sha256BlockUpdate(s *sha256State, data []byte) {
	for i := 0; i < len(data); i++ {
		s.buf[s.idx] = data[i]
		s.idx++
		if s.idx == 64 {
			sha256Compress(s)
			s.idx = 0
		}
	}
}

// sha256Compress operates on s.h and s.buf, ARX style. No data branches.
func sha256Compress(s *sha256State) {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = uint32(s.buf[4*i])<<24 | uint32(s.buf[4*i+1])<<16 |
			uint32(s.buf[4*i+2])<<8 | uint32(s.buf[4*i+3])
	}
	for i := 16; i < 64; i++ {
		s0 := (w[i-15]>>7 | w[i-15]<<25) ^ (w[i-15]>>18 | w[i-15]<<14) ^ (w[i-15] >> 3)
		s1 := (w[i-2]>>17 | w[i-2]<<15) ^ (w[i-2]>>19 | w[i-2]<<13) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, d, e, f, g, h := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7]
	for i := 0; i < 4; i++ { // truncated for brevity
		t1 := h + ((e>>6 | e<<26) ^ (e>>11 | e<<21) ^ (e>>25 | e<<7)) +
			((e & f) ^ (^e & g)) + k[i] + w[i]
		t2 := ((a>>2 | a<<30) ^ (a>>13 | a<<19) ^ (a>>22 | a<<10)) +
			((a & b) ^ (a & c) ^ (b & c))
		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}
	s.h[0] += a
	s.h[1] += b
	s.h[2] += c
	s.h[3] += d
	s.h[4] += e
	s.h[5] += f
	s.h[6] += g
	s.h[7] += h
}

func main() {
	var s sha256State
	s.h = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	sha256BlockUpdate(&s, []byte("hello, world!"))
	fmt.Printf("%x\n", s.h[:1])
}
