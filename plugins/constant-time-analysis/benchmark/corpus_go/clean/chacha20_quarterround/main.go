// Source: ChaCha20 quarter-round (DJB reference, mirrored in Go's
// chacha20 implementation). ARX-only: add, rotate, XOR. No branches
// or divisions. The for-loop in ChaCha20Block iterates a public,
// constant 10 times.
package main

import (
	"encoding/binary"
	"fmt"
)

func rotl(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

// quarterRound is the ARX core of ChaCha20. No data-dependent control flow.
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = rotl(d, 16)
	c += d
	b ^= c
	b = rotl(b, 12)
	a += b
	d ^= a
	d = rotl(d, 8)
	c += d
	b ^= c
	b = rotl(b, 7)
	return a, b, c, d
}

// ChaCha20Block: 20 rounds (10 double-rounds) over a 16-word state.
func ChaCha20Block(out []byte, key []byte, counter uint32, nonce []byte) {
	var state [16]uint32
	state[0], state[1], state[2], state[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[12] = counter
	for i := 0; i < 3; i++ {
		state[13+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	x := state
	for i := 0; i < 10; i++ {
		x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = quarterRound(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = quarterRound(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = quarterRound(x[3], x[7], x[11], x[15])
		x[0], x[5], x[10], x[15] = quarterRound(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = quarterRound(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = quarterRound(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = quarterRound(x[3], x[4], x[9], x[14])
	}
	for i := 0; i < 16; i++ {
		x[i] += state[i]
		binary.LittleEndian.PutUint32(out[i*4:], x[i])
	}
}

func main() {
	out := make([]byte, 64)
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	ChaCha20Block(out, key, 1, nonce)
	fmt.Printf("%x\n", out[:8])
}
