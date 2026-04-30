package main

import (
	_ "crypto/aes"
	_ "crypto/cipher"
	_ "crypto/ecdsa"
	_ "crypto/ed25519"
	_ "crypto/hmac"
	_ "crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	_ "crypto/subtle"
	_ "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	_ "github.com/cloudflare/circl/pke/kyber/internal/common"
	_ "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/chacha20poly1305"
	_ "golang.org/x/crypto/curve25519"
	_ "golang.org/x/crypto/nacl/box"
	_ "golang.org/x/crypto/salsa20"
)

func main() {}
