# Cryptographic Operation to ProVerif Mapping

Maps every Mermaid annotation produced by the `crypto-protocol-diagram` skill
to the corresponding ProVerif declarations and process patterns.

Use this table to build the preamble (types, functions, equations) and the
per-step process code for each participant.

---

## Key Generation

### Long-term asymmetric keypair

**Mermaid:** `Note over A: keygen() → sk_A, pk_A`

**Meaning:** Party A has a long-term signing or asymmetric encryption keypair.

**ProVerif:**
- Long-term keys are inputs to the participant process (not `new` inside).
- The secret key is a process parameter; the public key is derived.
- The main process generates the keypair and publishes the public key.

```proverif
(* Function declaration *)
fun pk(skey): pkey.

(* In main process *)
new sk_A: skey; let pk_A = pk(sk_A) in out(c, pk_A);

(* In participant process signature *)
let PartyA(sk_A: skey, pk_B: pkey) = ...
```

### Ephemeral keypair

**Mermaid:** `Note over A: keygen() → ek_A, epk_A`

**Meaning:** Party A generates a fresh single-use keypair for this session.

**ProVerif:**
- Generate with `new` inside the participant process.
- Derive the public ephemeral key from the secret ephemeral key.

```proverif
(* Function declaration *)
fun dhpk(skey): pkey.

(* In participant process *)
new ek_A: skey;
let epk_A = dhpk(ek_A) in
```

---

## Diffie-Hellman

### Two-party DH

**Mermaid:** `Note over A: dh = DH(ek_A, epk_B)`

**Meaning:** Party A computes the DH shared secret using their ephemeral
secret key and the peer's ephemeral public key.

**ProVerif:**

```proverif
(* Function declarations *)
fun dhpk(skey): pkey.
fun dh(skey, pkey): key.

(* Equation — DH commutativity *)
equation forall a: skey, b: skey;
    dh(a, dhpk(b)) = dh(b, dhpk(a)).

(* In process *)
let dh_val = dh(ek_A, epk_B) in
```

**Note:** ProVerif's equation engine handles the commutativity — you only
write `dh(ek_A, epk_B)` in A's process and `dh(ek_B, epk_A)` in B's process;
the equation unifies them.

### Static-ephemeral DH (e.g., for authentication)

**Mermaid:** `Note over A: dh_se = DH(sk_A, epk_B)`

Same declaration — `dh` accepts any `skey` regardless of whether it is
long-term or ephemeral. The typing is structural.

---

## Key Derivation (KDF / HKDF / PRF)

**Mermaid:** `Note over A: sk = HKDF(dh || transcript, info="...")`

**Meaning:** Party A derives a session key from keying material and
domain-separation info.

**ProVerif:**

```proverif
(* Function declaration *)
fun hkdf(key, bitstring): key.

(* Constants for domain separation labels *)
const info_session_key: bitstring.
const info_handshake: bitstring.

(* In process — concatenate IKM and call hkdf *)
let sk_session = hkdf(dh_val, concat(info_session_key, concat(pkey2bs(epk_A), pkey2bs(epk_B)))) in
```

**Tuple vs concatenation:** Use tuples `(a, b, c)` rather than a `concat`
function when the protocol only extracts keys from HKDF (not when it computes
a MAC over the same bytes). Tuples are simpler and keep the model readable.

If the protocol chains two HKDF calls (e.g., TLS 1.3's `HKDF-Extract` +
`HKDF-Expand`), model them as two separate function applications:

```proverif
let prk = hkdf_extract(salt, ikm) in
let okm = hkdf_expand(prk, info, length_tag) in
```

---

## Digital Signatures

### Signing

**Mermaid:** `Note over A: σ = Sign(sk_A, msg)`

**ProVerif:**

```proverif
(* Function declarations *)
fun sign(bitstring, skey): bitstring.
fun pk(skey): pkey.    (* verification key derived from signing key *)

(* In process *)
let sig = sign(msg, sk_A) in
```

### Verification

**Mermaid:** `Note over B: Verify(pk_A, msg, σ)`

**ProVerif:**

```proverif
(* Function declaration — returns the message on success, aborts on failure *)
fun verify(bitstring, bitstring, pkey): bitstring
    reduc forall m: bitstring, k: skey;
        verify(sign(m, k), m, pk(k)) = m.

(* In process — let _ = ... in aborts the branch if the signature is invalid *)
let _ = verify(sig, msg, pk_A) in
```

**Signing key vs verification key:** In ProVerif it is idiomatic to use a
single `skey` as the signing key and derive the verification key with `pk`.
Do not create a separate `vk` type unless the diagram explicitly uses
different keys for signing and verification (rare).

---

## Symmetric Encryption / AEAD

### Encryption

**Mermaid:** `Note over A: ct = Enc(key, plaintext)` or
`A ->> B: AEAD(sk, nonce, plaintext)`

**ProVerif:**

```proverif
(* Function declarations *)
fun senc(bitstring, key): bitstring.
fun sdec(bitstring, key): bitstring
    reduc forall m: bitstring, k: key;
        sdec(senc(m, k), k) = m.

(* In process *)
let ct = senc(plaintext, sk_session) in
out(c, ct);
```

### Decryption

**Mermaid:** `Note over B: plaintext = Dec(key, ct)`

```proverif
(* In process *)
in(c, ct: bitstring);
let plaintext = sdec(ct, sk_session) in
```

**AEAD vs unauthenticated encryption:** ProVerif does not distinguish AEAD
from unauthenticated encryption at the equational level — both use `senc`/`sdec`.
Authentication is modeled implicitly: if decryption succeeds (the equation
fires), the ciphertext was produced with the correct key. This is a standard
simplification in symbolic models.

---

## Message Authentication Codes (MAC)

**Mermaid:** `Note over A: tag = MAC(key, msg)` /
`Note over B: VerifyMAC(key, msg, tag)`

**ProVerif:**

```proverif
(* Function declaration *)
fun mac(bitstring, key): bitstring.

(* Verification: check tag equals recomputed mac *)
if mac(msg, key) = received_tag then
```

**Note:** Unlike signatures, MACs do not have a dedicated verify function.
Verification is equality-checking the recomputed value. This means:
- Both parties must hold the key (symmetric — no public-key exposure).
- Do not output the MAC key to channel `c` in the main process.

---

## Asymmetric Encryption

**Mermaid:** `Note over A: ct = AEnc(pk_B, msg)` /
`Note over B: plaintext = ADec(sk_B, ct)`

**ProVerif:**

```proverif
fun aenc(bitstring, pkey): bitstring.
fun adec(bitstring, skey): bitstring
    reduc forall m: bitstring, k: skey;
        adec(aenc(m, pk(k)), k) = m.

(* Encrypt *)
let ct = aenc(msg, pk_B) in out(c, ct);

(* Decrypt *)
in(c, ct: bitstring);
let msg = adec(ct, sk_B) in
```

---

## Hash Functions

**Mermaid:** `Note over A: h = H(data)` or `h = SHA256(data)`

**ProVerif:**

```proverif
fun hash(bitstring): bitstring.

(* In process *)
let h = hash(data) in
```

Hash functions are modeled as free constructors — the attacker can compute
them on any input. This is the standard symbolic model (random oracle is not
needed for most authentication properties).

---

## Commitments

**Mermaid:** `Note over A: C = Commit(value, rand)` /
`Note over B: Open(C, value, rand)` or `Verify(C, value, rand)`

**ProVerif:**

```proverif
fun commit(bitstring, bitstring): bitstring.

(* Binding: equational model — no equation needed;
   opening is modeled by sending value and rand and letting
   the verifier recompute the commitment *)

(* Committer *)
new r: bitstring;
let com = commit(value, r) in
out(c, com);           (* send commitment *)
...
out(c, (value, r));    (* reveal *)

(* Verifier *)
in(c, (v: bitstring, r2: bitstring));
if commit(v, r2) = received_com then
```

**Hiding:** This symbolic model does not prove computational hiding. For
formal hiding proofs, use a computational tool (CryptoVerif, EasyCrypt).

---

## Nonces

**Mermaid:** `Note over A: nonce_A = random()` or `A ->> B: nonce_A`

**ProVerif:**

```proverif
new nonce_A: bitstring.   (* type can also be nonce *)
out(c, nonce_A);
```

Nonces are just fresh bitstrings. Use `type nonce.` if you want to prevent
accidental type confusion, but `bitstring` is fine for simple protocols.

---

## Message Concatenation and Transcripts

**Mermaid:** `transcript = epk_I || epk_R` or `msg = A || B || C`

**ProVerif approach:**

Prefer **tuples** over a concat function:

```proverif
(* Send: pack into tuple *)
out(c, (epk_I, epk_R));

(* Receive: destructure tuple *)
in(c, (epk_I: pkey, epk_R: pkey));
```

Use a `concat` function only when the protocol computes over the raw
concatenated bytes in a way that matters (e.g., the transcript is fed to a
MAC or HKDF as a single blob, and the parts are also available separately).
In that case:

```proverif
fun concat2(bitstring, bitstring): bitstring.
fun concat3(bitstring, bitstring, bitstring): bitstring.
```

There are no equations on `concat` — it is a free constructor, which is
correct: the attacker cannot split a concatenation unless they know the
length boundaries (length-prefix models are usually out of scope for symbolic
proofs).

---

## Key Agreement Summary Table

| Mermaid annotation | ProVerif function | Equation needed? |
|-------------------|-------------------|------------------|
| `keygen() → sk, pk` | `pk(skey): pkey` | No |
| `keygen() → ek, epk` | `dhpk(skey): pkey` | No |
| `DH(ek, epk)` | `dh(skey, pkey): key` | Yes — commutativity |
| `HKDF(ikm, info)` | `hkdf(key, bitstring): key` | No |
| `Sign(sk, msg)` | `sign(bitstring, skey): bitstring` | No |
| `Verify(pk, msg, σ)` | `verify(bitstring, bitstring, pkey): bitstring` | Yes — inline `reduc` |
| `Enc(k, m)` / `Dec(k, ct)` | `senc` / `sdec` | Yes — correctness |
| `AEnc(pk, m)` / `ADec(sk, ct)` | `aenc` / `adec` | Yes — correctness |
| `MAC(k, m)` | `mac(bitstring, key): bitstring` | No |
| `H(data)` | `hash(bitstring): bitstring` | No |
| `Commit(v, r)` | `commit(bitstring, bitstring): bitstring` | No |
| `nonce = random()` | `new nonce: bitstring` | No |

---

## Modeling Notes

### What the symbolic model captures

- Perfect correctness of cryptographic functions (equations hold exactly)
- Dolev-Yao attacker: controls the network, can read/write all public channel
  messages, knows all published public keys
- Unbounded sessions via replication `!`

### What the symbolic model does NOT capture

- Computational hardness (e.g., discrete log, AES key recovery)
- Timing side-channels
- Nonce/IV reuse in AEAD (model assumes nonces are always fresh)
- Key material leakage through implementation bugs
- Computational binding/hiding of commitment schemes

For these properties, use CryptoVerif (computational) or EasyCrypt (proofs).
