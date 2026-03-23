---
name: mermaid-to-proverif
description: "Translates Mermaid sequenceDiagrams describing cryptographic protocols into ProVerif formal verification models (.pv files). Use when generating a ProVerif model, formally verifying a protocol, converting a Mermaid diagram to ProVerif, verifying protocol security properties (secrecy, authentication, forward secrecy), checking for replay attacks, or producing a .pv file from a sequence diagram."
---

# Mermaid to ProVerif

Reads a Mermaid `sequenceDiagram` describing a cryptographic protocol and
produces a ProVerif model (`.pv` file) that can be passed directly to the
ProVerif verifier.

**Tools used:** Read, Write, Grep, Glob.

The typical input is the output of the `crypto-protocol-diagram` skill — a
Mermaid `sequenceDiagram` annotated with cryptographic operations (`Sign`,
`Verify`, `DH`, `HKDF`, `Enc`, `Dec`, etc.) and message arrows.

## When to Use

- User asks to formally verify a cryptographic protocol described as a Mermaid sequenceDiagram
- User wants to generate a ProVerif model (.pv file) from a protocol diagram
- User wants to prove secrecy, authentication, or forward secrecy properties
- Input is the output of the `crypto-protocol-diagram` skill

## When NOT to Use

- No Mermaid sequenceDiagram exists yet — use `crypto-protocol-diagram` first to generate one
- User wants to verify properties of non-cryptographic systems (state machines, access control)
- User wants to run ProVerif on an existing .pv file — just run `proverif model.pv` directly

## Rationalizations (Do Not Skip)

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "Reachability queries are just busywork" | If events aren't reachable, all other query results are meaningless | Always add reachability queries first as a sanity check |
| "Public channels are fine for all messages" | Private channels for internal state prevent false attacks | Use private channels for intra-process state threading |
| "I'll skip the forward secrecy test" | Ephemeral keys demand forward secrecy verification | Add the ForwardSecrecyTest process whenever the diagram shows ephemeral keys |
| "Unused declarations are harmless" | ProVerif may report spurious results from orphan declarations | Clean up all unused types, functions, and events |
| "The model compiles, so it's correct" | A compiling model can have dead receives, type mismatches, or impossible guards that make queries vacuously true | Validate reachability before trusting any security query |
| "I don't need to check the example first" | The example defines the expected output quality bar | Study `examples/simple-handshake/` before working on unfamiliar protocols |

---

## Workflow

```
ProVerif Model Progress:
- [ ] Step 1: Parse participants and channels
- [ ] Step 2: Inventory cryptographic operations
- [ ] Step 3: Declare types, functions, and equations
- [ ] Step 4: Identify and declare events
- [ ] Step 5: Formulate security queries
- [ ] Step 6: Write participant processes
- [ ] Step 7: Write main process and finalize
- [ ] Step 8: Verify and deliver
```

### Step 1: Parse Participants and Channels

From the Mermaid diagram:

1. Extract every `participant` or `actor` declaration. Each becomes a
   ProVerif process.
2. Count message arrows (`->>`, `-->>`, `-x`, `--x`). Each distinct
   `A ->> B: label` creates a communication step on a channel.
3. Decide channel model:
   - **Public channel** for any message sent over the network before a
     secure channel is established (e.g., ClientHello, ephemeral keys,
     ciphertext to be decrypted by the peer).
   - **Private channel** only for internal state threading within a single
     party process (not for cross-party messages).
   - Default: declare one shared public channel `c` for all cross-party
     messages. Add per-flow channels only when two distinct parallel sessions
     must be independent.

```proverif
free c: channel.
```

### Step 2: Inventory Cryptographic Operations

Walk through every `Note over` annotation and message label. Build a list of
all distinct operations used. Map each to a ProVerif declaration category:

| Mermaid annotation | ProVerif category |
|--------------------|-------------------|
| `keygen() → sk, pk` | New name (`new sk`), public key derived via function |
| `DH(sk_A, pk_B)` | DH function or `exp` with group |
| `Sign(sk, msg) → σ` | Signature function |
| `Verify(pk, msg, σ)` | Equation or destructor |
| `Enc(key, msg) → ct` | Symmetric or asymmetric encryption function |
| `Dec(key, ct) → msg` | Destructor (equation) |
| `HKDF(ikm, info) → k` | PRF/KDF function |
| `HMAC(key, msg) → tag` | MAC function |
| `H(msg) → digest` | Hash function |
| `Commit(v, r) → C` | Commitment function |
| `Open(C, v, r)` | Commitment equation |

Consult [references/crypto-to-proverif-mapping.md](references/crypto-to-proverif-mapping.md)
for exact ProVerif syntax for each.

### Step 3: Declare Types, Functions, and Equations

Build the cryptographic preamble in this order:

1. **Types** — declare custom types used to distinguish key material:

```proverif
type key.
type pkey.   (* public key *)
type skey.   (* secret key *)
type nonce.
```

2. **Constants** — for fixed strings used as domain separators or labels:

```proverif
const msg1_label: bitstring.
const info_session_key: bitstring.
```

3. **Functions** — constructors and destructors. Destructors use inline `reduc`
   so that the process aborts on verification or decryption failure:

```proverif
(* Asymmetric encryption *)
fun aenc(bitstring, pkey): bitstring.
fun adec(bitstring, skey): bitstring
    reduc forall m: bitstring, k: skey;
        adec(aenc(m, pk(k)), k) = m.
fun pk(skey): pkey.

(* Symmetric encryption / AEAD *)
fun senc(bitstring, key): bitstring.
fun sdec(bitstring, key): bitstring
    reduc forall m: bitstring, k: key;
        sdec(senc(m, k), k) = m.

(* Digital signatures — verify returns the message on success, aborts on failure *)
fun sign(bitstring, skey): bitstring.
fun verify(bitstring, bitstring, pkey): bitstring
    reduc forall m: bitstring, k: skey;
        verify(sign(m, k), m, pk(k)) = m.

(* KDF *)
fun hkdf(bitstring, bitstring): key.

(* MAC *)
fun mac(bitstring, key): bitstring.

(* Hash *)
fun hash(bitstring): bitstring.

(* DH *)
fun dh(skey, pkey): key.
fun dhpk(skey): pkey.
```

4. **Equations** — algebraic identities on constructors only (not on destructors,
   which already have their rewrite rules inline):

```proverif
equation forall sk_a: skey, sk_b: skey;
    dh(sk_a, dhpk(sk_b)) = dh(sk_b, dhpk(sk_a)).
```

Only declare what the diagram actually uses. Do not add functions for
operations not present.

### Step 4: Identify and Declare Events

Events mark security-relevant moments in the protocol execution. Extract them
by identifying:

- **Begin events** (`event beginRole(params)`): triggered immediately before a
  party sends a message that depends on a long-term identity commitment (e.g.,
  right before sending a signed message or a MAC'd message).
- **End events** (`event endRole(params)`): triggered immediately after a party
  successfully verifies the peer's identity (e.g., after `Verify(...)` or MAC
  check passes, session key confirmed).
- **Secrecy markers**: any key or nonce that should remain unknown to the
  attacker after the handshake.

```proverif
event beginI(pkey, pkey).     (* pk_I, pk_R — fired before sending the signed message *)
event endI(pkey, pkey, key).  (* pk_I, pk_R, session_key — fired after accepting *)
event beginR(pkey, pkey).
event endR(pkey, pkey, key).
```

Parameters should uniquely identify the session: the parties' public keys,
plus the session key or a transcript hash.

### Step 5: Formulate Security Queries

Write one query per security property. Choose from:

**Reachability (always add first — structural sanity check):**

Verify that the success events are actually reachable. If ProVerif reports any
of these as `false`, the model has a structural bug (dead receive, type mismatch,
impossible guard) and no other query result should be trusted. Once the model
is validated, comment them out if they slow down the main property checks:

```proverif
(* Sanity: both endpoints must be reachable — comment out once validated. *)
(*
query pk_i: pkey, pk_r: pkey, k: key; event(endI(pk_i, pk_r, k)).
query pk_i: pkey, pk_r: pkey, k: key; event(endR(pk_i, pk_r, k)).
*)
```

**Secrecy** (key not derivable by attacker):

Declare a private free name and encrypt it under the session key. The attacker
knowing `private_I` is equivalent to breaking the session key:

```proverif
free private_I: bitstring [private].

(* In process, after deriving sk_session: *)
out(c, aead_enc(private_I, sk_session));

(* Query: *)
query attacker(private_I).
```

**Weak authentication** (if B accepted, A ran at some point with matching
params — does not prevent replay):

```proverif
query pk_i: pkey, pk_r: pkey, k: key;
    event(endR(pk_i, pk_r, k)) ==> event(beginI(pk_i, pk_r)).
```

**Injective authentication** (prevents replay — each B-accept corresponds to
a distinct A-run):

```proverif
query pk_i: pkey, pk_r: pkey, k: key;
    inj-event(endR(pk_i, pk_r, k)) ==>
    inj-event(beginI(pk_i, pk_r)).
```

**Forward secrecy**: add a `ForwardSecrecyTest` process to the main process
that leaks both long-term secret keys to the attacker, then check that a past
session key remains secret. Pair it with a `free fs_witness: key [private]`
declaration and `query attacker(fs_witness)`. See
[references/security-properties.md](references/security-properties.md) →
Forward Secrecy, and the worked example in
`examples/simple-handshake/sample-output.pv`.

Choose the strongest applicable query for each property. See
[references/security-properties.md](references/security-properties.md) for
the full decision tree.

### Step 6: Write Participant Processes

Write one `let` process per participant. Structure each process to mirror the
Mermaid diagram step-by-step, in order.

**Template for a two-party protocol:**

```proverif
let Initiator(sk_I: skey, pk_R: pkey) =
    (* Step: generate ephemeral key *)
    new ek_I: skey;
    let epk_I = dhpk(ek_I) in
    (* Step: sign and send msg1 *)
    let sig_I = sign((msg1_label, epk_I), sk_I) in
    out(c, (epk_I, sig_I));
    (* Step: receive msg2 *)
    in(c, (epk_R: pkey, sig_R: bitstring));
    (* Step: verify responder signature *)
    if verify(sig_R, (msg2_label, epk_I, epk_R), pk_R) = true then
    (* Step: derive session key *)
    let dh_val = dh(ek_I, epk_R) in
    let sk_session = hkdf((dh_val, epk_I, epk_R), info_session_key) in
    event endInitiator(pk(sk_I), pk_R, sk_session);
    (* Secrecy witness: encrypt a fresh secret under the session key.
     * The query attacker(secret_I) checks that the attacker cannot read it.
     * See references/security-properties.md for the full secrecy query pattern. *)
    new secret_I: bitstring;
    out(c, senc(secret_I, sk_session)).
```

**Rules for writing processes:**

- Each `A ->> B: msg_contents` in the diagram becomes:
  - `out(c, msg_contents)` in A's process
  - `in(c, x)` (with matching destructuring) in B's process
- Each `Note over A: op → result` becomes a `let result = op in` binding
- Each `Note over A: Verify(...)` becomes an `if verify(...) = true then`
  branch (the `else` branch is implicit — the process simply stops on failure,
  modeling abort)
- Use `alt` blocks in the diagram as `if/then/else` in the process
- Long-term keys are process parameters; ephemeral values use `new`

**N-party or MPC protocols:** write one process per distinct role. For
threshold protocols, write a single role process and replicate it `!N` times
in the main process.

### Step 7: Write Main Process and Finalize

The main process:

1. Generates long-term keys with `new`
2. Publishes public keys to the attacker via `out(c, pk(sk))`
3. Runs participant processes in parallel under replication (`!`) to allow
   multiple sessions
4. Optionally leaks long-term keys for forward-secrecy analysis

```proverif
process
    new sk_I: skey; let pk_I = pk(sk_I) in out(c, pk_I);
    new sk_R: skey; let pk_R = pk(sk_R) in out(c, pk_R);
    (
        !Initiator(sk_I, pk_R)
      | !Responder(sk_R, pk_I)
    )
```

Place the full file in this order:

```
(* 1. Channel declarations (free c: channel. / free ch: channel [private].) *)
(* 2. noselect directives (if needed for termination) *)
(* 3. Type declarations *)
(* 4. Constants *)
(* 5. Function declarations *)
(* 6. Equations (algebraic identities on constructors only) *)
(* 7. Table declarations *)
(* 8. Events *)
(* 9. Queries *)
(* 10. Let processes *)
(* 11. Main process *)
```

### Step 8: Verify and Deliver

Before writing the file:

- [ ] Every participant in the diagram has a matching `let` process
- [ ] Every `out(c, ...)` has a matching `in(c, ...)` on the other side with
      compatible types
- [ ] Every function used in a process is declared in the preamble
- [ ] Every destructor uses inline `reduc` (not a separate `equation` block)
- [ ] Every event in a query is declared and triggered in a process
- [ ] Long-term public keys are output to channel `c` in the main process
      (attacker can see them — that is the Dolev-Yao model)
- [ ] No unused declarations (clean up anything added speculatively)
- [ ] If `table` declarations are present: every `insert T(...)` has a
      corresponding `get T(...)` with compatible column types and matching
      pattern constraints (`=key` vs bare name)
- [ ] If `noselect` is used: its tuple structure matches the actual message
      shapes sent on `c` (e.g., pairs → `mess(c, (x, y))`)
- [ ] If the Key Exposure Oracle pattern is used: `event key_exposed(sk_type)`
      is declared, the oracle `in(c, guess: sk_type); if pk(guess) = pk_new then
      event key_exposed(guess)` appears at the end of the process that holds the
      secret, and the query is `query x: sk_type; event(key_exposed(x))`

**Write the model to a `.pv` file.** Choose a filename from the protocol name,
e.g. `noise-xx-handshake.pv` or `x3dh-key-agreement.pv`.

After writing, print a brief summary:

```
Protocol:   <Name>
Output:     <filename>
Queries:    <list each query and what property it tests>
Assumptions: <list modeling decisions and simplifications>
```

---

## Decision Tree

```
├─ No Mermaid diagram provided?
│  └─ Ask the user: "Please provide the Mermaid sequenceDiagram,
│     or run the crypto-protocol-diagram skill first."
│
├─ Diagram uses DH (not just symmetric crypto)?
│  └─ Use dh/dhpk with commutativity equation
│     See references/crypto-to-proverif-mapping.md → DH section
│
├─ Diagram uses asymmetric signatures (Sign/Verify)?
│  └─ Use sign/verify with inline reduc (not equation)
│     verify returns the message on success; let _ = verify(...) in to abort on failure
│     Distinguish signing key (skey) from verification key (pkey)
│
├─ Diagram has an "alt" block (abort path)?
│  └─ Model as if/then only — the else branch aborts (process terminates)
│     Do NOT add out(c, error_message) unless the diagram shows it
│
├─ Protocol has N > 2 parties?
│  └─ Write one process per role, use ! for replication
│     Pass participant index as a parameter if roles differ by index only
│
├─ Forward secrecy requested?
│  └─ Add a ForwardSecrecy variant in the main process that leaks
│     long-term sk after session; add secrecy query for past session_key
│     See references/security-properties.md → Forward Secrecy
│
├─ Type-checker rejects the model?
│  └─ ProVerif is typed: check every function arg type matches declaration.
│     bitstring is the catch-all; key/pkey/skey/nonce are stricter.
│     Cast with explicit constructors when needed.
│
├─ Protocol has cross-process state coordination (e.g., one process must wait
│  for another to record acceptance before proceeding)?
│  └─ Use ProVerif tables (table/insert/get)
│     See references/proverif-syntax.md → Tables
│
├─ Verification does not terminate after several minutes?
│  └─ Add noselect directive matching the message tuple structure on c
│     See references/proverif-syntax.md → noselect
│
├─ Protocol generates a private-type key (type sk [private]) that is never
│  output directly but whose secrecy should be verified?
│  └─ Use the Key Exposure Oracle pattern instead of query attacker(sk)
│     See references/security-properties.md → Key Exposure Oracle
│
└─ Unsure which security properties to verify?
   └─ Default set: secrecy of session key + injective authentication
      (both directions). Add forward secrecy if diagram shows ephemeral keys.
```

---

## Example

`examples/simple-handshake/` contains a worked example:

- **`diagram.md`** — Mermaid sequenceDiagram for a two-party authenticated key
  exchange (X25519 DH + Ed25519 signing + HKDF)
- **`sample-output.pv`** — exact ProVerif model the skill should produce,
  with secrecy and injective authentication queries

Study this before working on an unfamiliar protocol.

---

## Supporting Documentation

- **[references/crypto-to-proverif-mapping.md](references/crypto-to-proverif-mapping.md)** —
  Mapping table from Mermaid cryptographic annotations to ProVerif function
  declarations, equations, and process patterns
- **[references/proverif-syntax.md](references/proverif-syntax.md)** —
  ProVerif language reference: types, functions, equations, processes, events,
  queries, and common pitfalls
- **[references/security-properties.md](references/security-properties.md)** —
  Decision guide for choosing the right queries: secrecy, authentication
  (weak vs injective), forward secrecy, unlinkability, and how to model them
