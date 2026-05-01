# Security Properties in ProVerif

A guide to choosing and expressing the right security queries for a given
Mermaid sequence diagram.

---

## Decision Tree: Which Queries to Include

```
Start here for every protocol
│
├─ Does the protocol establish a shared key?
│  └─ YES → Add secrecy query for that key
│
├─ Does a party verify the peer's identity (Verify/MAC check)?
│  └─ YES → Add authentication queries (both directions if mutual auth)
│     ├─ Does the verification cover a fresh session value (nonce, epk)?
│     │  └─ YES → Use injective authentication (prevents replay)
│     └─ NO (only verifies static identity, no freshness) → Use weak auth
│
├─ Does the protocol use ephemeral keys (keygen inside the session)?
│  └─ YES → Add forward secrecy query (compromise long-term key after session)
│
├─ Does the protocol have a "challenge-response" nonce exchange?
│  └─ YES → Add injective authentication to capture that freshness
│
└─ Always add: reachability sanity check query
```

---

## 1. Secrecy

### Goal

The session key (or any sensitive value) is not learnable by the attacker,
even after observing all network traffic.

### When to add

Add whenever the Mermaid diagram contains a derived session key label (e.g.,
`sk_session`, `sk_I`, `key_data`) that should remain private.

### Query

The canonical pattern: declare a private free name and encrypt it under the
session key. The attacker learning `private_I` is equivalent to breaking the
session key, because decrypting the ciphertext requires it.

```proverif
(* Top-level declarations *)
free private_I: bitstring [private].
free private_R: bitstring [private].

(* In the Initiator process, after deriving sk_session: *)
out(c, aead_enc(private_I, sk_session));

(* In the Responder process, after deriving sk_session: *)
out(c, aead_enc(private_R, sk_session));

(* Queries *)
query attacker(private_I).
query attacker(private_R).
```

ProVerif proves `attacker(private_I)` by verifying that no derivation path
for `private_I` exists. Since `private_I` is encrypted and decryption requires
`sk_session`, this is equivalent to session key secrecy.

**Important:** `attacker(k)` cannot appear as the consequent of a
correspondence query (`event(...) ==> attacker(k)` is not valid ProVerif
syntax). Use the witness pattern above instead.

---

## 2. Authentication

### Weak Authentication

**Goal:** If B completed accepting a session with A, then A ran at some point.
Does NOT prevent replay (attacker can replay A's messages to create a second
session where B accepts).

**When to use:** Protocol has identity verification but no per-session
freshness binding (e.g., only verifies a static certificate, no nonce or
ephemeral key in the signature).

```proverif
query pk_i: pkey, pk_r: pkey, k: key;
    event(endR(pk_i, pk_r, k)) ==> event(beginI(pk_i, pk_r)).
```

Note: `beginI` fires before the session key is known, so it typically
has fewer parameters than `endR`. Match the parameter list to what the
`begin` event actually receives when it fires.

### Injective Authentication

**Goal:** Each B-accept corresponds to a distinct, unique A-run. Prevents
replay attacks.

**When to use:** The signature (or MAC) covers a fresh value unique to this
session — an ephemeral key, a nonce, or a transcript hash. This is the
default for most modern protocols.

```proverif
query pk_i: pkey, pk_r: pkey, k: key;
    inj-event(endR(pk_i, pk_r, k)) ==>
    inj-event(beginI(pk_i, pk_r)).
```

**Note on `inj-event`:** ProVerif will report this as `true` if there is a
one-to-one correspondence. If it reports `false`, the protocol is vulnerable
to replay — investigate whether nonces or ephemeral keys are correctly bound
in the signatures.

### Mutual Authentication

For protocols where both parties authenticate each other, add queries in both
directions:

```proverif
(* Responder accepts => Initiator ran *)
query pk_i: pkey, pk_r: pkey, k: key;
    inj-event(endR(pk_i, pk_r, k)) ==>
    inj-event(beginI(pk_i, pk_r)).

(* Initiator accepts => Responder ran *)
query pk_i: pkey, pk_r: pkey, k: key;
    inj-event(endI(pk_i, pk_r, k)) ==>
    inj-event(beginR(pk_i, pk_r)).
```

### Placing Events in the Process

| Event | Where to trigger |
|-------|-----------------|
| `beginI(pk_I, pk_R)` | Just before Initiator sends the first authenticated message (the one signed with sk_I) |
| `endI(pk_I, pk_R, sk)` | Just after Initiator successfully verifies Responder's identity AND derives session key |
| `beginR(pk_I, pk_R)` | Just before Responder sends its signed reply |
| `endR(pk_I, pk_R, sk)` | Just after Responder successfully verifies Initiator's identity AND derives session key |

The session key `sk` in the event parameters binds authentication to the
specific key material established — preventing cross-session confusion attacks.

---

## 3. Forward Secrecy

### Goal

Compromise of a long-term key AFTER a session completes does not allow the
attacker to decrypt past session traffic.

### When to add

Add when:
- The Mermaid diagram shows ephemeral key generation inside the session
  (e.g., `keygen() → ek_I, epk_I`)
- The session key derivation uses DH over ephemeral keys (not just static ones)

### Modeling Pattern

Leak long-term keys to the attacker and check that session key secrecy
still holds. If it does, forward secrecy is achieved because the session
key depends only on ephemeral material.

```proverif
(* In main process — leak long-term keys immediately *)
new sk_I: skey; out(c, pk(sk_I)); out(c, sk_I);  (* attacker knows sk_I *)
new sk_R: skey; out(c, pk(sk_R)); out(c, sk_R);  (* attacker knows sk_R *)
(!Initiator(sk_I, pk(sk_R)) | !Responder(sk_R, pk(sk_I)))
```

The existing session key secrecy query (`query attacker(private_I).`) now
tests forward secrecy: if the attacker knows both long-term keys but still
cannot derive the session key, the protocol has forward secrecy. If the
query fails, the session key depended on a long-term key.

---

## 4. Reachability (Sanity Check)

### Goal

Confirm that the success path of the protocol actually executes. A ProVerif
model with a bug (e.g., a type error causing a dead receive) may trivially
prove all security properties because the end event is never reached.

### Always add

```proverif
query pk_i: pkey, pk_r: pkey, k: key; event(endI(pk_i, pk_r, k)).
query pk_i: pkey, pk_r: pkey, k: key; event(endR(pk_i, pk_r, k)).
```

Note: ProVerif does not support `_` wildcards in `query` declarations; every
parameter must be bound to a typed variable.

If ProVerif reports these as `false` (unreachable), the model has a structural
bug. Fix it before trusting any other query result.

---

## 5. Key Exposure Oracle (for `[private]` type secrets)

### Goal

Prove that the attacker cannot learn a secret key `sk` that is declared with a
private type (`type sk [private]`) and never directly output on the public
channel.

### Why `query attacker(sk)` doesn't work here

`query attacker(sk)` checks whether the attacker can derive the term `sk` from
public channel traffic. A value of a private type is never synthesised by the
attacker (the type prevents it), and if `sk` is never output, ProVerif cannot
prove the query — it would return `cannot be proved`, not `true`. The property
needs a different formulation.

### The oracle pattern

Give the attacker an explicit "guess oracle": receive an arbitrary value of
type `sk` from the public channel, then fire a `key_exposed` event if that
guess matches the known public key:

```proverif
(* Declare the sentinel event — use whatever secret key type the protocol uses *)
event key_exposed(skey).

(* Secrecy query: key_exposed must be unreachable *)
query x: skey; event(key_exposed(x)).

(* At the end of the process that generated sk_new — place after all other
 * protocol steps so the oracle is only reachable on a complete run: *)
in(c, guess: skey);
if pk(guess) = pk_new then event key_exposed(guess)
else 0.
```

**How it works:**

1. The attacker submits its best guess for `sk_new` via `c`.
2. The process checks whether `pk(guess)` matches the known `pk_new`.
3. If the check succeeds, `key_exposed` fires.
4. ProVerif proves `event(key_exposed(x))` unreachable → no guess can match
   the public key → `sk_new` is secret.

### When to use

Use the oracle pattern when all of these hold:

- The secret key is of a `[private]` type (e.g., `type skey [private]`) and
  never output directly.
- The corresponding public key IS observable on `c` (e.g., sent in a signed
  message or after key exchange).
- `query attacker(sk_new)` would return `cannot be proved` (not meaningful).

### Placement in process

Put the oracle at the very end of the process that generated `sk_new`,
**after** all other steps that depend on the secret are complete (typically
after the signature is sent). This ensures `key_exposed` is only reachable
upon protocol completion, not on every intermediate step.

---

## 6. Query Checklist by Protocol Type

### Two-party key exchange (e.g., DH-based handshake)

```proverif
(* Sanity — all parameters must be bound to typed variables *)
query pk_i: pkey, pk_r: pkey, k: key; event(endI(pk_i, pk_r, k)).
query pk_i: pkey, pk_r: pkey, k: key; event(endR(pk_i, pk_r, k)).

(* Session key secrecy — use the witness pattern, not correspondence *)
query attacker(private_I).
query attacker(private_R).

(* Mutual injective authentication *)
query pk_i: pkey, pk_r: pkey, k: key;
    inj-event(endR(pk_i, pk_r, k)) ==> inj-event(beginI(pk_i, pk_r)).
query pk_i: pkey, pk_r: pkey, k: key;
    inj-event(endI(pk_i, pk_r, k)) ==> inj-event(beginR(pk_i, pk_r)).
```

### Unilateral authentication (server authenticates, client does not)

```proverif
(* Sanity *)
query pk_s: pkey, k: key; event(endC(pk_s, k)).

(* Session key secrecy — use the witness pattern *)
query attacker(private_C).

(* Server authentication only — client to server direction *)
query pk_s: pkey, k: key;
    inj-event(endC(pk_s, k)) ==> inj-event(beginS(pk_s, k)).
```

### Commit-reveal protocol

```proverif
(* Binding: verifier accepts only the committed value *)
query v: bitstring, r: bitstring;
    event(accepted(v)) ==> event(committed(v, r)).

(* Hiding: attacker cannot learn committed value before reveal *)
query attacker(committed_value).
```

### Challenge-response authentication

```proverif
(* Freshness: each successful auth used a distinct challenge *)
query id: pkey, ch: bitstring;
    inj-event(authSuccess(id, ch)) ==> inj-event(challengeSent(id, ch)).
```

---

## 7. Interpreting ProVerif Output

| ProVerif result | Meaning |
|----------------|---------|
| `RESULT ... is true.` | Property holds for all executions (proof found) |
| `RESULT ... is false.` | Attack found — ProVerif prints a trace |
| `RESULT ... cannot be proved.` | Proof search timed out or approximation too coarse; does not mean the property is false |

When a result is `false`, read the attack trace carefully:
1. Identify the event sequence ProVerif found
2. Map it back to the Mermaid diagram steps
3. Determine if the attack is a real flaw or a modeling artifact

Common false attacks from modeling artifacts:
- **Type confusion**: Two bitstrings with compatible types where the model
  should use distinct types
- **Missing replication**: Single-session model allows trivial "man-in-middle"
  because the attacker is the only other party
- **Missing freshness binding**: Signature does not include the nonce/epk,
  so replay is possible at the model level even if the spec would bind it

When a result is `cannot be proved`, consider:
- Adding more specific type annotations
- Splitting the `!` replication into bounded sessions
- Switching to a weaker query first to establish partial results
