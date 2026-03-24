# ProVerif Syntax Reference

ProVerif models cryptographic protocols in the applied pi-calculus. This
reference covers the constructs needed to translate a Mermaid sequence diagram
into a verifiable `.pv` file.

---

## File Structure

A `.pv` file must follow this order:

```
1. Channel declarations (free c: channel. / free ch: channel [private].)
2. noselect directives (if needed for termination)
3. Type declarations
4. Constants
5. Function declarations
6. Equations / Reduction rules
7. Table declarations
8. Event declarations
9. Query declarations
10. Let process definitions
11. Main process (process ...)
```

Comments: `(* this is a comment *)` — no inline `//`.

---

## Types

ProVerif is strongly typed. The base type for any untyped byte sequence is
`bitstring`. Declare custom types to prevent confusing distinct key roles:

```proverif
type key.       (* symmetric key *)
type pkey.      (* public key (for enc or verify) *)
type skey.      (* secret key (for dec or sign) *)
type nonce.     (* random nonce *)
type tag.       (* MAC tag or signature *)
```

Types are structural — ProVerif does not enforce physical separation, but
type mismatches cause type errors that prevent verification.

---

## Constants

Declare fixed domain-separation labels or protocol identifiers:

```proverif
const msg1: bitstring.
const msg2: bitstring.
const info_handshake: bitstring.
const info_app: bitstring.
```

---

## Functions

### Declaring Functions

```proverif
fun name(arg_type1, arg_type2, ...): return_type.
```

Functions are **constructors** by default — the attacker can apply them freely.

```proverif
fun pk(skey): pkey.          (* derive public key *)
fun sign(bitstring, skey): bitstring.
fun aenc(bitstring, pkey): bitstring.
fun aead_enc(bitstring, key): bitstring.
fun mac(bitstring, key): bitstring.
fun hash(bitstring): bitstring.
fun hkdf(key, bitstring): key.
fun concat2(bitstring, bitstring): bitstring.
fun concat3(bitstring, bitstring, bitstring): bitstring.
```

For DH:

```proverif
fun dhpk(skey): pkey.           (* g^x given x *)
fun dh(skey, pkey): key.        (* g^(xy) given x and g^y *)
```

### Destructors

Destructors **can fail** — they extract values only when the rewrite rule
matches. Declare them with an inline `reduc` block:

```proverif
fun adec(bitstring, skey): bitstring
    reduc forall m: bitstring, k: skey;
        adec(aenc(m, pk(k)), k) = m.

fun aead_dec(bitstring, key): bitstring
    reduc forall m: bitstring, k: key;
        aead_dec(aead_enc(m, k), k) = m.

fun verify(bitstring, bitstring, pkey): bitstring
    reduc forall m: bitstring, k: skey;
        verify(sign(m, k), m, pk(k)) = m.
```

`verify` returns the verified message on success; the process **aborts** (that
branch is pruned) on failure. Use it as an abort-on-failure guard:

```proverif
let _ = verify(sig_R, msg, pk_R) in
(* reaches here only if sig_R is a valid signature under pk_R *)
```

**`equation` vs `reduc` — critical distinction:**

- A standalone `equation` block applies to **constructors** — functions
  declared with `fun` that the attacker can apply freely. Adding an equation
  does not make the function fail on mismatch; it only enables rewriting.
- An inline `reduc` block declares the function as a **destructor** that
  fails when no rewrite rule matches. This is what you want for `verify`,
  `adec`, `sdec`, and any check that must abort the process on failure.

Use `equation` only for algebraic identities on constructors (e.g., DH
commutativity). Use `reduc` for all cryptographic verification and decryption.

```proverif
(* Constructor + algebraic identity — equation is correct here *)
fun dh(skey, pkey): key.
equation forall a: skey, b: skey;
    dh(a, dhpk(b)) = dh(b, dhpk(a)).
```

**Note:** `bool` is not a valid return type for `fun` declarations in ProVerif.
Use `bitstring` (and return the message on success) or a custom type.

---

## Channels

All cross-party communication happens on channels:

```proverif
free c: channel.                    (* public channel — attacker can read and write *)
free priv_c: channel [private].     (* private channel — only declared code can use *)
```

The `free name: channel.` form declares `name` as a globally accessible
channel name. The `[private]` attribute prevents the attacker from learning
or using the channel.

For most protocol models, one public channel `c` is sufficient.

---

## Events

Events mark security-relevant points for use in authentication queries.

**Declaration:**

```proverif
event beginI(pkey, pkey).          (* pk_I, pk_R — before session key is known *)
event endI(pkey, pkey, key).       (* pk_I, pk_R, session_key *)
event beginR(pkey, pkey).
event endR(pkey, pkey, key).
```

**Use in process:**

```proverif
event beginI(pk(sk_I), pk_R);           (* fired before sending authenticated msg *)
event endI(pk(sk_I), pk_R, sk_session); (* fired after deriving session key *)
```

---

## Queries

### Secrecy

```proverif
query attacker(session_key).
```

Succeeds (i.e., ProVerif proves the protocol secure) if the attacker cannot
derive `session_key` in any execution.

For named secrets inside a process, use `query secret session_key.` inside the
process — but `query attacker(x)` at top level is cleaner for most use cases.

### Authentication (Correspondence)

**Weak**: A ran ==> B ran (allows replay):

```proverif
query x: pkey, y: pkey, k: key;
    event(endR(x, y, k)) ==> event(beginI(x, y)).
```

**Injective**: each B-accept corresponds to a unique A-run (prevents replay):

```proverif
query x: pkey, y: pkey, k: key;
    inj-event(endR(x, y, k)) ==> inj-event(beginI(x, y)).
```

### Reachability (sanity check)

Verify that the "success" point of the protocol is actually reachable (rules out
vacuously true results from trivially blocked processes):

```proverif
query x: pkey, y: pkey, k: key; event(endR(x, y, k)).
```

If this query returns `false` (unreachable), the protocol model is broken —
the endpoint never executes. Note: ProVerif does not support `_` wildcards in
`query` declarations; all parameters must be bound to typed variables.

---

## Processes

### Basic Syntax

```proverif
let ProcessName(param1: type1, param2: type2) =
    (* body *).
```

### Core Constructs

| Construct | Meaning |
|-----------|---------|
| `new x: T` | Generate fresh random value of type T |
| `out(c, term)` | Send term on channel c |
| `in(c, x: T)` | Receive a term of type T from channel c |
| `in(c, (x: T, y: U))` | Receive and destructure a tuple |
| `let x = term in P` | Bind term to x, continue with P |
| `let (x, y) = term in P` | Destructure tuple |
| `if t = u then P else Q` | Conditional |
| `if f(t) = true then P` | Destructor check |
| `event e(args)` | Trigger event |
| `P \| Q` | Parallel composition |
| `!P` | Replicate P (unbounded concurrent sessions) |
| `0` | Terminated process |

### Receiving and Destructuring

When a message contains multiple components separated by a comma in the
Mermaid diagram, receive as a tuple:

```proverif
in(c, (epk_R: pkey, sig_R: bitstring));
```

For concatenated values (e.g., `A || B`), model as a tuple `(a, b)` unless the
protocol computes over the concatenated bytes specifically:

```proverif
(* sender *)
out(c, (epk_R_bytes, sig_R));

(* receiver *)
in(c, (epk_R_bytes: pkey, sig_R: bitstring));
```

If the protocol requires an explicit concat (e.g., hashing a concatenation),
declare a constructor:

```proverif
fun concat(bitstring, bitstring): bitstring.
out(c, concat(epk_R_bytes, sig_R));
```

### Verification Checks

Map each `Verify(pk, msg, sig)` annotation to a `let _ = ... in` destructor
call. The destructor fails and aborts the branch when the signature is invalid:

```proverif
let _ = verify(sig_R, (msg2_label, epk_I, epk_R), pk_R) in
(* reaches here only if sig_R is a valid signature under pk_R *)
(* else: branch is pruned — models abort on invalid signature *)
```

The `else` branch is implicit; ProVerif prunes the branch on destructor failure.

### Example: Two-Party Process

```proverif
let Initiator(sk_I: skey, pk_R: pkey) =
    new ek_I: skey;
    let epk_I = dhpk(ek_I) in
    let sig_I = sign((msg1, epk_I), sk_I) in
    event beginI(pk(sk_I), pk_R);    (* session key not yet known *)
    out(c, (epk_I, sig_I));

    in(c, (epk_R: pkey, sig_R: bitstring));
    let transcript = concat2(pkey2bs(epk_I), pkey2bs(epk_R)) in
    let _ = verify(sig_R, concat2(msg2, transcript), pk_R) in
    let dh_val = dh(ek_I, epk_R) in
    let sk_session = hkdf(dh_val, concat2(info_session, transcript)) in
    event endI(pk(sk_I), pk_R, sk_session).
```

---

## Main Process

```proverif
process
    new sk_I: skey; let pk_I = pk(sk_I) in out(c, pk_I);
    new sk_R: skey; let pk_R = pk(sk_R) in out(c, pk_R);
    (
        !Initiator(sk_I, pk_R)
      | !Responder(sk_R, pk_I)
    )
```

**Replication `!`** allows arbitrarily many concurrent sessions — essential
for ProVerif to detect replay and man-in-the-middle attacks.

**Long-term key publication** (`out(c, pk_I)`) is mandatory: the Dolev-Yao
attacker must know public keys to attempt attacks.

---

## Tables

ProVerif tables provide shared mutable state across parallel processes — the
only built-in mechanism for synchronizing information between two `let`
processes that run concurrently.

### Declaration

```proverif
table myTable(bitstring, bitstring).   (* two bitstring columns *)
table accepted(bitstring, bitstring).  (* e.g. (session_id, sas) *)
table sessionKeys(bitstring, key).     (* (nonce, derived_key) *)
```

### Insert a row

```proverif
insert myTable(key1, value1);
```

### Read a row

```proverif
get myTable(=key1, x: bitstring) in
    (* x is bound to value1 when the first column equals key1 *)
    ...
```

`=key1` is a pattern-match constraint (first column must equal `key1`).
Bare names like `x: bitstring` capture the column value for use in the body.

**Semantics:** `get T(...) in P` succeeds for every matching row. If no row
matches, the process terminates (that branch is pruned). If multiple rows
match, ProVerif considers all branches.

### When to use tables

| Use tables | Use private channels |
|------------|----------------------|
| Reader determines the lookup key | Writer pushes to a known recipient |
| Fan-in: wait for multiple writers | Point-to-point signal |
| Cross-check: two processes verify agreement on a value | Callback: one-shot reply |

**Typical pattern — coordination between parallel processes:**

```proverif
table accepted(bitstring, bitstring).    (* (nonce, sas) *)

(* Party A: records user acceptance *)
insert accepted(nonce_new, sas);

(* Party B: checks that A recorded acceptance before proceeding *)
get accepted(=nonce_new, =sas) in
    event partyB_accept(...);
    ...
```

---

## `noselect` — Termination Hints

ProVerif's Horn clause solver may not terminate on models with complex tuple
patterns on the public channel. The `noselect` directive restricts which
clauses the solver selects during proof search. It is a **performance hint
only** — it does not restrict what the attacker can send or receive.

### Syntax

```proverif
noselect x: bitstring, y: bitstring; mess(c, (x, y)).
```

This tells ProVerif: "do not select clauses that derive a pair `(x, y)` from
channel `c`." The `mess(c, t)` predicate means "term `t` is on channel `c`."

### When to add

If ProVerif runs for several minutes without terminating on a model with:
- Many concurrent sessions (`!` replication on multiple processes)
- Pair-typed messages on the public channel (tuples sent over `c`)

Then add a `noselect` hint matching the tuple structure of messages on `c`.
For a protocol where all messages are pairs, use:

```proverif
noselect x: bitstring, y: bitstring; mess(c, (x, y)).
```

For triple-element messages:

```proverif
noselect x: bitstring, y: bitstring, z: bitstring; mess(c, (x, y, z)).
```

### Placement

Add immediately after channel declarations, before type and function
declarations. `noselect` is parsed as a query-level directive and must appear
before the `process` block. Placing it early (after channels) keeps it
visible alongside the declarations it constrains.

---

## Common Pitfalls

### Pitfall 1: Type Mismatch

`dh(ek_I, epk_R)` requires `ek_I: skey` and `epk_R: pkey`. If you declared
both as `bitstring`, the equation `dh(sk_a, dhpk(sk_b)) = dh(sk_b, dhpk(sk_a))`
cannot fire. Keep types strict.

### Pitfall 2: Missing Replication

Without `!` in the main process, ProVerif only checks single-session security.
Always use `!Initiator(...)` and `!Responder(...)` to allow multiple sessions.

### Pitfall 3: Attacker Cannot Reach End Event

If the reachability query `query event(endR(...))` returns false, the protocol
process is stuck — usually due to a type error in `in(c, ...)` destructuring
or an `if` condition that never holds. Debug by simplifying the process to just
the `out`/`in` steps without guards, confirm reachability, then add guards
back one at a time.

### Pitfall 4: Equations Cause Non-Termination

The DH commutativity equation `dh(sk_a, dhpk(sk_b)) = dh(sk_b, dhpk(sk_a))`
is convergent. Arbitrary equations with cycles (e.g., `f(f(x)) = x`) can
cause ProVerif to loop. Stick to the standard primitives in the mapping table.

### Pitfall 5: Secrets Must Be `new` Inside Process

Do not use `new` in the main process for values that should be per-session
secrets — they would be shared across all replications. Generate per-session
secrets inside the participant `let` process.

```proverif
(* WRONG — shared across all sessions *)
new sk_session: key;
!Initiator(sk_session, ...)

(* RIGHT — fresh per session *)
let Initiator(...) =
    ...
    let sk_session = hkdf(...) in   (* derived, not new *)
    ...
```

### Pitfall 6: Queries Reference Undeclared Events

Every event name used in a `query` must be declared with `event name(types).`.
Missing declarations cause a parse error.
