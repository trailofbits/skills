---
name: cluster-panic-dos
kind: cluster
consolidated: false
covers:
  - resource-exhaustion  # RESEXHAUST
  - unwrap-on-untrusted  # UNWRAP
  - arithmetic-overflow  # ARITHOFL
  - assertion-reachable  # ASSERTREACH
  - out-of-bounds-index  # OOBIDX
  - str-slice-boundary   # STRSLICE
  - refcell-borrow-panic # REFCELLPANIC
---

# Cluster: Panic-induced DoS and availability

Rust panics terminate the thread (or process under `panic = "abort"`). On servers, an attacker-triggered panic is a DoS. **`RESEXHAUST` runs first:** CPU/RAM exhaustion via unbounded loops, O(n²) work, or uncapped `Vec::reserve` often leaves the process alive (no panic) — a distinct availability class from abort-on-panic.

ID prefixes: `RESEXHAUST`, `UNWRAP`, `ARITHOFL`, `ASSERTREACH`, `OOBIDX`, `STRSLICE`, `REFCELLPANIC`.

## Phase A — Profile gate (do this first)

Arithmetic-overflow panics (`a + b`, `a - b`, `a * b`, `-a`, `a << b`) are conditional on `overflow-checks`. Default: `true` in debug, `false` in release. Check the target profile before scoring `ARITHOFL` findings:

```
Grep: pattern="overflow-checks\s*=" path="**/Cargo.toml"
```

- If `overflow-checks = true` on the relevant profile (often `[profile.release]` in security-sensitive crates — Solana programs, Substrate runtimes, etc.): plain `+ - *` are panic candidates.
- If unset or `false` on release: plain `+ - *` wrap silently in release builds — **not** a panic-DoS, but may still be a logic/correctness bug (route to `cluster-logic-correctness`).

**Unconditional arithmetic panics** (fire regardless of `overflow-checks`, score these always):
- `/` or `%` by zero
- `i::MIN / -1`, `i::MIN % -1`
- Shift by ≥ bit-width (panics in debug; masked in release — debug-only DoS)

## Phase B — Resource exhaustion inventory (RESEXHAUST)

```
Grep: pattern="(Vec|String|BytesMut|VecDeque)::(with_capacity|reserve)\s*\("
Grep: pattern="\.resize\s*\(|vec!\[[^;]+;\s*\w+\]|repeat\s*\("
Grep: pattern="unbounded(_channel)?|async_channel::unbounded|crossbeam.*unbounded"
Grep: pattern="for\s+\w+\s+in\s+0\.\.|while\s+.*\.len\(\)|loop\s*\{"
```

Trace whether capacity/index/count is tainted from decode/parse of external input.

## Phase C — Panic inventory

```
Grep: pattern="\.unwrap(_err)?\s*\(\s*\)|\.expect\s*\("
Grep: pattern="(panic!|todo!|unimplemented!|unreachable!|assert(_eq|_ne)?!)\s*\("
Grep: pattern="\bas\s+(u\d+|i\d+|usize|isize)\b"
Grep: pattern="\[\s*\w+\s*\]"  # bracket indexing
Grep: pattern="[^/\w](/|%)[^/=]"  # division / modulo — unconditional panic on zero
Grep: pattern="\[[^\]]*\.\.[^\]]*\]|\.split_at(_mut)?\s*\(|\.truncate\s*\("  # str range-slice / split_at / truncate — char-boundary panic
Grep: pattern="RefCell|\.borrow_mut\s*\("
Grep: pattern="\.try_borrow_mut\s*\(\s*\)\s*\.(unwrap(_err)?|expect)\s*\("  # try_borrow_mut().unwrap()/expect() re-introduces the panic
```

**Negative-signal grep (sites already hardened, skip for `ARITHOFL`):**

```
Grep: pattern="\b(checked|saturating|wrapping|overflowing)_(add|sub|mul|div|shl|shr|neg|pow)\b"
```

These methods never panic on overflow — they're the explicit non-panicking alternatives. Use this grep to *exclude* hardened sites from the arithmetic inventory, not to find panic candidates. (One exception: `checked_*().unwrap()` chains — those re-introduce a panic and should fall out of the `unwrap` grep above.)

## Deconfliction

- `RESEXHAUST` vs `ARITHOFL`: allocation/loop DoS vs integer overflow panic — different mechanics; both may cite the same untrusted `n` but file separately when both apply.
- `RESEXHAUST` vs `RECURSEDES` / `RECURSEFMT` / `RECURSEDROP` (recursion-dos): stack exhaustion from depth, not CPU/RAM amplification in safe loops.
- `RESEXHAUST` vs `TRAITADV`: untrusted length into safe `Vec::reserve` files here; untrusted trait return into `unsafe`/`set_len` files at `TRAITADV` / `SETLEN`.
- `OOBIDX` owns integer-index OOB on `Vec`/`[T]`; `STRSLICE` owns `str` range-slice / `split_at` / `truncate` panics where the byte index lands off a UTF-8 char boundary (a panic that fires even *in bounds*).
- `REFCELLPANIC` owns single-threaded interior-mutability borrow panics; a borrow panic inside `Drop` routes to `DROPPANIC`; cross-thread/callback reentrancy routes to the concurrency-locking reentrancy classes.

Run finders in declared order: `RESEXHAUST` first, then panic passes.
