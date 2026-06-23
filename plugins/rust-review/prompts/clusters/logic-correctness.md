---
name: cluster-logic-correctness
kind: cluster
consolidated: false
covers:
  - ord-eq-hash                # ORDEQHASH
  - adversarial-trait          # TRAITADV
  - closure-panic              # CLOSUREPANIC
  - float-edge                 # FLOATEDGE
  - string-comparison          # STRCMP
  - serialize-struct-mismatch  # SERFIELDS
  - nondeterminism             # NONDET
  - collection-key-mutation    # KEYMUT
---

# Cluster: Logic correctness

ID prefixes: `ORDEQHASH`, `TRAITADV`, `CLOSUREPANIC`, `FLOATEDGE`, `STRCMP`, `SERFIELDS`, `NONDET`, `KEYMUT`.

## Phase A

```
rg seed: "impl\b[^{]*?\b(Ord|PartialOrd|Eq|PartialEq|Hash)\b[^{]*\bfor\b"  # hand impls incl. generic `impl<T> Ord for W<T>` and `impl PartialOrd<Other> for Foo`
rg seed: "#\[derive\([^)]*\b(Ord|PartialOrd|Eq|PartialEq|Hash)\b"          # derived — a hand/derive split across these traits is a common inconsistency source
rg seed: "\b(f32|f64)\b"
rg seed: "<\s*\w+\s*:\s*[A-Z]"  # generic trait bounds
rg seed: "\bcatch_unwind\b"
rg seed: "\bFn(Once|Mut)?\b|\bptr::(read|write)\b|\bdrop_in_place\b"  # closure-accepting bounds + pointer ops → CLOSUREPANIC unsafe windows
rg seed: "\b(starts_with|ends_with|contains)\b"
rg seed: "eq_ignore_ascii_case|to_lowercase|to_uppercase|to_ascii_lowercase|to_ascii_uppercase"  # case-folding → STRCMP case-mixing
rg seed: "serialize_(struct|tuple|seq|map)\("
rg seed: "\bHashMap\b|\bHashSet\b"
rg seed: "peek_mut|RefCell\b|Cell\b"
```

## Phase B — Run finders in order

Apply each pass against the Phase-A inventory; detailed detection + FP guidance live in the per-class finder files (do not re-derive them here).

1. **`ORDEQHASH` — ord-eq-hash** — hand `Ord`/`PartialOrd`/`Eq`/`PartialEq`/`Hash` impls that violate the consistency contracts (incl. a hand/derive split across them). Seed: the `impl … for` and `#[derive(…)]` greps.
2. **`TRAITADV` — adversarial-trait** *(requires `has_unsafe`)* — a hostile generic trait impl breaks an invariant an `unsafe` block relies on. Seed: generic trait bounds.
3. **`CLOSUREPANIC` — closure-panic** *(requires `has_unsafe`)* — a user closure invoked between two pointer ops panics and leaves an `unsafe` scaffold inconsistent. Seed: `Fn`/`FnMut`/`FnOnce` bounds + `ptr::read`/`ptr::write`/`drop_in_place` windows, `catch_unwind`.
4. **`FLOATEDGE` — float-edge** — NaN/Inf comparison or ordering edge cases (e.g. saturating `f64 as usize`). Seed: `f32` / `f64`.
5. **`STRCMP` — string-comparison** — partial / case-insensitive comparison bypasses a check. Seed: `starts_with`/`ends_with`/`contains` + case-folding (`eq_ignore_ascii_case`, `to_lowercase`, …).
6. **`SERFIELDS` — serialize-struct-mismatch** — `serialize_struct(len)` (or `serialize_tuple`/`serialize_seq(Some(N))`/`serialize_map(Some(N))`) field-count disagreement corrupts output. Seed: `serialize_struct(`/`serialize_tuple(`/`serialize_seq(`/`serialize_map(`.
7. **`NONDET` — nondeterminism** — `HashMap`/`HashSet` iteration or hashing introduces nondeterminism in replicated/consensus state. Seed: `HashMap` / `HashSet`.
8. **`KEYMUT` — collection-key-mutation** — mutating a key or heap element already stored in a map/set/heap breaks its ordering/hash invariant. Seed: `peek_mut` / `RefCell` / `Cell`.

## Deconfliction

- `ORDEQHASH` vs `KEYMUT`: a *broken* `Ord`/`Hash` impl is `ORDEQHASH`; mutating an otherwise-correct key already inside a collection is `KEYMUT`.
- `FLOATEDGE` vs `ORDEQHASH`: a NaN-induced `PartialOrd` surprise at a use site is `FLOATEDGE`; a hand `Ord` impl that is internally inconsistent is `ORDEQHASH`.
- `NONDET` vs `KEYMUT`: nondeterministic *iteration order* is `NONDET`; in-place *key mutation* breaking lookup is `KEYMUT`.
- `CLOSUREPANIC` (here) vs `PANICUNWIND` (memory-safety): a user `Fn` panicking between two pointer ops vs container metadata left stale across unwind.
