---
name: cluster-memory-safety
kind: cluster
consolidated: false
covers:
  - use-after-free      # UAF
  - double-free         # DFREE
  - invalid-free        # INVFREE
  - uninitialized-read  # UNINITREAD
  - vec-set-len-uninit  # SETLEN
  - buffer-overflow-unsafe # BOF
  - union-ub             # UNIONUB
  - panic-unwind-unsafe  # PANICUNWIND
---

# Cluster: Memory safety (unsafe code)

Rust memory-safety bugs ALWAYS originate from `unsafe` code. Per empirical study, 70 production memory-safety bugs all had a propagation chain across the safe/unsafe boundary. The sub-passes share one mental model: **for each unsafe block, who owns the memory, when does it Drop, and who else points at it?**

ID prefixes: `UAF`, `DFREE`, `INVFREE`, `UNINITREAD`, `SETLEN`, `BOF`, `UNIONUB`, `PANICUNWIND`.

Cluster gate `has_unsafe` — when `has_unsafe=false`, the orchestrator drops this entire cluster before spawn (the manifest gates the whole cluster, not each pass).

---

## Phase A — Build the unsafe-memory map (ONCE per run)

Run these scans:

```
Grep: pattern="\bunsafe\s*\{"
Grep: pattern="\.(as_ptr|as_mut_ptr|into_raw|from_raw)\("
Grep: pattern="\bptr::(read|write|copy(_nonoverlapping)?|drop_in_place|offset|add|sub)\b"
Grep: pattern="\.(add|sub|offset|read|write|copy_to|copy_from|copy_to_nonoverlapping|copy_from_nonoverlapping)(_unaligned|_volatile)?\s*\("  # raw-pointer METHOD form (p.read(), p.add(i)) — complements the ptr:: free-fn line above
Grep: pattern="\b(get_unchecked(_mut)?)\s*\("
Grep: pattern="\bMaybeUninit::(<[^>]*>::)?(assume_init|uninit|new|zeroed)|\.assume_init(_read|_mut|_ref)?\s*\("  # turbofish MaybeUninit::<T>::uninit() and the .assume_init() method form
Grep: pattern="\b(mem::uninitialized|mem::zeroed|mem::transmute|mem::forget|ManuallyDrop::)"
Grep: pattern="\b(alloc|dealloc|realloc)\s*\(|\balloc::(alloc|dealloc|realloc)\b"  # allocator calls: bare/imported `dealloc(p, layout)`, method `.dealloc(`, and fully-qualified `std::alloc::dealloc`
Grep: pattern="\bunion\s+\w+\b"
Grep: pattern="\bset_len\s*\(|\bfrom_raw_parts\s*\(|\bspare_capacity_mut\s*\("
Grep: pattern="drop_in_place|catch_unwind"
```

Record `mem_map[site] = { kind, type, owner_var, lifetime_scope, drop_site }`.

Then read each finder below and apply against `mem_map`.

---

## Phase B — Run finders in order

1. **`UNINITREAD` — Uninitialized read** — prerequisite for INVFREE/UAF (uninit memory can't be freed correctly).
2. **`SETLEN` — Vec length without init** — `set_len` / `from_raw_parts` exposes uninitialized slots through safe APIs; often co-occurs with UNINITREAD on `MaybeUninit` paths but files at the vec init gap.
3. **`INVFREE` — Invalid free via assignment-to-uninit** — `*ptr = val` where `ptr` is uninitialized triggers Drop on garbage.
4. **`UAF` — Use-after-free via dangled raw pointer** — pointer outlives implicit Drop scope.
5. **`DFREE` — Double free via `ptr::read`** — non-Copy heap type duplicated.
6. **`BOF` — Buffer overflow via flawed index** — safe-side arithmetic into `unsafe` unchecked access.
7. **`UNIONUB` — Union variant misread or aliasing** — reading a union field whose validity invariants are not proven for the currently-active variant, or taking a reference into one field while another owned field is live.
8. **`PANICUNWIND` — Panic during unsafe container mutation** — stale `len`/capacity across unwind → second `Drop`/`clear` (UAF/double-free class via metadata, not dangling pointer alone).

---

## Deconfliction

- `INVFREE` > `UAF` if the freed memory was uninitialized (root cause is missing init, not stale pointer).
- `UAF` > `DFREE` if a single pointer dereferenced after free; `DFREE` requires two distinct Drop calls.
- `SETLEN` > `UNINITREAD` when the bug is specifically `Vec::set_len` / `from_raw_parts` without slot init (not `assume_init` on a struct field).
- `UNINITREAD` is independent when `MaybeUninit::assume_init` is the sole failure mode.
- `BOF` is independent (different mechanic).
- `UNIONUB` is independent of `UNINITREAD`/`INVFREE`: it concerns *misinterpretation* of valid bytes, not absence of init.
- `PANICUNWIND` > `DFREE`/`UAF` when unwind leaves container metadata describing already-dropped elements; `DFREE`/`UAF` without a panic on the mutation path.
- `PANICUNWIND` vs `DROPPANIC` (error-handling): container bookkeeping across unwind vs panic inside `impl Drop for T` itself.
- `PANICUNWIND` vs `CLOSUREPANIC` (logic-correctness): user `Fn` between two pointer ops vs custom vec-like `len` not committed before `drop_in_place`.

Build `mem_map` ONCE.
