---
name: cluster-concurrency-data-race
kind: cluster
consolidated: false
covers:
  - atomic-race        # ATOMICRACE
  - unsafe-sync-impl   # UNSAFESYNC
  - send-sync-bounds   # SENDSYNCBOUND
  - shared-memory-race # SHMRACE
  - static-mut-race    # STATICMUT
---

# Cluster: Concurrency — data races

A significant share of non-blocking concurrency bugs in Rust occur entirely in **safe code** via misuse of `Atomic*` primitives. Unsafe `Sync` impls add a second front. Cross-process shared memory (`MAP_SHARED`/`shm_open`/`memfd`) adds a third: Rust's aliasing model assumes the process owns its address space, so a `&mut T` borrow into a region another process can write is unsound regardless of intra-process synchronization. **`static mut`** is a fourth: process-wide unsynchronized mutation (including `&raw mut` / `ptr::read` paths that never form a reference).

ID prefixes: `ATOMICRACE`, `UNSAFESYNC`, `SENDSYNCBOUND`, `SHMRACE`, `STATICMUT`.

## Phase A — Inventory

```
Grep: pattern="\bAtomic(Bool|Usize|U8|U16|U32|U64|I8|I16|I32|I64|Isize|Ptr)\b"
Grep: pattern="\bunsafe\s+impl\s+(Send|Sync)\b"
Grep: pattern="(Send|Sync)\s+for\s+\w"
Grep: pattern="\b(load|store|fetch_(add|sub|or|and|xor)|compare_(exchange(_weak)?|and_swap))\b"
Grep: pattern="\bMAP_SHARED\b|memmap2::MmapMut|shm_open|memfd_create|CreateFileMapping"
Grep: pattern="\bstatic\s+mut\b"
Grep: pattern="&raw\s+(const|mut)\s+|addr_of_mut!|thread::spawn|tokio::spawn|rayon::spawn"
```

Run finders in declared order: `ATOMICRACE`, `UNSAFESYNC`, `SENDSYNCBOUND`, `SHMRACE`, `STATICMUT`.

## Deconfliction

- `STATICMUT` vs `ATOMICRACE`: unsynchronized `static mut` (or raw access to it) vs incorrect `Atomic*` sequencing — file both if both apply at different sites.
- `STATICMUT` vs `UNSAFESYNC`: `static mut` race is not fixed by an unsound `Sync` impl on a wrapper; prefer `STATICMUT` at the `static mut` site.
- `SHMRACE` vs `STATICMUT`: cross-process mmap vs in-process `static mut` — different trust boundaries.
