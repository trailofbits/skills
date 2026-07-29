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
rg seed: "\bAtomic(Bool|Usize|U8|U16|U32|U64|I8|I16|I32|I64|Isize|Ptr)\b"
rg seed: "\bunsafe\s+impl\b.*\b(Send|Sync)\b"  # tolerates generic `unsafe impl<T> Send for W<T>` (the `<...>` sits between impl and Send/Sync)
rg seed: "(Send|Sync)\s+for\s+\w"
rg seed: "\b(load|store|swap|fetch_(add|sub|or|and|xor|nand|max|min|update)|compare_(exchange(_weak)?|and_swap))\b"  # incl. swap / fetch_update / fetch_max|min — common RMW + CAS-loop sites
rg seed: "\bMAP_SHARED\b|memmap2::MmapMut|shm_open|memfd_create|CreateFileMapping"
rg seed: "\bstatic\s+mut\b"
rg seed: "&raw\s+(const|mut)\s+|addr_of_mut!|thread::spawn|tokio::spawn|rayon::spawn"
```

Run finders in declared order: `ATOMICRACE`, `UNSAFESYNC`, `SENDSYNCBOUND`, `SHMRACE`, `STATICMUT`.

## Deconfliction

- `STATICMUT` vs `ATOMICRACE`: unsynchronized `static mut` (or raw access to it) vs incorrect `Atomic*` sequencing — file both if both apply at different sites.
- `STATICMUT` vs `UNSAFESYNC`: `static mut` race is not fixed by an unsound `Sync` impl on a wrapper; prefer `STATICMUT` at the `static mut` site.
- `SHMRACE` vs `STATICMUT`: cross-process mmap vs in-process `static mut` — different trust boundaries.
- `UNSAFESYNC` vs `SENDSYNCBOUND`: a manual `unsafe impl Send`/`Sync` *definition* over a non-thread-safe payload is `UNSAFESYNC`; `SENDSYNCBOUND` only files when a missing bound is laundered across threads by an `unsafe` spawn primitive / `transmute` (not by the manual impl itself). When a single `unsafe impl Send for W {}` both exists and lets its value cross a thread, file `UNSAFESYNC` at the impl site; do not double-file `SENDSYNCBOUND` for the same impl.
