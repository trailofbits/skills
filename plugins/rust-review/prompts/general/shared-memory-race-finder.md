---
name: shared-memory-race-finder
description: Detects unsynchronized cross-process access to shared memory regions (MAP_SHARED mmap, shm_open, memfd)
---

**Finding ID Prefix:** `SHMRACE`.

**Bug shape:** Rust's memory model assumes the process has exclusive control of its address space. When a region is mapped `MAP_SHARED` with another process, another container, or another mapping of the same `shm_open`/`memfd_create` object, ordinary `&mut T` borrows are unsound — another writer may modify the bytes mid-borrow. Atomic types accessed across processes additionally require both processes to use compatible memory orderings and matching layouts. The only sound access pattern is via raw pointers or `UnsafeCell` with appropriate atomic primitives and `// SAFETY:` reasoning that names the peer process and its synchronization protocol.

**Verification gates (ALL must pass):**

1. **Shared mapping site:** call to `libc::mmap`/`nix::sys::mman::mmap` with `MAP_SHARED` (not `MAP_PRIVATE`); or `shm_open`, `memfd_create`, `posix_ipc`, `shared_memory` crate, `raw_sync`, `memmap2::MmapMut::map_mut` on a shared file, or Windows `CreateFileMapping` + `MapViewOfFile`.
2. **Cast to safe Rust reference:** the resulting pointer is reinterpreted as `&T`/`&mut T`/`&[T]`/`&mut [T]`/`Box<T>`, or wrapped in a type that exposes safe `Deref`/`DerefMut` (e.g., `MmapMut` direct deref into a Rust struct).
3. **No synchronization protocol:** the reads/writes are not gated by an inter-process primitive (file lock via `flock`/`fcntl`, named semaphore, pthread shared mutex with `PTHREAD_PROCESS_SHARED`, futex on the shared region, atomic CAS protocol with documented ordering).
4. **No `// SAFETY:` invariant naming the peer:** the unsafe access lacks a `// SAFETY:` block that identifies the peer process and explains why concurrent access is sound (e.g., "single-writer, lock-free SPMC queue with `Release`/`Acquire` on the head pointer").

**FPs to reject:**

- `MAP_PRIVATE` mappings — copy-on-write, single-process.
- Memory-mapped read-only files used as input data (no writer process).
- `Mmap` (immutable) over a file that the same process opens exclusively.
- Sites that use only `AtomicU*`/`AtomicPtr` with documented orderings AND a `// SAFETY:` that names the peer protocol.

**Search patterns:**

```
\bMAP_SHARED\b|libc::mmap|memmap2::MmapMut|shm_open|memfd_create
\bshared_memory\b|\braw_sync\b|posix_ipc
CreateFileMapping|MapViewOfFile
PTHREAD_PROCESS_SHARED
```

For each hit, find the deref/cast site and check gates.

**Patch:** wrap the region in `UnsafeCell<MaybeUninit<T>>` and access it exclusively through atomic primitives with documented orderings AND an inter-process lock or lock-free protocol; add a `// SAFETY:` comment naming the peer process. For pure data exchange, prefer message-passing IPC (Unix socket, pipe) over shared memory.
