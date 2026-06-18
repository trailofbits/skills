---
name: unsafe-sync-impl-finder
description: Audits unsafe impl Send/Sync over types with interior mutability
---

**Finding ID Prefix:** `UNSAFESYNC`.

**Bug shape:** `unsafe impl Sync for MyStruct { }` where `MyStruct` contains a raw pointer or `UnsafeCell` whose mutation is not protected by a `Mutex`/`RwLock`/atomic.

**Gates:**

1. `unsafe impl (Send | Sync) for T` exists.
2. `T` contains at least one raw pointer field, `UnsafeCell`, or interior-mutable wrapper.
3. The methods on `T` taking `&self` mutate the interior without an internal synchronization primitive.

**FPs:**

- Interior mutation goes through `Atomic*`.
- All `&self` methods are read-only (only `&mut self` mutates — but that's Send/Sync-safe).
- `T` documents an invariant explaining external synchronization required (e.g., wrapper over single-threaded FFI handle).

**Search patterns:**

```
unsafe\s+impl\b.*\b(Send|Sync)\b\s+for
UnsafeCell|\bCell\b|\bRefCell\b
\*mut\s|\*const\s
```

The first pattern uses `impl\b.*\b(Send|Sync)\b` (not `impl\s+(Send|Sync)`) so it also matches the dominant generic forms `unsafe impl<T> Send for Wrapper<T>` and `unsafe impl<T: ?Sized> Sync for Box<T>`, where `<...>` sits between `impl` and the trait. The second/third lines seed Gate 2's raw-pointer / interior-mutable fields (`*mut`/`*const`, `Cell`/`RefCell`), not just `UnsafeCell`.
