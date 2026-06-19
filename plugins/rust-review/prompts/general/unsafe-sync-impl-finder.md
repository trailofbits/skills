---
name: unsafe-sync-impl-finder
description: Audits unsafe impl Send/Sync over types with interior mutability
---

**Finding ID Prefix:** `UNSAFESYNC`.

**Bug shape:** a manual `unsafe impl Send`/`Sync for MyStruct {}` overrides the auto-derived `!Send`/`!Sync` of a payload that is not actually thread-safe — a raw pointer, `UnsafeCell`, or a handle to non-thread-safe foreign state. The unsoundness can come from **either** unsynchronized interior mutation through `&self`, **or** simply making a non-thread-safe payload transferable (`Send`) / shareable (`Sync`) across threads with **no Rust-side mutation at all** (e.g. `struct W(*mut CHandle); unsafe impl Send for W {}` over a single-threaded C handle).

**Gates:**

1. `unsafe impl (Send | Sync) for T` exists.
2. `T` contains at least one field that is **not** auto-`Send`/`Sync`: a raw pointer (`*mut`/`*const`), `NonNull`, `UnsafeCell`/`Cell`/`RefCell`, `Rc`, a `MutexGuard`, or any other `!Send`/`!Sync` type (e.g. an FFI handle). It need not be a literal raw pointer — `struct W(NonNull<CHandle>)` / `struct W(Rc<u32>)` are the common real shapes.
3. At least **one** of: (a) `T`'s `&self` methods mutate the interior without internal synchronization; **or** (b) `T` holds a raw pointer / non-`Send` / non-`Sync` field and the manual impl lets that payload be transferred (`Send`) or shared (`Sync`) across threads without the wrapped resource being thread-safe — **no `&self` mutation required**. Treat the test as "the auto-derived `!Send`/`!Sync` was overridden without a justifying invariant", not strictly "mutation through `&self`".

**FPs:**

- Interior mutation goes through `Atomic*`.
- The payload is genuinely thread-safe for the trait being impl'd (every field is itself `Send`/`Sync`, or interior mutation goes through an atomic/`Mutex`/`RwLock`), making the manual impl redundant rather than unsound. (Note: confining mutation to `&mut self` does **not** by itself make a manual `unsafe impl Send`/`Sync` sound — `Sync` concerns shared `&self` access to a possibly non-thread-safe payload and `Send` concerns transfer, neither of which requires `&self` mutation.)
- `T`'s manual impl is justified by an invariant that is **actually enforced for all safe uses** — not merely documented. `unsafe impl Send`/`Sync` grants the capability to *all* safe code, so a `// SAFETY:`/doc comment alone does **not** make it sound: a bare `*mut CHandle` wrapper that safe code can freely construct and move across threads is still unsound *even with* a "caller must use one thread" comment (that is the bug shape above, not an FP). The invariant counts only when the type's API upholds it — e.g. the sole constructor is `unsafe` (shifting the obligation to callers), or every access is gated behind a `Mutex`/`RwLock`/atomic the wrapper owns. Verify enforcement, not the mere presence of a comment.

**Search patterns:**

```
unsafe\s+impl\b.*\b(Send|Sync)\b\s+for
UnsafeCell|\bCell\b|\bRefCell\b|\bNonNull\b|\bRc<|\bMutexGuard\b
\*mut\s|\*const\s
```

The first pattern uses `impl\b.*\b(Send|Sync)\b` (not `impl\s+(Send|Sync)`) so it also matches the dominant generic forms `unsafe impl<T> Send for Wrapper<T>` and `unsafe impl<T: ?Sized> Sync for Box<T>`, where `<...>` sits between `impl` and the trait. The second/third lines seed Gate 2's raw-pointer / interior-mutable fields (`*mut`/`*const`, `Cell`/`RefCell`), not just `UnsafeCell`.

**Recommendation:** remove the manual `unsafe impl` and let the type stay `!Send`/`!Sync`; or make the payload genuinely thread-safe (wrap mutation in `Mutex`/`RwLock`/atomics, or replace the raw pointer with a `Send`/`Sync` type); or, if the impl is truly required, document the exact synchronization invariant the caller must uphold and why it justifies overriding the auto trait.
