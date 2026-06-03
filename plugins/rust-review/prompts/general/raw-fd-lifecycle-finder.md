---
name: raw-fd-lifecycle-finder
description: Detects raw file-descriptor double-close (double drop) and missing-close (leak) ownership errors
---

**Finding ID Prefix:** `RAWFD`.

**Bug shape:** `RawFd` is a bare `i32` — ownership is a convention, not a type. Two failure modes: **double-close**, where the same fd gets two closing owners (`from_raw_fd` called twice, or a borrowed/`as_raw_fd()` value fed into `from_raw_fd`) so the second `close` hits a recycled fd number now naming an unrelated resource (CWE-672; CWE-415 analog); and **missing-close (leak)**, where an fd from `into_raw_fd()`/`libc::open`/`dup`/`pipe` (or a `mem::forget`/`ManuallyDrop`'d `File`/`OwnedFd`) is never closed, exhausting the fd table -> DoS. Same logic for Windows `RawHandle`/`RawSocket`.

**Gates (double-close):**

1. A `RawFd`/`RawHandle` reaches `from_raw_fd`/`from_raw_handle` (takes ownership).
2. That fd is owned elsewhere too: a second `from_raw_fd`, the source `File`/`OwnedFd` is still live, or it came from `as_raw_fd()` (a borrow).
3. Both owners reach a close on a feasible path, with no `mem::forget`/`into_raw_fd` neutralizing one.

**Gates (leak):**

1. `into_raw_fd()` or a raw syscall (`open`/`dup`/`pipe`) yields an owned fd.
2. It is dropped as a plain integer, `mem::forget`'d, or its owner is `ManuallyDrop`'d, with no matching `close`/re-wrap on every path (including `?` and panic-unwind).

**FPs:**

- Code stays in `OwnedFd`/`File`/`BorrowedFd` (RAII closes once; borrows never close).
- `into_raw_fd()` immediately handed to another owner — ownership transferred, not leaked.
- `as_raw_fd()` used only as a syscall argument, never wrapped in an owner.
- `mem::forget`/`ManuallyDrop` paired with a documented FFI/owner handoff (`// SAFETY:`).

**Patch:** use `OwnedFd`/`BorrowedFd`/`File` and let RAII close once; transfer with `OwnedFd`, borrow with `BorrowedFd`/`AsFd`; if a raw fd must be held, wrap it in exactly one `OwnedFd` and convert via `From`/`Into` rather than re-deriving from `as_raw_fd()`.
