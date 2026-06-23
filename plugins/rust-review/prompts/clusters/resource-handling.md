---
name: cluster-resource-handling
kind: cluster
consolidated: false
covers:
  - raw-fd-lifecycle # RAWFD
  - destructor-skip  # DROPSKIP
---

# Cluster: Resource and destructor handling

Non-memory OS resources (file descriptors, handles, sockets) and values whose `Drop` performs security-relevant cleanup (secrets, connections, transactions) follow the same ownership discipline as heap memory: every destructor runs exactly once on every exit path.

ID prefixes: `RAWFD`, `DROPSKIP`.

## Phase A

```
rg seed: "\b(from_raw_fd|into_raw_fd|as_raw_fd)\b"
rg seed: "\b(RawFd|OwnedFd|BorrowedFd)\b"
rg seed: "libc::(close|dup|dup2|open|pipe|socket)\b"
rg seed: "\b(RawHandle|RawSocket|from_raw_handle|into_raw_handle)\b"
rg seed: "\bmem::forget\b|\bManuallyDrop\b"
rg seed: "process::exit|libc::exit"
```

Run finders in declared order.

## Deconfliction

- `RAWFD` vs `DROPSKIP`: a file descriptor / handle / socket whose lifecycle is mishandled (double-close, leak, `from_raw_fd` without ownership transfer) is `RAWFD`. Any *other* security-relevant `Drop` skipped via `mem::forget` / `ManuallyDrop` / `process::exit` (secrets, connections, transactions, locks) is `DROPSKIP`. When a `mem::forget` / `ManuallyDrop` / `exit` strands an fd-backed value (`OwnedFd`, `File`, `TcpStream`), file `RAWFD` — the fd leak is the precise bug — and do **not** also file `DROPSKIP` for the same site.
- Foreign-allocator free mismatch on FFI-owned memory is `FOREIGNDROP` (ffi-cross-language cluster), not `RAWFD`/`DROPSKIP`.
