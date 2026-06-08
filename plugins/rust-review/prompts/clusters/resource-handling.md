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
Grep: pattern="\b(from_raw_fd|into_raw_fd|as_raw_fd)\b"
Grep: pattern="\b(RawFd|OwnedFd|BorrowedFd)\b"
Grep: pattern="libc::(close|dup|dup2|open|pipe|socket)\b"
Grep: pattern="\b(RawHandle|RawSocket|from_raw_handle|into_raw_handle)\b"
Grep: pattern="\bmem::forget\b|\bManuallyDrop\b"
Grep: pattern="process::exit|libc::exit"
```

Run finders in declared order.
