---
name: cluster-resource-handling
kind: cluster
consolidated: false
covers:
  - raw-fd-lifecycle # RAWFD
---

# Cluster: OS resource handling

Non-memory OS resources (file descriptors, handles, sockets) follow the same ownership discipline as heap memory: exactly one owner, closed exactly once. This cluster inventories raw-handle sites and checks each for double-close and leak.

ID prefixes: `RAWFD`.

## Phase A

```
Grep: pattern="\b(from_raw_fd|into_raw_fd|as_raw_fd)\b"
Grep: pattern="\b(RawFd|OwnedFd|BorrowedFd)\b"
Grep: pattern="libc::(close|dup|dup2|open|pipe|socket)\b"
Grep: pattern="\b(RawHandle|RawSocket|from_raw_handle|into_raw_handle)\b"
Grep: pattern="\bmem::forget\b|\bManuallyDrop\b"
```

Run finders in declared order.
