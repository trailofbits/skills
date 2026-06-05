---
name: cluster-async-runtime
kind: cluster
consolidated: false
covers:
  - async-blocking  # ASYNCBLOCK
  - cancel-safety   # CANCELSAFETY
  - select-bias     # SELECTBIAS
---

# Cluster: Async runtime hazards

ID prefixes: `ASYNCBLOCK`, `CANCELSAFETY`, `SELECTBIAS`.

## Phase A

```
Grep: pattern="\basync\s+fn\b|\.await\b"
Grep: pattern="tokio::select!|futures::select!"
Grep: pattern="std::(sync::(Mutex|RwLock)|fs::|thread::sleep|net::)"
Grep: pattern="tokio::sync::(Mutex|RwLock)"
```

Run finders in declared order.
