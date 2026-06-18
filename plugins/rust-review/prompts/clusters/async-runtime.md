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
Grep: pattern="\b(fs::(read|write|read_to_string|File|create|metadata|remove)|thread::sleep|TcpStream|TcpListener|recv\s*\(\s*\))\b|\.lock\(\)\s*\.unwrap\(\)|block_in_place|spawn_blocking"  # imported/short forms (`use std::fs; fs::read(..)`, `.lock().unwrap()`, blocking `recv()`) + already-wrapped sites
Grep: pattern="tokio::sync::(Mutex|RwLock)"
```

Run finders in declared order.
