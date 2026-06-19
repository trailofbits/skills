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
Grep: pattern="\bfs::(read|write|read_to_string|File|create|metadata|remove_file|remove_dir(_all)?)\s*\(|\bthread::sleep\b|\bTcpStream\b|\bTcpListener\b|\brecv\s*\(\s*\)|\.lock\(\)\s*\.unwrap\(\)|block_in_place|spawn_blocking"  # imported/short forms (`use std::fs; fs::read_to_string(..)`, blocking `recv()`, `.lock().unwrap()`) + already-wrapped sites
Grep: pattern="tokio::sync::(Mutex|RwLock)"
```

Run finders in declared order.
