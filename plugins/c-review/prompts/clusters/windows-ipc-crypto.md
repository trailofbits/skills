---
name: cluster-windows-ipc-crypto
kind: cluster
consolidated: false
gate: is_windows
covers:
  - named-pipe             # NAMEDPIPE
  - windows-crypto         # WINCRYPTO
  - windows-alloc          # WINALLOC
---

# Cluster: Windows — IPC, crypto, allocator

Three Windows-only bug classes around named-pipe security, CryptoAPI misuse, and Windows heap/alloc specifics.

ID prefixes: `NAMEDPIPE`, `WINCRYPTO`, `WINALLOC`.

---

## Phase A — Seed targets

```
Grep: pattern="\\b(CreateNamedPipe[AW]?|ConnectNamedPipe|ImpersonateNamedPipeClient|SetNamedPipeHandleState)\\s*\\("
Grep: pattern="\\b(CryptAcquireContext[AW]?|CryptGenKey|CryptGenRandom|CryptEncrypt|CryptDecrypt|CryptHashData|CryptSignHash|CryptVerifySignature|BCrypt\\w+|NCrypt\\w+)\\s*\\("
Grep: pattern="\\b(HeapAlloc|HeapFree|HeapReAlloc|HeapCreate|HeapDestroy|VirtualAlloc|VirtualFree|VirtualProtect|LocalAlloc|LocalFree|GlobalAlloc|GlobalFree)\\s*\\("
Grep: pattern="\\bSECURITY_DESCRIPTOR\\b|\\bSetSecurityDescriptor\\w+\\s*\\("
```

Keep as `win_ipc_sites`.

---

## Phase B — Passes in order

1. **`NAMEDPIPE` — Named-pipe security**
   Missing `PIPE_REJECT_REMOTE_CLIENTS`, weak DACL on pipe, impersonation without `SECURITY_IDENTIFICATION`.

2. **`WINCRYPTO` — CryptoAPI misuse**
   Deprecated algorithms (`CALG_MD5`, `CALG_DES`), `rand()` for keys, missing `CryptGenRandom`/`BCryptGenRandom`.

3. **`WINALLOC` — Windows allocator specifics**
   Mismatched alloc/free pairs (`HeapAlloc` freed with `LocalFree`), `VirtualProtect` race, W^X violations.

---

## Deconfliction

Mostly disjoint. `WINCRYPTO` never merges with the others.
