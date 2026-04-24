---
name: cluster-windows-process
kind: cluster
consolidated: false
gate: is_windows
covers:
  - createprocess          # CREATEPROC
  - cross-process          # CROSSPROC
  - token-privilege        # TOKPRIV
  - service-security       # WINSVC
---

# Cluster: Windows — process & token

Four Windows-only bug classes around process creation, cross-process handles, privilege tokens, and service security. Share a common inventory of Win32 process/security APIs.

ID prefixes: `CREATEPROC`, `CROSSPROC`, `TOKPRIV`, `WINSVC`.

---

## Phase A — Seed targets

```
Grep: pattern="\\b(CreateProcess[AW]?|ShellExecute[AW]?|CreateProcessAsUser[AW]?|WinExec)\\s*\\("
Grep: pattern="\\b(OpenProcess|DuplicateHandle|ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread)\\s*\\("
Grep: pattern="\\b(OpenProcessToken|OpenThreadToken|AdjustTokenPrivileges|LookupPrivilegeValue|ImpersonateLoggedOnUser|SetTokenInformation)\\s*\\("
Grep: pattern="\\b(StartServiceCtrlDispatcher|RegisterServiceCtrlHandler|CreateService|OpenSCManager|StartService)\\s*\\("
Grep: pattern="\\bSECURITY_ATTRIBUTES\\b|\\bSECURITY_DESCRIPTOR\\b"
```

Keep as `win_proc_sites`.

---

## Phase B — Passes in order

1. **`CREATEPROC` — `CreateProcess` misuse**
   Unquoted paths with spaces, relative lpApplicationName, bInheritHandles=TRUE leaking handles.

2. **`CROSSPROC` — Cross-process memory / handle issues**
   `OpenProcess(PROCESS_ALL_ACCESS)` to untrusted PIDs, handle duplication without access-mask narrowing.

3. **`TOKPRIV` — Token / privilege misuse**
   `AdjustTokenPrivileges` without checking `GetLastError`, impersonation not reverted.

4. **`WINSVC` — Service security**
   Weak service DACLs, `SERVICE_CHANGE_CONFIG` granted to Users, unquoted `ImagePath`.

---

## Deconfliction

1. `WINSVC` > `CREATEPROC` (if the process-creation bug lives inside a service bootstrap).
2. `TOKPRIV` > `CROSSPROC` (if the bug is specifically adjusting privileges, even across processes).
