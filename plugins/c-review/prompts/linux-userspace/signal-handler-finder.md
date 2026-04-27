---
name: signal-handler-finder
description: Finds async-signal-unsafe function calls
---

**Finding ID Prefix:** `SIGNAL` (e.g., SIGNAL-001, SIGNAL-002)

**Async-Signal-Unsafe Operations:**

1. **Memory Allocation**
   - `malloc`, `free`, `realloc`, `calloc`
   - `new`, `delete`

2. **Standard I/O**
   - `printf`, `fprintf`, `sprintf`
   - `fopen`, `fclose`, `fread`, `fwrite`

3. **Other Unsafe Functions**
   - `strtok`, `strerror`
   - `getpwnam`, `getgrnam`
   - `localtime`, `gmtime`

4. **errno Modification**
   - Any function that sets errno
   - errno not saved/restored in handler

**Safe Functions (async-signal-safe):**
- `write`, `read` (raw syscalls)
- `_exit`, `abort`
- `signal`, `sigaction` (careful)
- `open`, `close` (file descriptors)

**Common False Positives to Avoid:**

- **Handler only sets flag:** Handler just sets `volatile sig_atomic_t` flag
- **Self-pipe trick:** Handler writes to pipe, processing done elsewhere
- **signalfd used:** Using signalfd for synchronous signal handling
- **Signals blocked:** Unsafe code runs with signals blocked
- **errno saved/restored:** Handler properly saves and restores errno

**Search Patterns:**
```
signal\s*\(|sigaction\s*\(|sighandler_t
SIG[A-Z]+\s*,|SIGINT|SIGTERM|SIGHUP|SIGUSR
malloc\s*\(|free\s*\(|printf\s*\(|fprintf\s*\(
errno\s*=|errno\s*$
```
