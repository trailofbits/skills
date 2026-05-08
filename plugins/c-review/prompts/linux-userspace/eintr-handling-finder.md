---
name: eintr-handling-finder
description: Detects missing EINTR handling
---

**Finding ID Prefix:** `EINTR` (e.g., EINTR-001, EINTR-002)

**Bug Patterns to Find:**

1. **Missing EINTR Retry**
   - Most syscalls should be retried on EINTR
   - `read`, `write`, `recv`, `send`, `accept`, `connect`
   - `select`, `poll`, `epoll_wait`
   - `waitpid`, `sem_wait`, `pthread_cond_wait`

2. **close() Retried on EINTR**
   - `close()` must NOT be retried after EINTR
   - FD is already closed even if EINTR returned
   - Retrying may close a different FD

3. **Incorrect EINTR Loop**
   - Not preserving partial progress
   - Wrong loop termination condition

**Correct Patterns:**

```c
// Most syscalls - RETRY
while ((n = read(fd, buf, len)) == -1 && errno == EINTR)
    ; // retry

// close() - DO NOT RETRY
if (close(fd) == -1 && errno != EINTR) {
    // handle error, but never retry
}
```

**Common False Positives to Avoid:**

- **SA_RESTART set:** When SA_RESTART is used for signal handlers, most syscalls auto-restart
- **Wrapper functions:** Code may use wrappers (e.g., `safe_read`) that handle EINTR internally
- **Non-blocking I/O:** Non-blocking operations may not need EINTR handling
- **Program doesn't use signals:** If no signal handlers installed, EINTR won't occur
- **Already in retry loop:** EINTR handling may be in outer loop structure

**Search Patterns:**
```
read\s*\(|write\s*\(|recv\s*\(|send\s*\(
accept\s*\(|connect\s*\(|close\s*\(
select\s*\(|poll\s*\(|epoll_wait\s*\(
EINTR|while.*errno
```
