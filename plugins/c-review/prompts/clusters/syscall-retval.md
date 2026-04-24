---
name: cluster-syscall-retval
kind: cluster
consolidated: false
covers:
  - errno-handling         # ERRNO
  - negative-retval        # NEGRET
  - error-handling         # ERR
  - eintr-handling         # EINTR
  - socket-disconnect      # SOCKDISCON
  - half-closed-socket     # HALFCLOSE
  - open-issues            # FILEOP
---

# Cluster: Syscall / libc return handling

Seven bug classes that all ask "what does the caller do with the return value of this syscall/libc function?" One syscall-site inventory fuels all seven.

ID prefixes: `ERRNO`, `NEGRET`, `ERR`, `EINTR`, `SOCKDISCON`, `HALFCLOSE`, `FILEOP`.

---

## Phase A — Build the syscall inventory (ONCE per run)

```
Grep: pattern="\\b(read|write|pread|pwrite|readv|writev|recv|recvfrom|recvmsg|send|sendto|sendmsg)\\s*\\("
Grep: pattern="\\b(open|openat|creat|close|fopen|fclose|dup|dup2|dup3|pipe|pipe2|socketpair|socket|accept|accept4|connect|bind|listen|shutdown)\\s*\\("
Grep: pattern="\\b(stat|fstat|lstat|access|faccessat|readlink|realpath)\\s*\\("
Grep: pattern="\\b(malloc|calloc|realloc|reallocarray|mmap|mprotect|munmap)\\s*\\("
Grep: pattern="\\b(ioctl|fcntl|select|poll|epoll_wait|kqueue|kevent)\\s*\\("
Grep: pattern="\\b(fork|execve|execv|execl|waitpid|wait|kill|sigaction|signal)\\s*\\("
Grep: pattern="\\berrno\\b"                                  # errno reads
Grep: pattern="\\b(setsockopt|getsockopt|getaddrinfo|freeaddrinfo)\\s*\\("
```

Keep the result as `syscall_sites` (callee, `path:line`, enclosing function). For each, note whether the return is assigned, whether it's checked, and whether `errno` is read on failure.

Do not file findings during Phase A.

---

## Phase B — Passes in order (reuse `syscall_sites`)

1. **`ERR` — Error handling (coarsest)**
   Flag return-value discarded entirely (`read(fd, buf, n);` with no check).

2. **`NEGRET` — Negative return not handled**
   Flag `-1` returns used as a size/index without a prior `< 0` check.

3. **`ERRNO` — `errno` misuse**
   Flag `errno` read after a non-erroring call, or after an intervening call that clobbered it.

4. **`EINTR` — Interrupted syscalls**
   Flag blocking syscalls without an `EINTR` retry loop when signals are installed.

5. **`FILEOP` — open() / fopen() specifics**
   Focus on the `open`/`openat`/`fopen` subset of `syscall_sites`: flags, mode, O_CREAT without O_EXCL, etc.

6. **`SOCKDISCON` — Socket disconnect handling**
   Focus on `recv`/`read` on sockets: return of 0 means peer closed, not "no data."

7. **`HALFCLOSE` — Half-closed sockets**
   Focus on `shutdown(SHUT_WR)` / `shutdown(SHUT_RD)` patterns and their interaction with reads/writes.

---

## Deconfliction

Priority (higher wins):

1. `SOCKDISCON` > `ERR` (if the unchecked return is specifically `recv`-returning-0 on a socket).
2. `EINTR` > `ERR` (if the bug is specifically the missing `EINTR` loop).
3. `FILEOP` > `ERR` (for `open`/`fopen` flag issues).
4. `NEGRET` > `ERR` (when `-1` is the value causing harm).
5. `ERRNO` is independent — about `errno` reads, not return values.

---

## Token-economy reminder

Each pass cares about a specific subset of `syscall_sites`. Do not re-grep syscalls between passes; filter the inventory you already have.
