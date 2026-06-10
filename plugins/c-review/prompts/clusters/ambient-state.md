---
name: cluster-ambient-state
kind: cluster
consolidated: false
covers:
  - access-control         # ACCESS
  - envvar                 # ENVVAR  (LOCAL_UNPRIVILEGED only)
  - privilege-drop         # PRIVDROP (LOCAL_UNPRIVILEGED only)
  - filesystem-issues      # FS
  - time-issues            # TIME
  - dos                    # DOS
---

# Cluster: Ambient state (env / fs / time / creds / DoS)

Six bug classes that all reason about **attacker influence over the ambient process state**: environment variables, filesystem, credentials, wall-clock, resource budgets.

ID prefixes: `ACCESS`, `ENVVAR`, `PRIVDROP`, `FS`, `TIME`, `DOS`.

If the active threat model is `REMOTE`, the run-plan builder hard-drops `privilege-drop` and `envvar`; they will not appear in `sub_prompt_paths` or `pass_bug_classes`. If they are absent, do not reconstruct or run those passes.

---

## Phase A — Build the ambient-state map (ONCE per run)

```
Grep: pattern="\\b(getenv|secure_getenv|setenv|unsetenv|putenv|environ)\\b"
Grep: pattern="\\b(setuid|setgid|seteuid|setegid|setresuid|setresgid|setfsuid|setfsgid|initgroups|setgroups|capset|prctl|chroot)\\s*\\("
Grep: pattern="\\b(access|faccessat|stat|lstat|fstat|readlink|realpath|chmod|fchmod|chown|fchown|umask)\\s*\\("
Grep: pattern="\\b(open|openat|creat|mkdir|mkdirat|symlink|symlinkat|link|linkat|rename|renameat|unlink|unlinkat)\\s*\\("
Grep: pattern="\\b(time|clock_gettime|gettimeofday|mktime|strftime|strptime|difftime)\\s*\\("
Grep: pattern="\\b(sleep|usleep|nanosleep|select|poll|epoll_wait)\\s*\\("
Grep: pattern="\\b(getpwuid|getpwnam|getgrgid|getgrnam|getlogin|geteuid|getuid|getgid|getegid)\\s*\\("
```

Keep as `ambient_sites`. Do not file findings during Phase A.

---

## Phase B — Passes in order (reuse `ambient_sites`)

1. **`FS` — Filesystem issues**
   TOCTOU (`access` then `open`), symlink races, temp-file races, untrusted path components, directory traversal.

2. **`ACCESS` — Access control**
   Missing permission checks before privileged operations; UID/GID comparisons; capability checks.

3. **`PRIVDROP` — Privilege drop** (skip if REMOTE)
   Drop-order bugs, unchecked `setuid` return, incomplete gid drop before uid drop.

4. **`ENVVAR` — Environment variable misuse** (skip if REMOTE)
   Trusting `getenv` result in setuid context; missing `secure_getenv`.

5. **`TIME` — Time-related issues**
   Y2K38, clock running backwards, non-monotonic clock for measuring intervals, signed `time_t`.

6. **`DOS` — Denial of service**
   Unbounded allocations from untrusted input; algorithmic complexity attacks; infinite loops driven by attacker input; fd/thread exhaustion.

---

## Deconfliction

Priority:

1. `FS` > `ACCESS` (if the missing check is specifically a TOCTOU, file `FS`).
2. `PRIVDROP` > `ACCESS` (drop-order is a privdrop bug, not access control).
3. `DOS` is mostly independent; overlaps with `INT` (allocation-size overflow) go to the arithmetic cluster.

---

## Token-economy reminder

Reuse `ambient_sites` across all six passes. Entry-point analysis (who is the process, what privileges, what config) is shared — write it once at the top of your working notes and reference it.
