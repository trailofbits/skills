---
name: toctou-finder
description: Detects filesystem time-of-check/time-of-use races where a path check is separated from the matching open/create/remove
---

**Finding ID Prefix:** `TOCTOU`.

**Bug shape:** A check (`exists`, `metadata`, `symlink_metadata`, permission or owner test) followed by a separate use (`File::open`, `create`, `remove_file`) on the same path leaves a window in which an attacker can swap the target (e.g., substitute a symlink) so the use operates on a different object than the check validated.

**Gates:**

1. A check call and a later use call reference the same path variable or expression.
2. The check's result gates a security decision (access control, content trust, creation safety).
3. The operation is non-atomic: separate syscalls with no `O_EXCL`/`create_new`, and no fd-relative reuse (open once then `fstat` on the resulting fd).

**FPs:**

- Atomic primitive used: `OpenOptions::create_new` / `O_EXCL`, or open-then-`fstat`/metadata on the returned fd.
- No security decision rides on the check result.
- Path is under the process's exclusive control (mode-0700 tmpdir, no other writers).

**Patch:** open the file once and call `fstat`/`metadata` on the returned fd, or use `OpenOptions::create_new` for creation; avoid re-checking the path name after the initial open.
