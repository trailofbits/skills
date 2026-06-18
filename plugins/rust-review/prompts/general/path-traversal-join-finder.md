---
name: path-traversal-join-finder
description: Detects Path::join / PathBuf::push with attacker-controlled components that escape the intended root
---

**Finding ID Prefix:** `PATHJOIN`.

**Bug shape:** `Path::join`/`PathBuf::push` silently replaces the entire path when the argument is absolute; `..`/`Component::ParentDir` components escape a base directory. Both let an attacker-controlled argument traverse outside the intended root.

**Gates:**

1. A `join`/`push` argument is derived from untrusted input (request parameter, env var, user-supplied string).
2. The resulting path is used to open, read, write, create, or remove a filesystem resource.
3. No validation rejects absolute paths and `..` components, and no `canonicalize` + `starts_with(base)` prefix check is performed on a feasible path.

**FPs:**

- Argument is validated before the call (refuses absolute and `Component::ParentDir` components).
- `canonicalize()` result is verified to remain under the base dir via `starts_with` — **valid only for operations on an existing target** (open/read/remove). `canonicalize` returns `NotFound` (ENOENT) on a not-yet-created path, so it cannot validate a create/write target.
- Argument is a compile-time literal with no attacker influence.
- Result is not used for an actual filesystem access.

**Patch:** reject absolute and `Component::ParentDir` components before `join`/`push` — the only approach that works for **create/write** targets. For operations on an **existing** path, you may instead `canonicalize` the result (and the base, in case it is itself a symlink) and verify the result stays under the base via `starts_with`. Do not rely on `canonicalize` for create/write paths — it fails with `NotFound` on a not-yet-existing target.
