---
name: cluster-object-lifecycle
kind: cluster
consolidated: false
covers:
  - use-after-free         # UAF
  - memory-leak            # LEAK
  - uninitialized-data     # UNINIT
  - null-deref             # NULL
---

# Cluster: Object lifecycle

Four bug classes that all answer questions about the same mental model: **for each allocated object, what is its alloc site, its init site(s), its free site(s), and its use sites?** Build that model once, then ask four different questions of it.

ID prefixes: `UAF`, `LEAK`, `UNINIT`, `NULL`.

---

## Phase A — Build the lifecycle map (ONCE per run)

Run these scans and keep the results as `obj_map` for all four passes:

```
Grep: pattern="\\b(malloc|calloc|realloc|reallocarray|strdup|strndup|asprintf)\\s*\\("
Grep: pattern="\\b(free|realloc)\\s*\\("
Grep: pattern="\\bnew\\s+\\w"            # C++ allocations
Grep: pattern="\\bdelete\\s+\\w|\\bdelete\\[\\]"
```

Project-specific allocator wrappers matter at least as much as libc ones. Detect them:

```
Grep: pattern="(?i)^\\s*\\w*(new|alloc|create|init|join|leave|delete|destroy|fini|release)\\b"
```

For each project-typed object (`fd_foo_t`, etc.), use `findReferences` on its `_new`/`_delete`/`_join`/`_leave`/`_init`/`_fini` pair to locate every constructor, destructor, and attach/detach call site. Track these as the object's lifecycle boundary — NOT just libc `malloc`/`free`.

Also record (for UNINIT and NULL passes): for every declaration of pointer/struct variables, whether the declaration has an initializer.

Do not file findings during Phase A.

---

## Phase B — Run these per-class finders in order, reusing `obj_map`

Read each file below and apply its bug patterns against `obj_map`. Do not re-derive the allocation/free map — reference `obj_map` directly.

1. **`UNINIT` — Uninitialized data**
   Context to reuse: declaration-initializer state from Phase A.

2. **`NULL` — Null-pointer dereference**
   Context to reuse: every alloc site in `obj_map` — its caller must check the return for NULL before the first dereference.

3. **`UAF` — Use-after-free**
   Context to reuse: the full free→use ordering in `obj_map`. Double-free is a UAF sub-case; flag under UAF.

4. **`LEAK` — Memory leak**
   Context to reuse: alloc sites with no matching free on some path (especially error paths and early returns).

---

## Deconfliction

Report only one finding per `(path, line)`. Priority (higher wins):

1. `UAF` > `NULL` (a use-after-free manifests as a NULL deref only if the freed pointer was also cleared to NULL, in which case report UAF — it's the more specific root cause).
2. `UNINIT` > `NULL` (uninit pointer deref is stronger signal than generic NULL deref).
3. `LEAK` is independent — never collapses with the others.

---

## Token-economy reminder

The four sub-prompts all overlap on "trace this pointer's lifetime." Keep a short shared note describing each interesting object (type, alloc site, free site, uses) and reuse it across passes. Do not re-`Read` the same source files four times — once is enough.
