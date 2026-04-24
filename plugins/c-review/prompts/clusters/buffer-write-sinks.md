---
name: cluster-buffer-write-sinks
kind: cluster
consolidated: true
covers:
  - buffer-overflow        # BOF
  - memcpy-size            # MEMCPYSZ
  - overlapping-buffers    # OVERLAP
  - strlen-strcpy          # STRLENCPY
  - strncat-misuse         # STRNCAT
  - strncpy-termination    # STRNCPY
  - snprintf-retval        # SNPRINTF
  - scanf-uninit           # SCANFUNINIT
  - format-string          # FMT
  - banned-functions       # BAN
  - flexible-array         # FLEX
  - unsafe-stdlib          # UNSAFESTD
  - string-issues          # STR
---

# Cluster: Buffer-write sinks (consolidated)

Thirteen related bug classes that all interrogate the same population of sink call sites (`memcpy`/`str*`/`*printf`/`*scanf` and friends). **Do ONE sink inventory and then run focused passes against it** — do not re-grep sinks per pass.

Finding ID prefixes this cluster owns: `BOF`, `MEMCPYSZ`, `OVERLAP`, `STRLENCPY`, `STRNCAT`, `STRNCPY`, `SNPRINTF`, `SCANFUNINIT`, `FMT`, `BAN`, `FLEX`, `UNSAFESTD`, `STR`.

---

## Phase A — Build the sink inventory (ONCE per run)

Run these greps, merging matches into a single working set `sink_sites`. Record `path:line`, the callee name, and one surrounding line for each match. Keep this set for all subsequent phases.

```
# Unified sink grep — one pass per target (do not repeat in later phases)
Grep: pattern="\\b(memcpy|memmove|memset|bcopy|bzero)\\s*\\("
Grep: pattern="\\b(strcpy|strncpy|stpcpy|stpncpy|strlcpy|strcat|strncat|strlcat|strdup|strndup)\\s*\\("
Grep: pattern="\\b(sprintf|vsprintf|snprintf|vsnprintf|asprintf|vasprintf|fprintf|dprintf|printf|vprintf|syslog|vsyslog)\\s*\\("
Grep: pattern="\\b(scanf|sscanf|fscanf|vscanf|vsscanf|vfscanf)\\s*\\("
Grep: pattern="\\b(gets|gets_s|fgets|read|pread|recv|recvfrom)\\s*\\("
Grep: pattern="\\b(malloc|calloc|realloc|reallocarray|alloca|aligned_alloc|posix_memalign)\\s*\\("
Grep: pattern="\\b(strtok|strtok_r|mbstowcs|wcstombs|wcsncpy|wcsncat|wcslen|tmpnam|tempnam|mktemp|putenv)\\s*\\("
Grep: pattern="\\[\\s*0\\s*\\]\\s*;|\\[\\s*1\\s*\\]\\s*;"   # FAM-style struct hacks
Grep: pattern="__attribute__\\s*\\(\\s*\\(\\s*format"        # existing printf-attr annotations
```

Optional LSP supplement (only if clangd is live): for each unique callee in `sink_sites`, `findReferences` to confirm the grep's call-site count and catch macro-wrapped calls.

**Do not file findings during Phase A.** Just build the inventory.

---

## Phase B — Focused passes

Run the passes below **in this order**. Within each pass: filter `sink_sites` to the callees the pass cares about, then for each candidate site, `Read` the enclosing function and trace the specific invariant the pass checks. Do **not** re-run Phase-A greps.

The passes are ordered so earlier passes "consume" the obvious cases, leaving later passes to focus on their distinct invariants. Never double-report: if the same site is flagged by multiple passes, pick the pass with the most specific invariant (checklist in Phase C).

### Pass 1 — `BAN` Banned / deprecated functions

**Callees:** `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `tmpnam`, `tempnam`, `mktemp`, `strtok` (not `_r`), `rand`/`srand`, `alloca`, `putenv`.

**Rule:** Bare call to a banned function in production code is the finding, irrespective of input shape. No data-flow trace needed — the presence is the bug under Intel SDL / CERT.

**FPs to skip (do not file):**
- The name appears in a comment, string literal, or test that deliberately exercises unsafe functions.
- A project-local macro or inline wrapper shadows the libc name with a bounded implementation (verify with `goToDefinition` before skipping).
- Code explicitly guarded by `#ifdef` for a platform not being audited.

**Prefix:** `BAN`.

### Pass 2 — `UNSAFESTD` Unsafe stdlib (non-banned but discouraged)

**Callees:** `scanf("%s")` / `sscanf("%s")` without width, `stpcpy`, un-widthed `fgets` into fixed buffers, `putenv` (ownership hazard), `alloca` under attacker-controlled size.

**Rule:** File only when the site is not already filed as `BAN`. Focus on width-less format specifiers and ownership ambiguity.

**Prefix:** `UNSAFESTD`.

### Pass 3 — `FMT` Format-string bugs

**Callees:** anything in the `printf` / `syslog` family.

**Bug patterns:**
- Non-literal format string: `printf(user_input)` instead of `printf("%s", user_input)`. For each site, `hover`/`Read` the first argument — is it a string literal or a variable?
- `%n` anywhere (write primitive).
- Type/size mismatches (`%d` on pointer, `%s` on int, `%d` vs `%ld`).
- Variadic wrapper functions without `__attribute__((format))`.

**FPs to skip:**
- Format argument is a compile-time string literal or enum-indexed static table.
- Function has `__attribute__((format(printf, N, M)))` so the compiler checks it.
- `-D_FORTIFY_SOURCE=2` is set AND format comes from writable memory the attacker cannot reach.

**Prefix:** `FMT`.

### Pass 4 — `SNPRINTF` snprintf return-value misuse

**Callees:** `snprintf`, `vsnprintf`, `asprintf`, `vasprintf`.

**Bug patterns:**
- `buf[n] = '\\0'` where `n` is the `snprintf` return (may be ≥ size).
- `ptr += snprintf(ptr, remaining, ...)` without `min(n, remaining-1)` clamp.
- `remaining = size - snprintf(...)` that can go negative.
- Ignoring truncation where truncation has security consequences (path building, log line, argv assembly).

**FPs to skip:** return value is clamped or compared to size before use; truncation is genuinely acceptable.

**Prefix:** `SNPRINTF`.

### Pass 5 — `OVERLAP` Overlapping buffer UB

**Callees:** `memcpy`, `strcpy`, `strncpy`, `sprintf`, `snprintf`, `strcat`, `strncat` (not `memmove`).

**Bug patterns:**
- Same buffer as source and destination: `sprintf(buf, "%s…", buf)`, `memcpy(buf+k, buf, n)`.
- Data flow proves source and destination can alias.

**FPs to skip:** `memmove` used (safe by design); provably different allocations; explicit intermediate copy.

**Prefix:** `OVERLAP`.

### Pass 6 — `MEMCPYSZ` Negative / wrap size into `mem*`

**Callees:** `memcpy`, `memmove`, `memset`, `bcopy`, `bzero`.

**Bug patterns:**
- Size is the result of signed arithmetic that can go negative (`end - start`, `total - used`) without a prior `< 0` check.
- Size is a syscall return cast to `size_t` without checking for `-1`.
- Size came from an unchecked subtraction between unsigned values (wrap to `SIZE_MAX`).

**FPs to skip:** explicit `< 0` check, assertion, or type chain keeps size unsigned and bounded.

**Prefix:** `MEMCPYSZ`.

### Pass 7 — `STRLENCPY` strlen-based allocation off-by-one

**Callees:** `malloc`/`char[]` followed by `strcpy`/`memcpy` where the allocation size is `strlen(s)` without `+1`.

**Bug patterns:**
- `malloc(strlen(s))` + `strcpy` — missing null terminator byte.
- `char buf[strlen(s)]` VLA + `strcpy`.
- `memcpy(dst, src, strlen(src))` and `dst` is subsequently used as a C string.

**FPs to skip:** `+1` added before the alloc; `strdup`/`strndup` used; `dst` treated as raw bytes, not a string.

**Prefix:** `STRLENCPY`.

### Pass 8 — `STRNCPY` strncpy not null-terminating

**Callees:** `strncpy`, `wcsncpy`.

**Bug patterns:**
- `strncpy(buf, src, sizeof(buf))` with no subsequent `buf[sizeof(buf)-1] = '\\0'`.
- `buf[n] = '\\0'` where `n` is the third arg (off-by-one).
- Conditional termination that misses the long-input branch.

**FPs to skip:** explicit terminator assignment covers all paths; `strlcpy` used; buffer pre-zeroed with room to spare; buffer used as fixed-width record, not string.

**Prefix:** `STRNCPY`.

### Pass 9 — `STRNCAT` strncat size argument misuse

**Callees:** `strncat`, `wcsncat`.

**Bug pattern:** the third argument is `sizeof(buf)` instead of `sizeof(buf) - strlen(buf) - 1`.

**FPs to skip:** correct `sizeof - strlen - 1` form; `strlcat` used; destination is proven empty at call time.

**Prefix:** `STRNCAT`.

### Pass 10 — `SCANFUNINIT` scanf leaves target uninitialized

**Callees:** `scanf`, `sscanf`, `fscanf`, `vsscanf`.

**Bug pattern:** target variable is declared without initialization, `scanf` return value isn't checked, target is subsequently used in a security-relevant decision.

**FPs to skip:** initializer present; return-value checked; target only used on success branch.

**Prefix:** `SCANFUNINIT`.

### Pass 11 — `FLEX` Flexible-array / zero-one array misuse

**Grep seed:** `[\\s*[01]\\s*]\\s*;` inside a `struct` definition, plus nearby `malloc(sizeof(struct …) + …)`.

**Bug patterns:**
- `char data[0]` (GNU extension) or `char data[1]` (pre-C99 hack) as last member of a variable-size struct.
- Allocation uses `sizeof(struct)` instead of `offsetof(struct, data)` when `[1]` is used.

**FPs to skip:** modern `data[]` syntax (C99 FAM); `offsetof`-based allocation; genuinely fixed-size struct.

**Prefix:** `FLEX`.

### Pass 12 — `STR` Locale / encoding / multibyte

**Callees:** `strlen`/`wcslen` on multibyte input, `toupper`/`tolower`/`setlocale`, `mbstowcs`/`wcstombs`, `strncpy`/`strncat` on text at trust boundaries.

**Bug patterns:**
- Byte-size vs character-size confusion (e.g., allocating `strlen(s)` bytes for a wide conversion output).
- Locale-dependent case mapping used for security comparisons.
- Missing UTF-8 / UTF-16 validation at input boundaries where downstream code assumes valid Unicode.
- Surrogate-pair mishandling.

**FPs to skip:** known-length binary protocols (not null-terminated strings); C++ `std::string` that manages its own length.

**Prefix:** `STR`.

### Pass 13 — `BOF` Buffer overflow (catch-all spatial)

Run this pass LAST — it catches spatial-safety bugs that didn't fit the narrower passes above.

**Bug patterns:**
- Off-by-one loop bounds (`<=` where `<` was meant).
- Fixed-buffer array indexing without bounds check (`arr[i]` where `i` is attacker-influenced).
- `malloc(n * sizeof(T))` without multiplication overflow check (the *overflow* piece — the resulting too-small alloc followed by a full-size write).
- `memcmp`/`memcpy` with a size larger than the smaller buffer.
- Raw-memory copy of a struct with pointer members (incomplete deep copy).

**FPs to skip:**
- Flexible array members (`data[]`) with allocation computed via `offsetof`.
- VLAs whose size is validated upstream.
- `memcpy(dst, src, sizeof(dst))` where `dst` is a stack array (not a pointer).
- Constant index provably within bounds.
- Bounds check present earlier in the function.

**Cross-reference:** if a site already produced a finding under passes 1-12, do **not** also file `BOF` on it — the earlier pass's prefix is more specific.

**Prefix:** `BOF`.

---

## Phase C — Write findings

For every finding you keep, write `{output_dir}/findings/<PREFIX>-<NNN>.md` per the system-prompt schema. Fill `bug_class` with the human-readable class name (see table below).

| Prefix | bug_class |
|---|---|
| `BOF` | `buffer-overflow` |
| `MEMCPYSZ` | `memcpy-size` |
| `OVERLAP` | `overlapping-buffers` |
| `STRLENCPY` | `strlen-strcpy` |
| `STRNCAT` | `strncat-misuse` |
| `STRNCPY` | `strncpy-termination` |
| `SNPRINTF` | `snprintf-retval` |
| `SCANFUNINIT` | `scanf-uninit` |
| `FMT` | `format-string` |
| `BAN` | `banned-functions` |
| `FLEX` | `flexible-array` |
| `UNSAFESTD` | `unsafe-stdlib` |
| `STR` | `string-issues` |

### Deconfliction rule (mandatory)

If the same `(path, line)` could be filed under multiple passes, pick the **most specific** pass using this priority (higher wins):

1. `SNPRINTF` (return-value misuse) > `BAN` > `UNSAFESTD`
2. `STRNCPY` > `STRLENCPY` > `BOF`
3. `STRNCAT` > `BOF`
4. `OVERLAP` > `MEMCPYSZ` > `BOF`
5. `FMT` > `BAN` (for printf family)
6. `STR` > `STRNCPY` (when the root cause is encoding, not termination)

Everything else ties: `BOF` is the fallback.

---

## Inventory reuse reminder

If the cluster task is huge and your context is filling up, you may re-summarize `sink_sites` into a compact table (callee → list of `path:line`) and drop the raw `Grep` output from active attention. Do **not** re-run Phase A — the inventory is deterministic and re-grepping wastes tokens without changing what you see.
