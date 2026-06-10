---
name: cluster-static-hygiene
kind: cluster
consolidated: false
covers:
  - exploit-mitigations    # MITIGATION
  - printf-attr            # PRINTFATTR
  - va-start-end           # VAARG
  - regex-issues           # REGEX
  - inet-aton              # INETATON
  - qsort                  # QSORT
---

# Cluster: Static hygiene (grep-only, low-context)

Six bug classes that are mostly **pattern matches at build settings or specific library calls**. They need minimal codebase context — cheap to batch through on a single worker.

ID prefixes: `MITIGATION`, `PRINTFATTR`, `VAARG`, `REGEX`, `INETATON`, `QSORT`.

---

## Phase A — Seed targets (run ONCE, reuse for every Phase B pass)

Run each seed below exactly once. The seed's hit-set is the **complete inventory** for the matching Phase B pass — when you reach Pass 3 (VAARG), do NOT re-grep for `va_start`; reuse the Phase A matches. Sub-prompts under `prompts/linux-userspace/*-finder.md` may list the same regexes in their own "Search Patterns" section; those are **redundant with Phase A** in this cluster — read the sub-prompt for FP guidance and bug-pattern detail, not for searcher commands.

```
# Build-system files (one Grep per glob shape — Grep accepts only one glob per call):
Grep: pattern="CFLAGS|CXXFLAGS|-fstack-protector|-D_FORTIFY_SOURCE|-fPIE|-fPIC|-Wformat|-Wl,-z,"  glob="Makefile*"
Grep: pattern="CFLAGS|CXXFLAGS|-fstack-protector|-D_FORTIFY_SOURCE|-fPIE|-fPIC|-Wformat|-Wl,-z,"  glob="*.mk"
Grep: pattern="CFLAGS|CXXFLAGS|-fstack-protector|-D_FORTIFY_SOURCE|-fPIE|-fPIC|-Wformat|-Wl,-z,"  glob="CMakeLists.txt"
Grep: pattern="CFLAGS|CXXFLAGS|-fstack-protector|-D_FORTIFY_SOURCE|-fPIE|-fPIC|-Wformat|-Wl,-z,"  glob="meson.build"
Grep: pattern="CFLAGS|CXXFLAGS|-fstack-protector|-D_FORTIFY_SOURCE|-fPIE|-fPIC|-Wformat|-Wl,-z,"  glob="configure*"

# Source-code seeds — one Grep per pass; reuse the hit-set in Phase B:
Grep: pattern="va_start\\s*\\(|va_end\\s*\\(|va_copy\\s*\\("              # → Pass 3 VAARG inventory
Grep: pattern="\\b(regcomp|regexec|regfree)\\s*\\("                       # → Pass 4 REGEX inventory (POSIX regex)
Grep: pattern="\\b(pcre_compile|pcre2_compile|pcre_exec|pcre2_match)\\s*\\(" # → Pass 4 REGEX inventory (PCRE)
Grep: pattern="\\b(inet_aton|inet_addr|inet_network|inet_pton|inet_ntop)\\s*\\("  # → Pass 5 INETATON inventory
Grep: pattern="\\bqsort\\s*\\(|\\bqsort_r\\s*\\(|\\bbsearch\\s*\\("       # → Pass 6 QSORT inventory
Grep: pattern="__attribute__\\s*\\(\\s*\\(\\s*format\\s*\\(\\s*printf"     # → Pass 2 PRINTFATTR inventory (functions WITH the attribute)
```

Each seed's hit-set is then the inventory for exactly one pass below. **An empty hit-set is a valid `cleared` outcome** for the matching pass — record it that way in the coverage-gate table; do not re-grep with a slightly different regex hoping for something to appear.

---

## Phase B — Passes (any order; reuse Phase A hits, don't re-grep)

1. **`MITIGATION` — Exploit mitigation flags.** Inventory = build-system seed hits.
   Missing `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wl,-z,now`, `-Wl,-z,relro`, PIE, etc. Also flag near-misses (typos like `_FORTIY_SOURCE`, `fstack-protect-strong`).

2. **`PRINTFATTR` — Missing printf-format attributes.** Inventory = `__attribute__((format(printf,…)))` hits, **plus** any variadic functions you find while running other passes that take `const char *fmt, ...` and forward to `vprintf`/`vsnprintf` etc. without the attribute.
   The compiler can't catch mismatches without the attribute; report only logging/printing wrappers, not unrelated variadic helpers.

3. **`VAARG` — `va_start` / `va_end` misuse.** Inventory = the `va_*` seed hits. Do NOT re-grep for `va_start|va_end|va_copy`; the seed is exhaustive.
   Look for: missing `va_end`, mismatched pairs, reading a `va_list` twice without `va_copy`.

4. **`REGEX` — Regex issues.** Inventory = `regcomp`/`regexec`/`regfree`/PCRE seed hits. Empty hit-set ⇒ `cleared` outcome.
   Catastrophic backtracking, unescaped user input compiled as pattern, `regfree` omission.

5. **`INETATON` — `inet_aton` / `inet_addr` misuse.** Inventory = the inet seed hits.
   Accepting "10.0.0" as `10.0.0.0` (classful fallback), `inet_addr("255.255.255.255")` returning `-1`. **Source matters:** if the input is from trusted config (`/etc/resolv.conf`, hardcoded admin paths) and never reaches network input, file as `cleared` rather than a finding.

6. **`QSORT` — `qsort` misuse.** Inventory = the qsort seed hits.
   Comparator returning difference of ints (can overflow), not reflexive/transitive/antisymmetric. If the sort key is bounded (e.g., enum or small range) such that `b - a` cannot overflow, file as `cleared` and note the bound.

---

## Deconfliction

These are mostly disjoint; no cross-pass dedup rules needed. If in doubt, prefer the pass whose prefix more narrowly describes the bug.
