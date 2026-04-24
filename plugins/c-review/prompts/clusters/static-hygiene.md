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

## Phase A — Seed targets

```
Grep: pattern="CFLAGS|CXXFLAGS|-fstack-protector|-D_FORTIFY_SOURCE|-fPIE|-fPIC|-Wformat|-Wl,-z,"   files="Makefile*,*.mk,CMakeLists.txt,meson.build,configure*,*.gyp,*.bazel"
Grep: pattern="va_start\\s*\\(|va_end\\s*\\(|va_copy\\s*\\("
Grep: pattern="\\b(regcomp|regexec|regfree)\\s*\\("
Grep: pattern="\\b(pcre_compile|pcre2_compile|pcre_exec|pcre2_match)\\s*\\("
Grep: pattern="\\b(inet_aton|inet_addr|inet_network|inet_pton|inet_ntop)\\s*\\("
Grep: pattern="\\bqsort\\s*\\(|\\bqsort_r\\s*\\(|\\bbsearch\\s*\\("
Grep: pattern="__attribute__\\s*\\(\\s*\\(\\s*format\\s*\\(\\s*printf"
```

No complex state to build — each pass below runs on its own matches.

---

## Phase B — Passes (any order)

1. **`MITIGATION` — Exploit mitigation flags**
   Missing `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wl,-z,now`, `-Wl,-z,relro`, PIE, etc.

2. **`PRINTFATTR` — Missing printf-format attributes**
   Variadic logging wrappers without `__attribute__((format(printf, N, M)))` — the compiler can't catch mismatches.

3. **`VAARG` — `va_start` / `va_end` misuse**
   Missing `va_end`, mismatched pairs, reading a `va_list` twice without `va_copy`.

4. **`REGEX` — Regex issues**
   Catastrophic backtracking, unescaped user input compiled as pattern, `regfree` omission.

5. **`INETATON` — `inet_aton` / `inet_addr` misuse**
   Accepting "10.0.0" as `10.0.0.0` (classful fallback), `inet_addr("255.255.255.255")` returning `-1`.

6. **`QSORT` — `qsort` misuse**
   Comparator returning difference of ints (can overflow), not reflexive/transitive/antisymmetric.

---

## Deconfliction

These are mostly disjoint; no cross-pass dedup rules needed. If in doubt, prefer the pass whose prefix more narrowly describes the bug.
