---
name: unsafe-stdlib-finder
description: Finds unsafe stdlib function usage
---

**Finding ID Prefix:** `UNSAFESTD` (e.g., UNSAFESTD-001, UNSAFESTD-002)

**Unsafe Functions:**

1. **No Bounds Checking**
   - `sprintf` → use `snprintf`
   - `vsprintf` → use `vsnprintf`
   - `strcpy` → use `strncpy` or `strlcpy`
   - `stpcpy` → use `stpncpy`
   - `strcat` → use `strncat` or `strlcat`
   - `gets` → REMOVED in C11, use `fgets`
   - `scanf("%s")` → use width specifier `%Ns`

2. **Race Conditions**
   - `tmpnam` → use `mkstemp`
   - `tempnam` → use `mkstemp`
   - `mktemp` → use `mkstemp`

3. **Complex Memory Management**
   - `alloca` → stack overflow risk, use malloc
   - `putenv` → complex ownership, use setenv

**Common False Positives to Avoid:**

- **Bounded input:** sprintf with format string that limits output size
- **Fixed-size literal:** strcpy from compile-time constant that fits
- **Wrapper macro:** Project defines safe macro that wraps the function
- **Intentionally unsafe test:** Test code deliberately using unsafe functions
- **Not libc version:** Function name shadowed by safe project-specific implementation

**Search Patterns:**
```
\bsprintf\s*\(|\bvsprintf\s*\(
\bstrcpy\s*\(|\bstpcpy\s*\(|\bstrcat\s*\(
\bgets\s*\(
\bscanf\s*\([^,]*"%s"|\bscanf\s*\([^,]*"%\[^"]"
\btmpnam\s*\(|\btempnam\s*\(|\bmktemp\s*\(
\balloca\s*\(|\bputenv\s*\(
```
