---
name: va-start-end-finder
description: Detects va_start/va_end misuse
---

**Finding ID Prefix:** `VAARG` (e.g., VAARG-001, VAARG-002)

**The Core Issue:**
Every `va_start()` must have a corresponding `va_end()` before the function returns.
Missing `va_end()` is undefined behavior and may corrupt stack on some platforms.

```c
void bad_func(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (error) {
        return;  // Missing va_end!
    }
    vprintf(fmt, ap);
    va_end(ap);  // Only reached on success path
}
```

**Bug Patterns to Find:**

1. **Early Return Without va_end**
   ```c
   va_start(ap, fmt);
   if (check_fails) {
       return;  // va_end not called!
   }
   va_end(ap);
   ```

2. **Exception Path Missing va_end (C++)**
   ```c
   va_start(ap, fmt);
   may_throw();  // If throws, va_end skipped
   va_end(ap);
   ```

3. **Multiple va_start Without Matching va_end**
   ```c
   va_start(ap, fmt);
   va_start(ap, fmt);  // Second start without end
   va_end(ap);
   ```

4. **va_copy Without va_end**
   ```c
   va_copy(ap2, ap);  // Creates new va_list
   // Missing va_end(ap2)
   ```

**Common False Positives to Avoid:**

- **va_end on all paths:** All return paths call va_end before returning
- **goto cleanup pattern:** Code uses goto to centralized cleanup that calls va_end
- **RAII wrapper (C++):** C++ code uses RAII class that calls va_end in destructor
- **noreturn function:** Early exit is via noreturn function (abort, _exit)
- **va_copy properly paired:** Both original and copied va_list have matching va_end

**Search Patterns:**
```
va_start\s*\(|va_end\s*\(|va_copy\s*\(
va_list\s+\w+
return\s*;|return\s+\w+;
throw\s+|goto\s+
```
