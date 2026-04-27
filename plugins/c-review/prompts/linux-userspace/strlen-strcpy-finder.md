---
name: strlen-strcpy-finder
description: Finds strlen/strcpy interaction bugs
---

**Finding ID Prefix:** `STRLENCPY` (e.g., STRLENCPY-001, STRLENCPY-002)

**The Core Issue:**
- `strlen()` returns length WITHOUT null terminator
- `strcpy()` copies INCLUDING null terminator
- Allocating `strlen(s)` bytes, then `strcpy` overflows by 1

**Bug Patterns to Find:**

1. **malloc(strlen(s)) + strcpy**
   ```c
   char *copy = malloc(strlen(s));  // Missing +1
   strcpy(copy, s);                  // Overflow!
   ```

2. **Array Size = strlen**
   ```c
   char buf[strlen(s)];  // VLA missing +1
   strcpy(buf, s);       // Overflow!
   ```

3. **memcpy with strlen**
   ```c
   memcpy(dst, src, strlen(src));  // Doesn't copy null
   // dst now not null-terminated
   ```

4. **Size Calculations**
   ```c
   size_t len = strlen(s);
   // ... later ...
   memcpy(dst, s, len);  // Forgot +1
   ```

**Common False Positives to Avoid:**

- **+1 added later:** Code adds +1 between strlen and allocation
- **strdup used:** Using strdup() which handles the +1 internally
- **Manual null termination:** Code manually adds null after memcpy
- **Fixed buffer with bounds check:** Buffer is larger than max possible string
- **Binary data, not string:** memcpy without +1 is correct for non-string data

**Search Patterns:**
```
malloc\s*\(\s*strlen\s*\(
strlen\s*\([^)]+\)\s*[^+]  # strlen not followed by +
memcpy.*strlen|memmove.*strlen
char\s+\w+\s*\[\s*strlen
```
