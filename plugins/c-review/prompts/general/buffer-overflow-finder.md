---
name: buffer-overflow-finder
description: Detects buffer overflows and spatial safety issues
---

**Finding ID Prefix:** `BOF` (e.g., BOF-001, BOF-002)

**Bug Patterns to Find:**

1. **Off-by-one errors**
   - Loop bounds: `for (i = 0; i <= len; i++)` instead of `< len`
   - Array indexing: `arr[size]` instead of `arr[size-1]`
   - String operations: forgetting null terminator space

2. **Invalid size computations**
   - `malloc(n * sizeof(type))` without overflow check
   - Size from untrusted source without validation
   - Incorrect struct size calculations

3. **Data-moving function misuse**
   - `memcpy(dst, src, strlen(src))` - missing +1 for null
   - `strncpy` with wrong size parameter
   - `sprintf` without bounds checking

4. **Out-of-bounds comparisons**
   - `memcmp` with size larger than buffer
   - Comparing more bytes than available

5. **Raw memory vs object copying**
   - `memcpy` of struct with pointers
   - Copying more than object size

6. **Out-of-bounds iterators**
   - Iterator past `.end()`
   - Negative indexing

**Common False Positives to Avoid:**

- **Flexible array members:** `struct { int len; char data[]; }` - size determined by allocation, not declaration
- **VLAs with validated size:** `char buf[validated_size]` where validation exists upstream
- **memcpy with sizeof(dst):** `memcpy(dst, src, sizeof(dst))` - usually safe if dst is array not pointer
- **Bounded loops on fixed arrays:** `for (i = 0; i < 10; i++) arr[i]` where `char arr[10]` - provably safe
- **Static analyzer annotations:** `__attribute__((access(...)))` indicates bounds are verified
- **Size checked before use:** If size is validated against buffer capacity before the access, not a bug
- **Constant indices within bounds:** `arr[5]` when `arr` is declared as `arr[10]` - provably safe

**Search Patterns:**
```
malloc|calloc|realloc|new\s*\[
memcpy|memmove|memset|strcpy|strncpy|strcat|strncat
sprintf|snprintf|vsprintf
\[.*\]  # Array access
\+\+.*\]|\[.*\+\+  # Increment in index
for\s*\(.*<=  # Potential off-by-one loops
```
