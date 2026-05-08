---
name: uninitialized-data-finder
description: Detects use of uninitialized memory
---

**Finding ID Prefix:** `UNINIT` (e.g., UNINIT-001, UNINIT-002)

**Bug Patterns to Find:**

1. **Uninitialized Variables**
   - Local variables used before assignment
   - Struct members not initialized
   - Array elements not set

2. **Struct Padding Disclosure**
   - Struct with padding sent over network
   - Struct written to file without zeroing
   - memcpy of struct leaks padding bytes

3. **Conditional Initialization**
   - Variable initialized only in some paths
   - Error path skips initialization

4. **Partial Initialization**
   - Some struct members set, others not
   - Array partially filled

5. **Stack/Heap Information Disclosure**
   - Returning struct with uninitialized members
   - Sending buffer with uninitialized portion

**Common False Positives to Avoid:**

- **Compiler zero-initialization:** Static/global variables are zero-initialized by default
- **Output parameters:** Variables passed to functions that initialize them (e.g., `read()` buffer)
- **Immediately overwritten:** Variable declared then immediately assigned in next statement
- **Union active member:** Only active member matters, not all members
- **Aggregate initialization:** `struct s = {0}` zero-initializes all members including padding
- **memset before use:** If buffer is zeroed with memset before being used
- **C++ value initialization:** `Type var{}` or `Type var = Type()` zero-initializes

**Search Patterns:**
```
\w+\s+\w+\s*;$  # Declaration without init
struct\s+\w+\s*\{  # Struct definitions
memset\s*\(|bzero\s*\(  # Initialization functions
send\s*\(|write\s*\(|fwrite\s*\(  # Output functions
```
