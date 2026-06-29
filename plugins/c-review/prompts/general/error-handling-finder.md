---
name: error-handling-finder
description: Finds missing or improper error handling
---

**Finding ID Prefix:** `ERR` (e.g., ERR-001, ERR-002)

**Bug Patterns to Find:**

1. **Unchecked Return Values**
   - Ignoring malloc/fopen/socket return
   - Ignoring write/read return
   - Ignoring security-critical function returns

2. **Incorrect Error Comparison**
   - `if (retval != 0)` when success is 1
   - `if (retval)` when -1 is error
   - Comparing wrong error codes

3. **Exception Handling Issues**
   - Catch-all hiding errors
   - Exception during cleanup
   - Resource leak on exception path

4. **Partial Error Handling**
   - Some errors handled, others not
   - Error logged but not propagated

5. **Error State Corruption**
   - Continuing after error
   - Partial operation on error

**Common False Positives to Avoid:**

- **Intentionally ignored:** `(void)close(fd)` - cast to void indicates intentional
- **Non-critical function:** `printf()` return rarely matters for security
- **Wrapper handles error:** Error handled in called wrapper function
- **Assert on error:** `assert(func() == 0)` catches in debug builds
- **Logging functions:** `syslog()`, `fprintf(stderr, ...)` return values rarely matter
- **Best-effort operations:** Close/cleanup operations where failure doesn't affect security

**Search Patterns:**
```
=\s*(malloc|calloc|fopen|socket|connect|open)\s*\(
if\s*\(.*==\s*-1|if\s*\(.*!=\s*0
catch\s*\(|throw\s+
errno\s*=|perror\s*\(
```
