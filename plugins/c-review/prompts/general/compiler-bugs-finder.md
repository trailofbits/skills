---
name: compiler-bugs-finder
description: Identifies patterns that trigger compiler optimization bugs
---

**Finding ID Prefix:** `COMP` (e.g., COMP-001, COMP-002)

**Bug Patterns to Find:**

1. **Removed Bounds Checks**
   - Compiler optimizes away null pointer checks
   - -fdelete-null-pointer-checks removing validation
   - Dead code elimination of security checks

2. **Removed Data Zeroization**
   - memset of sensitive data optimized away
   - SecureZeroMemory not used
   - explicit_bzero required but memset used

3. **Constant-Time Violation**
   - Compiler optimizing constant-time code
   - Short-circuit evaluation breaking timing
   - Branch prediction affecting security

4. **Debug Assertion Removal**
   - assert() removed in release builds
   - Security-critical checks in assert
   - NDEBUG removing validation

**Common False Positives to Avoid:**

- **explicit_bzero/SecureZeroMemory used:** Proper secure memory clearing functions in place
- **Volatile access:** volatile qualifier prevents optimization
- **Compiler barriers:** Memory barriers or asm volatile prevent reordering
- **Non-sensitive data:** memset on non-sensitive data can safely be optimized away
- **Check not security-relevant:** Null check for debug/logging purposes, not security

**Search Patterns:**
```
memset\s*\(.*0\s*\)|bzero\s*\(
explicit_bzero|SecureZeroMemory|volatile.*memset
assert\s*\(|ASSERT\s*\(|DEBUG_ASSERT
-O[23s]|-fdelete-null-pointer-checks
if\s*\(\s*\w+\s*!=\s*NULL\s*\).*\*\w+
```
