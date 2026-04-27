---
name: integer-overflow-finder
description: Detects integer overflow and signedness issues
---

**Finding ID Prefix:** `INT` (e.g., INT-001, INT-002)

**Bug Patterns to Find:**

1. **Arithmetic Overflows**
   - `a + b` where result exceeds type range
   - `a * b` multiplication overflow
   - Size calculations: `n * sizeof(type)`

2. **Widthness Overflows**
   - 64-bit value assigned to 32-bit variable
   - Large value truncated to smaller type

3. **Signedness Bugs**
   - Signed/unsigned comparison
   - Negative value interpreted as large unsigned
   - `int` used where `size_t` expected

4. **Implicit Conversions**
   - Unexpected type promotion/demotion
   - Integer to pointer conversion

5. **Negative Assignment Overflow**
   - `abs(-INT_MIN) == -INT_MIN`
   - `-(-INT_MIN)` still negative

6. **Integer Cut**
   - Read 64-bit, compare 32-bit, use 64-bit
   - Mask or truncate then use full value

7. **Rounding Errors**
   - Integer division truncation issues
   - Lost precision in calculations

8. **Float Imprecision**
   - Direct float comparison without epsilon
   - Float used for financial/precise calculations

**Common False Positives to Avoid:**

- **Checked arithmetic:** If overflow is explicitly checked before use (e.g., `if (a > SIZE_MAX - b)`)
- **Safe integer libraries:** `SafeInt<>`, `__builtin_add_overflow`, or similar checked operations
- **Known small values:** Constants or validated inputs that can't overflow (e.g., `argc * 4`)
- **Intentional wrapping:** Hash functions, checksums, crypto often use intentional wrapping
- **Unsigned comparison with zero:** `unsigned >= 0` is always true but not a security bug
- **Loop counters with known bounds:** `for (int i = 0; i < 100; i++)` can't overflow
- **Sizeof expressions with small n:** `sizeof(x) * n` where n is a small constant

**Search Patterns:**
```
\*\s*sizeof|\+\s*sizeof
\(int\)|\(unsigned\)|\(size_t\)|\(long\)
abs\s*\(|labs\s*\(
<=\s*0|>=\s*0.*unsigned
malloc\s*\(.*\*|calloc\s*\(
```
