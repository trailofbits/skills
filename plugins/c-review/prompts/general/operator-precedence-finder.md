---
name: operator-precedence-finder
description: Identifies operator precedence mistakes
---

**Finding ID Prefix:** `PREC` (e.g., PREC-001, PREC-002)

**Bug Patterns to Find:**

1. **Bitwise vs Comparison**
   - `x & mask == value` (== binds tighter than &)
   - `x | y < z` (< binds tighter than |)

2. **Bitwise vs Logical**
   - `x & y && z` (potential confusion)
   - Mixing & and && without parens

3. **Ternary Operator**
   - `a ? b : c + d` (+ is in else only)
   - Nested ternary without parens

4. **Shift Precedence**
   - `1 << n + 1` (+ happens first)
   - `x >> y & mask` (& binds tighter)

5. **Macro Expansion**
   - Macro without proper parentheses
   - `#define SQ(x) x*x` then SQ(1+1)

**Common False Positives to Avoid:**

- **Properly parenthesized:** Expression already has clarifying parentheses
- **Intentional evaluation order:** Some precedence is intentional and well-documented
- **Single-operator expressions:** No precedence issue with single operator
- **Well-known idioms:** Common patterns like `flags & MASK` without comparison
- **Compiler warnings enabled:** Many of these trigger compiler warnings that may already be addressed

**Search Patterns:**
```
&\s*\w+\s*==|&\s*\w+\s*!=|\|\s*\w+\s*<|\|\s*\w+\s*>
\?\s*.*:\s*\w+\s*[+\-*/]
<<\s*\w+\s*[+\-*/]|>>\s*\w+\s*[+\-*/]
#define\s+\w+\s*\([^)]*\)\s+[^(]
```
