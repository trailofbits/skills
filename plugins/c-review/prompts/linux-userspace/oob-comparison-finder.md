---
name: oob-comparison-finder
description: Detects out-of-bounds comparison bugs
---

**Finding ID Prefix:** `OOBCMP` (e.g., OOBCMP-001, OOBCMP-002)

**Bug Patterns to Find:**

1. **std::equal with Unequal Lengths**
   - Three-iterator form: `std::equal(a.begin(), a.end(), b.begin())`
   - Reads from b even if b is shorter
   - Use four-iterator form or check sizes first

2. **memcmp Size Errors**
   - Size larger than smaller buffer
   - Size from wrong buffer
   - Unchecked size parameter

3. **strncmp Issues**
   - Size larger than shorter string
   - Comparing with size from wrong source
   - Not checking string length first

4. **bcmp Issues**
   - Same problems as memcmp
   - Deprecated but still used

**Common False Positives to Avoid:**

- **Sizes validated first:** Code checks buffer sizes before comparison
- **Equal-sized buffers:** Both buffers are known to be at least comparison size
- **Four-iterator std::equal:** `std::equal(a.begin(), a.end(), b.begin(), b.end())` is safe
- **Compile-time known sizes:** Buffers are fixed-size arrays with known dimensions
- **Size comes from smaller buffer:** Comparison size derived from minimum of both sizes

**Search Patterns:**
```
std::equal\s*\(|memcmp\s*\(|strncmp\s*\(|bcmp\s*\(
wcsncmp\s*\(|wmemcmp\s*\(
\.begin\(\).*\.begin\(\)      # two begin() calls; verify via Read that both ends are properly bounded
```
