---
name: overlapping-buffers-finder
description: Detects overlapping buffer bugs
---

**Finding ID Prefix:** `OVERLAP` (e.g., OVERLAP-001, OVERLAP-002)

**Bug Patterns to Find:**

1. **Same Buffer as Input and Output**
   - `snprintf(buf, size, "%s...", buf)` - UB
   - `sprintf(buf, "%s...", buf)` - UB
   - `vsprintf` with overlapping args

2. **memcpy with Overlap**
   - `memcpy(dst, src, n)` where src+n > dst
   - Must use `memmove` for overlapping regions

3. **String Operations with Overlap**
   - `strcat(s, s+n)` - may overlap
   - `strcpy` with overlapping regions

4. **Source + Offset Overlap**
   - `memcpy(buf+10, buf, 20)` - overlaps
   - Offset doesn't prevent overlap

**Common False Positives to Avoid:**

- **memmove used:** memmove is designed for overlapping regions
- **Different buffers:** Pointers proven to point to different allocations
- **Non-overlapping regions:** Even within same buffer, regions may not overlap
- **Intermediate copy:** Data copied to temporary buffer first
- **String doesn't self-reference:** snprintf format doesn't use the destination buffer

**Search Patterns:**
```
snprintf\s*\([^,]+,\s*[^,]+,\s*[^,]*%s       # snprintf with %s — read each hit to see if dst aliases a %s arg
sprintf\s*\([^,]+,\s*[^,]*%s                 # sprintf with %s — same
memcpy\s*\(|strcpy\s*\(|strncpy\s*\(
memmove\s*\(  # This is the safe one
```
