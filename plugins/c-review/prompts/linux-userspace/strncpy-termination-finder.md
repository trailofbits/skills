---
name: strncpy-termination-finder
description: Identifies strncpy null termination issues
---

**Finding ID Prefix:** `STRNCPY` (e.g., STRNCPY-001, STRNCPY-002)

**The Core Issue:**
`strncpy(dst, src, n)` does NOT null-terminate if `strlen(src) >= n`

```c
char buf[10];
strncpy(buf, user_input, sizeof(buf));
printf("%s", buf);  // May read past buf if input >= 10 chars!
```

**Bug Patterns to Find:**

1. **No Manual Null Termination**
   ```c
   strncpy(buf, src, sizeof(buf));
   // Missing: buf[sizeof(buf)-1] = '\0';
   use_string(buf);  // May not be terminated!
   ```

2. **Null Termination in Wrong Place**
   ```c
   strncpy(buf, src, n);
   buf[n] = '\0';  // Off by one! Should be buf[n-1]
   ```

3. **Conditional Termination Missing**
   ```c
   strncpy(buf, src, sizeof(buf));
   if (strlen(src) < sizeof(buf))  // Only terminates if short
       // ... but what if longer?
   ```

**Correct Usage:**
```c
strncpy(buf, src, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';
// Or better: use strlcpy if available
```

**Common False Positives to Avoid:**

- **Manual null termination present:** Code sets `buf[sizeof(buf)-1] = '\0'` after strncpy
- **strlcpy used:** Using strlcpy which always null-terminates
- **Size includes room for null:** strncpy(buf, src, sizeof(buf)-1) leaves room
- **Destination pre-zeroed:** Buffer is memset to 0 before strncpy
- **Fixed-width field:** Buffer used for fixed-width records, not as C string

**Search Patterns:**
```
strncpy\s*\(
wcsncpy\s*\(
\[\s*sizeof.*-\s*1\s*\]\s*=\s*['"\\]0|=\s*'\0'
```
