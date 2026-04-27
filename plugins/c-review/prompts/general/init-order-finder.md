---
name: init-order-finder
description: Detects static initialization order fiasco
---

**Finding ID Prefix:** `INIT` (e.g., INIT-001, INIT-002)

**Bug Patterns to Find:**

1. **Static Initialization Order Fiasco**
   - Global object depends on another global
   - Order of initialization across translation units
   - Static variable in one file uses another file's static

2. **Construct-on-First-Use Failures**
   - Singleton pattern race conditions
   - Local static initialization issues

3. **Initialization List Order**
   - Members initialized out of declaration order
   - Base class vs member initialization order

4. **Thread-Unsafe Static Initialization**
   - Static locals in multi-threaded code (pre-C++11)
   - Global initialization races

**Common False Positives to Avoid:**

- **Same translation unit:** Globals in same .cpp file initialize in declaration order
- **constexpr/constinit:** Compile-time constants don't have runtime init order issues
- **POD types with literal init:** `int x = 5;` is compile-time initialized
- **C++11 thread-safe statics:** Local statics are thread-safe in C++11+
- **Explicit init functions:** Code uses explicit init() functions instead of constructors
- **Header-only globals:** `inline` globals have defined behavior in C++17+

**Search Patterns:**
```
^static\s+\w+.*=|^extern\s+\w+
static\s+\w+\s+\w+\s*=.*::
Singleton|GetInstance|Instance\(\)
:\s*\w+\(.*\),\s*\w+\(  # Initialization lists
```
