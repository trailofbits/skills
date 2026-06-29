---
name: printf-attr-finder
description: Finds missing printf format attributes
---

**Finding ID Prefix:** `PRINTFATTR` (e.g., PRINTFATTR-001, PRINTFATTR-002)

**The Core Issue:**
Custom printf-like functions should have `__attribute__((format(printf, ...)))` so the compiler can check format strings against arguments.

```c
// Dangerous - compiler can't check format strings
void log_error(const char *fmt, ...) {
    // Forwards to vfprintf
}
log_error("%s %d", ptr);  // Type mismatch not caught!

// Safe - compiler checks format strings
__attribute__((format(printf, 1, 2)))
void log_error(const char *fmt, ...) {
    // Forwards to vfprintf
}
log_error("%s %d", ptr);  // Compiler warning!
```

**Bug Patterns to Find:**

1. **Wrapper Functions Without Attribute**
   ```c
   void debug_print(const char *fmt, ...) {
       va_list args;
       va_start(args, fmt);
       vprintf(fmt, args);
       va_end(args);
   }
   ```

2. **Logging Functions Without Attribute**
   ```c
   void log_message(int level, const char *fmt, ...) {
       // Uses vfprintf or similar
   }
   ```

3. **Error Handling Functions**
   ```c
   void die(const char *fmt, ...) {
       // Prints error and exits
   }
   ```

**Common False Positives to Avoid:**

- **Attribute already present:** Function already has `__attribute__((format(printf, ...)))`
- **Not a printf wrapper:** Function doesn't forward to printf family
- **Macro wrapper:** Format checking done through macro that expands to attributed function
- **Fixed format:** Function takes fixed format, not user-supplied
- **Type-safe wrapper:** C++ variadic template that's type-safe

**Search Patterns:**
```
\.\.\.\s*\)|va_list|va_start|va_end
vprintf|vfprintf|vsprintf|vsnprintf|vsyslog
__attribute__.*format.*printf
void\s+\w+\s*\([^)]*const\s+char\s*\*[^)]*\.\.\.\s*\)
```
