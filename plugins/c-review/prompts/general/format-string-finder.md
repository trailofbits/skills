---
name: format-string-finder
description: Identifies format string vulnerabilities
---

**Finding ID Prefix:** `FMT` (e.g., FMT-001, FMT-002)

**Bug Patterns to Find:**

1. **User Input as Format String**
   - `printf(user_input)` instead of `printf("%s", user_input)`
   - `syslog(priority, user_input)`
   - `fprintf(file, user_input)`

2. **Type Mismatch Bugs**
   - `%d` with pointer argument
   - `%s` with integer argument
   - `%n` anywhere (write primitive)
   - Wrong size specifier (`%d` vs `%ld`)

3. **Custom Printf-like Functions**
   - Wrapper functions forwarding to printf
   - Missing `__attribute__((format))` annotation

4. **Scanf Format Issues**
   - `%s` without width limit
   - Type mismatches in scanf

**Common False Positives to Avoid:**

- **Literal format strings:** `printf("Hello %s", name)` - format is constant, not attacker-controlled
- **Format from trusted source:** Config loaded at compile time, not runtime user input
- **FORTIFY_SOURCE protected:** Modern glibc with `-D_FORTIFY_SOURCE=2` catches many format bugs
- **Format attribute present:** Functions with `__attribute__((format(printf, ...)))` are compiler-checked
- **Indirect but validated:** Format string from array indexed by validated enum

**Search Patterns:**
```
printf\s*\(|fprintf\s*\(|sprintf\s*\(|snprintf\s*\(
syslog\s*\(|vsprintf\s*\(|vprintf\s*\(
scanf\s*\(|sscanf\s*\(|fscanf\s*\(
%n|%\d*\$
__attribute__.*format
```
