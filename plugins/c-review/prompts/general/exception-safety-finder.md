---
name: exception-safety-finder
description: Analyzes exception safety guarantees
---

**Finding ID Prefix:** `EXCEPT` (e.g., EXCEPT-001, EXCEPT-002)

**Bug Patterns to Find:**

1. **RAII Violations**
   - Raw pointer with manual delete instead of smart pointer
   - new without corresponding delete in same scope
   - Resource acquired but not wrapped in RAII class

2. **Exception-Unsafe Code**
   - Destructor that throws
   - noexcept function that calls throwing code
   - Swap operation that can throw

3. **Resource Leaks on Exception Path**
   - Memory allocated then exception thrown before delete
   - File opened then exception before close
   - Lock acquired then exception before unlock

4. **Copy/Move Assignment Issues**
   - Self-assignment not handled with exceptions
   - Strong exception guarantee violated
   - Partial assignment on exception

5. **Constructor Exception Issues**
   - Resource acquired in constructor body (not initializer)
   - Partially constructed object on exception
   - Virtual function called in constructor

**Common False Positives to Avoid:**

- **Smart pointers used:** `unique_ptr`, `shared_ptr` handle cleanup automatically
- **RAII wrapper present:** Custom RAII class handles the resource
- **noexcept path:** If all called functions are noexcept, no exception possible
- **C code called:** extern "C" functions typically don't throw
- **Catch and handle:** Exception caught and resources cleaned up in handler
- **Finally-equivalent:** Scope guard or similar ensures cleanup

**Search Patterns:**
```
\bnew\s+\w+|\bdelete\s+\w+
~\w+\s*\(.*\)\s*\{.*throw
noexcept\s*\(|noexcept\s*\{
catch\s*\(|try\s*\{
fopen\s*\(.*\{|open\s*\(.*\{
```
