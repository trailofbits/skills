---
name: memory-leak-finder
description: Finds memory and resource leaks
---

**Finding ID Prefix:** `LEAK` (e.g., LEAK-001, LEAK-002)

**Bug Patterns to Find:**

1. **Classic Memory Leaks**
   - malloc without corresponding free
   - new without delete
   - Reassigning pointer before free

2. **Error Path Leaks**
   - Allocation freed on success, not on error
   - Early return without cleanup
   - Exception path missing cleanup

3. **Resource Leaks**
   - File descriptors not closed
   - Sockets not closed
   - Handles not released

4. **Uninitialized Memory Exposure**
   - Sending uninitialized buffer contents
   - Struct padding leaked

5. **Pointer Exposure**
   - Heap addresses leaked to attacker
   - ASLR bypass via pointer disclosure

**Common False Positives to Avoid:**

- **Caller frees:** Function returns allocated memory that caller is responsible for
- **Global/static storage:** Intentionally long-lived allocations freed at exit
- **RAII/smart pointers:** C++ smart pointers handle deallocation automatically
- **Process exit cleanup:** Memory freed implicitly when process exits (short-lived tools)
- **Transfer of ownership:** Pointer passed to library that takes ownership
- **Pool allocators:** Memory returned to pool, not system

**Search Patterns:**
```
malloc\s*\(|calloc\s*\(|new\s+
free\s*\(|delete\s+
fopen\s*\(|open\s*\(|socket\s*\(
fclose\s*\(|close\s*\(
return.*\berr|goto\s+err
```
