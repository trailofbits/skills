---
name: smart-pointer-finder
description: Detects smart pointer misuse patterns
---

**Finding ID Prefix:** `SPTR` (e.g., SPTR-001, SPTR-002)

**Bug Patterns to Find:**

1. **Circular References**
   - shared_ptr cycle causing memory leak
   - Parent-child with both using shared_ptr
   - Observer pattern with shared_ptr

2. **Dangling weak_ptr Issues**
   - Using weak_ptr::lock() result without checking
   - Storing raw pointer from weak_ptr::lock()
   - Race between expired() and lock()

3. **Ownership Problems**
   - Multiple unique_ptr to same object
   - shared_ptr from raw pointer to already-managed object
   - Returning raw pointer from unique_ptr-managed object

4. **Performance/Correctness**
   - make_shared not used (exception safety)
   - shared_ptr copy in loop (refcount overhead)
   - unique_ptr where shared_ptr used

5. **Aliasing Issues**
   - shared_ptr aliasing constructor misuse
   - Storing pointer to subobject that outlives parent

**Common False Positives to Avoid:**

- **weak_ptr used correctly:** weak_ptr breaks cycles intentionally
- **enable_shared_from_this:** Proper pattern for self-shared_ptr
- **Custom deleter:** Null deleter or custom delete is intentional
- **Aliasing for subobject:** Valid use of aliasing constructor
- **Refcount checked:** lock() result is properly checked before use

**Search Patterns:**
```
shared_ptr|unique_ptr|weak_ptr
make_shared|make_unique
\.get\(\)|\.release\(\)
enable_shared_from_this|shared_from_this
weak_ptr.*lock\(\)
```
