---
name: spinlock-init-finder
description: Detects spinlock initialization bugs
---

**Finding ID Prefix:** `SPINLOCK` (e.g., SPINLOCK-001, SPINLOCK-002)

**The Core Issue:**
Using `pthread_spin_trylock` (or any spinlock operation) on an uninitialized spinlock is undefined behavior and can cause deadlock or corruption.

**Bug Patterns to Find:**

1. **Missing pthread_spin_init**
   ```c
   pthread_spinlock_t lock;  // Declared but not initialized
   pthread_spin_lock(&lock);  // UB!
   ```

2. **Conditional Initialization**
   ```c
   if (condition) {
       pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);
   }
   pthread_spin_lock(&lock);  // May not be initialized
   ```

3. **Use Before Init in Constructor Order**
   - Static spinlock used before static init runs
   - Similar to static initialization order fiasco

4. **Error Path Skips Init**
   ```c
   if (pthread_spin_init(&lock, 0) != 0) {
       // Error but continues
   }
   pthread_spin_lock(&lock);  // May not be initialized
   ```

**Common False Positives to Avoid:**

- **Static zero initialization:** Static/global spinlocks are zero-initialized (may be valid on some platforms)
- **Init verified before use:** Code checks return value of pthread_spin_init and handles failure
- **Init in constructor:** C++ class initializes spinlock in constructor, use in methods
- **PTHREAD_SPINLOCK_INITIALIZER:** Static initializer macro used (if available)
- **Wrapper function initializes:** Spinlock is initialized in a wrapper/factory function

**Search Patterns:**
```
pthread_spinlock_t\s+\w+
pthread_spin_init\s*\(|pthread_spin_destroy\s*\(
pthread_spin_lock\s*\(|pthread_spin_unlock\s*\(
pthread_spin_trylock\s*\(
```
