---
name: move-semantics-finder
description: Identifies move semantics misuse
---

**Finding ID Prefix:** `MOVE` (e.g., MOVE-001, MOVE-002)

**Bug Patterns to Find:**

1. **Use After Move**
   - Accessing object after std::move()
   - Using moved-from container (size, iteration)
   - Calling methods on moved-from object

2. **Invalid Move Operations**
   - Moving const object (falls back to copy)
   - Moving non-moveable type
   - Self-move assignment

3. **Move in Loop**
   - std::move in loop body reuses moved-from object
   - Lambda capturing by move used multiple times

4. **Forwarding Issues**
   - std::forward on non-forwarding reference
   - Perfect forwarding breaking value category
   - Missing std::forward in template

5. **Move Constructor Issues**
   - Move constructor that copies
   - Move leaves source in invalid state
   - noexcept move required but missing

**Common False Positives to Avoid:**

- **Reassigned after move:** Object assigned new value before next use
- **Moved into function:** Object moved into function, never used again in caller
- **Valid moved-from state:** Some types (std::unique_ptr) have defined moved-from state
- **Move of primitive:** Primitives just copy, no moved-from issue
- **Conditional move:** Move only happens on certain paths, use on others is safe

**Search Patterns:**
```
std::move\s*\(
std::forward\s*\(
&&\s*\w+|T&&|auto&&
noexcept.*move|move.*noexcept
\w+\s*=\s*std::move\s*\(
```
