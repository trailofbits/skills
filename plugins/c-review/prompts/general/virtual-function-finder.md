---
name: virtual-function-finder
description: Finds virtual function vulnerabilities
---

**Finding ID Prefix:** `VIRT` (e.g., VIRT-001, VIRT-002)

**Bug Patterns to Find:**

1. **Missing Virtual Destructor**
   - Base class with virtual methods but non-virtual destructor
   - delete through base pointer leaks derived resources
   - Polymorphic class without virtual destructor

2. **Object Slicing**
   - Derived object assigned to base object by value
   - Base class copy/move from derived
   - Vector<Base> containing Derived objects

3. **Override Issues**
   - Missing override keyword hides bug
   - Signature mismatch creating new virtual
   - Covariant return type issues

4. **Virtual in Constructor/Destructor**
   - Virtual call in constructor calls base version
   - Pure virtual called during construction/destruction
   - Dynamic type not yet established

5. **Multiple Inheritance Diamond**
   - Virtual inheritance issues
   - Ambiguous base access
   - Constructor order problems

**Common False Positives to Avoid:**

- **Final class:** Class marked final doesn't need virtual destructor
- **Non-polymorphic base:** Base without virtual functions is fine without virtual destructor
- **Intentional slicing:** Sometimes slicing is intentional (copying base portion)
- **override present:** If override keyword is there, compiler checks signature
- **CRTP pattern:** Curiously recurring template pattern intentionally non-virtual

**Search Patterns:**
```
virtual\s+\w+|virtual\s+~
class\s+\w+\s*:\s*public
override|final
\(\s*\w+\s+\w+\s*\)|vector<\w+>
~\w+\s*\(\s*\)\s*[^=]
```
