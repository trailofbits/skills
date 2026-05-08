---
name: privilege-drop-finder
description: Detects privilege dropping mistakes
---

**Finding ID Prefix:** `PRIVDROP` (e.g., PRIVDROP-001, PRIVDROP-002)

**Bug Patterns to Find:**

1. **Unchecked Return Values**
   - `setuid(uid)` return not checked
   - `setgid(gid)` return not checked
   - Can fail silently, leaving privileges

2. **Incomplete Privilege Drop**
   - `seteuid(X)` followed by `setuid(X)` may not drop permanently
   - Saved-set-user-ID not cleared
   - Use `setresuid(uid, uid, uid)` for complete drop

3. **Wrong Order**
   - User privileges dropped before group
   - Once user privileges dropped, can't change group
   - Drop group privileges first, then user

4. **Missing Verification**
   - Privileges not verified after dropping
   - Should call `getuid()/geteuid()` to confirm
   - Check `getgroups()` for supplementary groups

5. **Inherited Resources**
   - File descriptors preserved across exec
   - ioperm permissions preserved
   - Capabilities inheritance complexity

6. **vfork Caveats**
   - Different privileges in same address space
   - Child can corrupt parent state

**Common False Positives to Avoid:**

- **Return values checked:** Code checks return value and handles failure
- **setresuid used:** Using setresuid(uid, uid, uid) for complete drop
- **Correct order:** Group dropped before user
- **Verification present:** Code verifies privileges after dropping
- **Non-privileged program:** Program doesn't run with elevated privileges

**Search Patterns:**
```
setuid\s*\(|setgid\s*\(|seteuid\s*\(|setegid\s*\(
setresuid\s*\(|setresgid\s*\(|setgroups\s*\(
getuid\s*\(|geteuid\s*\(|getgid\s*\(|getegid\s*\(
initgroups\s*\(|setgroups\s*\(
cap_set_proc|prctl\s*\(.*CAP
```
