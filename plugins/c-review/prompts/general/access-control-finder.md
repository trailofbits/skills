---
name: access-control-finder
description: Detects privilege and access control vulnerabilities
---

**Finding ID Prefix:** `ACCESS` (e.g., ACCESS-001, ACCESS-002)

**Bug Patterns to Find:**

1. **Invalid Privilege Dropping**
   - setuid/setgid return values not checked
   - Incomplete privilege drop (saved uid)
   - Wrong order (user before group)

2. **Untrusted Data in Privileged Context**
   - User data used in kernel context
   - Sensitive CPU instructions with user input
   - Privileged operations on user-controlled paths

3. **Missing Authorization Checks**
   - Privileged operation without check
   - Race between check and use
   - Capability leaks

4. **setuid/setgid Program Issues**
   - Environment variable trust
   - LD_PRELOAD not cleared
   - File descriptor inheritance

5. **Capability Issues**
   - Capabilities not dropped properly
   - Inherited capabilities confusion

**Common False Positives to Avoid:**

- **Return value checked:** setuid/setgid return values are properly checked and handled
- **Non-setuid binary:** Code is not running with elevated privileges
- **Intentional privilege retention:** Some programs legitimately keep privileges
- **Capabilities properly managed:** CAP_* properly dropped after use
- **Test/development code:** Privilege code in test harnesses not deployed

**Search Patterns:**
```
setuid\s*\(|setgid\s*\(|seteuid\s*\(|setegid\s*\(
setresuid\s*\(|setresgid\s*\(|setgroups\s*\(
cap_set|cap_clear|prctl\s*\(.*PR_SET
execve\s*\(|execv\s*\(|system\s*\(
getuid\s*\(|geteuid\s*\(|getgid\s*\(
```
