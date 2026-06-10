---
name: installer-race-finder
description: Detects installer race conditions
---

**Finding ID Prefix:** `INSTRACE` (e.g., INSTRACE-001, INSTRACE-002)

**Bug Patterns to Find:**

1. **Temp File Race Conditions**
   - Extract to temp, then copy to final location
   - Predictable temp file names
   - Missing exclusive file access

2. **MSI Rollback Exploitation**
   - Arbitrary file deletion → privilege escalation
   - Rollback restores attacker-controlled file
   - Custom actions during rollback

3. **Symlink/Junction Attacks**
   - Temp directory junction to system directory
   - Extracted file overwrites system file
   - Missing directory validation

4. **Permission Window**
   - File extracted with weak permissions
   - Permissions tightened later (TOCTOU)
   - Attacker modifies file between operations

5. **Signature Verification TOCTOU**
   - Signature checked on temp file
   - Different file copied to final location
   - Missing re-verification after copy

**Common False Positives to Avoid:**

- **Atomic operations:** Single operation extracts and sets permissions
- **Locked directory:** Temp directory only accessible by SYSTEM
- **Exclusive access:** File opened with exclusive sharing
- **No privilege boundary:** Installer runs at same privilege as user

**Search Patterns:**
```
GetTempPath|GetTempFileName|CreateFile.*GENERIC_WRITE
MoveFile|CopyFile|DeleteFile.*temp
SetFileSecurity|SetSecurityInfo|SetNamedSecurityInfo
MsiInstall|MsiOpenPackage|MsiDoAction
INSTALLSTATE_|MsiSetProperty|MsiGetProperty
```
