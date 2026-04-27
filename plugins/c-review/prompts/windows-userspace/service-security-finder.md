---
name: service-security-finder
description: Finds Windows service security problems
---

**Finding ID Prefix:** `WINSVC` (e.g., WINSVC-001, WINSVC-002)

**Bug Patterns to Find:**

1. **Excessive Service Privileges**
   - Service running as `SYSTEM` unnecessarily
   - Should use `LOCAL SERVICE` or `NETWORK SERVICE`
   - Missing service account restrictions

2. **Binary Path Vulnerabilities**
   - Unquoted service path with spaces
   - Service binary in writable directory
   - Parent directory writable (DLL planting)

3. **Registry ACL Issues**
   - Service registry key writable by users
   - `ImagePath` modifiable
   - Manual registry entry (not SCM APIs)

4. **Missing Protected Process**
   - Security software not using PPL
   - Anti-tampering bypassable
   - Non-protected child processes

5. **Service DACL Issues**
   - Service modifiable by non-admin users
   - `SERVICE_CHANGE_CONFIG` granted too broadly
   - Missing service hardening

**Common False Positives to Avoid:**

- **Requires SYSTEM:** Service functionality requires SYSTEM privileges
- **Program Files location:** Binary in protected directory
- **SCM-created:** Service created via proper SCM APIs
- **Protected process light:** Security software using PPL

**Search Patterns:**
```
CreateService[AW]?\s*\(|ChangeServiceConfig[AW]?\s*\(
OpenService[AW]?\s*\(|StartService\s*\(
SERVICE_WIN32|SERVICE_AUTO_START|SERVICE_DEMAND_START
LocalSystem|LocalService|NetworkService
RegCreateKey|RegSetValue.*ImagePath
PROCESS_CREATION_MITIGATION_POLICY
```
