---
name: named-pipe-finder
description: Identifies named pipe security issues
---

**Finding ID Prefix:** `NAMEDPIPE` (e.g., NAMEDPIPE-001, NAMEDPIPE-002)

**Bug Patterns to Find:**

1. **Missing Security Descriptor**
   - `lpSecurityAttributes` is NULL
   - Default DACL allows Everyone access
   - No explicit ACL on pipe

2. **Remote Access Enabled**
   - Missing `PIPE_REJECT_REMOTE_CLIENTS` flag
   - Pipe accessible over network

3. **Single Instance DoS**
   - `nMaxInstances` is 1
   - Malicious process can claim pipe first
   - Legitimate client blocked

4. **Impersonation Without Verification**
   - `ImpersonateNamedPipeClient` without checking client identity
   - Privilege escalation via token impersonation

5. **Data Validation**
   - Untrusted data from pipe not validated
   - Deserialization of pipe data
   - Command injection via pipe input

**Common False Positives to Avoid:**

- **Explicit restrictive DACL:** Security descriptor properly configured
- **PIPE_REJECT_REMOTE_CLIENTS set:** Remote access blocked
- **High nMaxInstances:** Multiple instances prevent DoS
- **Server-side only:** Pipe used only for server-to-client communication

**Search Patterns:**
```
CreateNamedPipe[AW]?\s*\(|CallNamedPipe[AW]?\s*\(
\\\\\\\\.\\\\pipe\\\\|\\\\\\?\\\\pipe\\\\
PIPE_REJECT_REMOTE_CLIENTS|PIPE_ACCESS
ImpersonateNamedPipeClient|RevertToSelf
lpSecurityAttributes|SECURITY_ATTRIBUTES
```
