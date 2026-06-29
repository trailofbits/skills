---
name: dll-planting-finder
description: Finds DLL hijacking/planting vulnerabilities
---

**Finding ID Prefix:** `DLLPLANT` (e.g., DLLPLANT-001, DLLPLANT-002)

**Bug Patterns to Find:**

1. **LoadLibrary Without Full Path**
   - `LoadLibrary("foo.dll")` without absolute path
   - Path from untrusted source (registry, config, CWD)
   - Missing `LOAD_LIBRARY_SEARCH_SYSTEM32` flag

2. **Missing Signature Verification**
   - `LoadLibrary` without `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET`
   - Manual signature check before load (TOCTOU)

3. **Implicit DLL Loads**
   - Delay-loaded DLLs that may not exist
   - Localization DLLs (mui, resources)
   - COM DLLs loaded by CLSID

4. **Search Order Hijacking**
   - Application directory writable by low-privilege user
   - PATH directories writable
   - Missing SafeDllSearchMode

**Common False Positives to Avoid:**

- **System DLLs with full path:** `LoadLibrary("C:\\Windows\\System32\\kernel32.dll")`
- **LOAD_LIBRARY_SEARCH_SYSTEM32 used:** Restricts search to System32
- **Protected directory:** Application installed in Program Files with proper ACLs
- **Signature required:** `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET` flag used

**Search Patterns:**
```
LoadLibrary[AW]?\s*\(|LoadLibraryEx[AW]?\s*\(
LOAD_LIBRARY_SEARCH|LOAD_LIBRARY_REQUIRE_SIGNED
GetModuleHandle[AW]?\s*\(.*NULL
delay.?load|__delayLoadHelper
```
