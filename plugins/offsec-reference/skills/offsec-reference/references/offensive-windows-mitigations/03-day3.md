## Day 3: Control Flow Integrity (CFG, CET, XFG)

- **Goal**: Understand modern control-flow protection mechanisms.
- **Activities**:
  - _Reading_:
    - [Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)
    - [Intel CET Documentation](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)
  - _Online Resources_:
    - [CFG Internals](https://blackhat.com/docs/us-15/materials/us-15-Zhang-Bypass-Control-Flow-Guard-Comprehensively-wp.pdf)
    - [CET Deep Dive](https://cdrdv2-public.intel.com/784473/784473_Intel%20Platform%20Security.pdf)
  - _Tool Setup_:
    - Windows 11 24H2 (for CET support)
    - Visual Studio 2022
    - WinDbg Preview
  - _Exercise_:
    - Enable CFG and test indirect call protection
    - Verify CET shadow stack
    - Observe XFG strict enforcement

### Control Flow Guard (CFG)

**What is CFG?**:

- Validates indirect call/jump targets
- Prevents control-flow hijacking
- Introduced in Windows 8.1/10
- Compiler + OS enforcement

**How CFG Works**:

```c
// Without CFG:
void (*func_ptr)() = user_controlled_value;
func_ptr();  // Jumps anywhere!

// With CFG:
void (*func_ptr)() = user_controlled_value;
// Compiler inserts:
if (!__guard_check_icall_fptr(func_ptr)) {
    __guard_icall_failure(func_ptr);  // Terminates
}
func_ptr();  // Only if valid target
```

### CFG Protection Scope: What It Blocks vs. What It Doesn't

> [!IMPORTANT]
> **CFG is forward-edge CFI only.** It validates indirect calls and jumps, but does NOT
> protect return addresses (backward-edge). ROP attacks using `ret` instructions are
> NOT blocked by CFG—that's what CET Shadow Stack is for.

**CFG Protection Matrix**:

| Attack Type                         | CFG Blocks? | Why / Why Not                                       |
| ----------------------------------- | ----------- | --------------------------------------------------- |
| **Indirect call to shellcode**      | Yes         | Shellcode address not in valid target bitmap        |
| **Indirect call to non-CFG DLL**    | Yes         | Non-CFG module functions not marked valid           |
| **vtable pointer overwrite**        | Yes\*       | \*Only if call site is CFG-instrumented             |
| **Function pointer overwrite**      | Yes\*       | \*Only if the call site uses `__guard_check_icall`  |
| **ROP chain (using `ret`)**         | No          | CFG doesn't validate return addresses               |
| **Direct call to attacker code**    | No          | Direct calls (`call 0x1234`) not validated          |
| **JOP (jump-oriented programming)** | Partial     | CFG validates `jmp [reg]` but not all gadget chains |
| **Data-only attacks**               | No          | CFG only protects control flow, not data            |
| **Calling valid but dangerous API** | No          | `VirtualProtect` is a valid CFG target              |
| **Type confusion (same signature)** | No          | CFG doesn't check function types (XFG does)         |

**Key Limitations to Understand**:

```text
CFG Limitation 1: Forward-Edge Only
-----------------------------------
CFG validates: call [rax], jmp [rax]
CFG ignores:   ret (return instructions)

ROP chains work because 'ret' pops address from stack and jumps.
CFG doesn't check these - the attacker controls the stack.

CFG Limitation 2: Call Site Must Be Instrumented
------------------------------------------------
CFG check only happens if:
1. Binary compiled with /guard:cf
2. Specific call site has guard check instrumentation

If the call site is in non-CFG code, NO validation occurs!

CFG Limitation 3: All Valid Functions Are Fair Game
---------------------------------------------------
If attacker overwrites function pointer to point to:
- VirtualProtect (valid target) -> Can make shellcode executable
- WinExec (valid target) -> Can execute arbitrary commands
- Any exported function -> These are all "valid"

This is why XFG (type checking) was developed.
```

**Lab: VTable Hijacking vs. CFG (C++)**

Week 5 touched on VTable smashing. This lab demonstrates the coarse-grained
nature of CFG: it blocks calls to shellcode or mid-function addresses, but
ALLOWS calls to valid function entries — even if the function was never
intended to be called from that call site.

Create `src\vtable_cfg_test.cpp`:

```cpp
// vtable_cfg_test.cpp
// Demonstrates CFG's coarse-grained behavior with vtable hijacking.
//
// Test 1: Redirect vtable to malicious_code (a valid function entry)
//         -> CFG ALLOWS this because malicious_code is in the CFG bitmap!
// Test 2: Redirect vtable to a shellcode address (not a valid function)
//         -> CFG BLOCKS this with __fastfail -> exit code 0x80000003
//
// This proves CFG only checks "is target a valid function entry?"
// — NOT "should this virtual call dispatch to that function?"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

class Shape {
public:
    virtual void draw() { printf("[*] Drawing Shape\n"); }
    virtual ~Shape() {}
};

class Circle : public Shape {
public:
    void draw() override { printf("[*] Drawing Circle\n"); }
};

void malicious_code() {
    printf("[!] PWNED: Malicious code executed!\n");
    printf("[!] This proves CFG is coarse-grained — malicious_code\n");
    printf("    is a valid function entry, so CFG allowed the call.\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    int test_mode = 1;  // Default: test 1 (valid function redirect)
    if (argc > 1) test_mode = atoi(argv[1]);

    Shape* shape = new Circle();
    printf("[*] Shape object at: %p\n", shape);
    printf("[*] Original VTable pointer: %p\n", *(void**)shape);
    fflush(stdout);

    if (test_mode == 1) {
        // TEST 1: Redirect to a valid function entry
        // CFG bitmap has malicious_code marked as valid -> call ALLOWED
        printf("\n[*] TEST 1: Redirect vtable to malicious_code (valid entry)\n");
        void* fake_vtable[] = { (void*)&malicious_code, NULL };
        printf("[*] Fake vtable at %p -> malicious_code at %p\n",
               fake_vtable, (void*)&malicious_code);
        *(void**)shape = fake_vtable;
        printf("[*] Calling shape->draw()...\n");
        fflush(stdout);
        shape->draw();  // CFG ALLOWS — malicious_code is a valid function!
        printf("[+] Call succeeded (CFG allowed it)\n");
    }
    else if (test_mode == 2) {
        // TEST 2: Redirect to arbitrary address (NOT a valid function)
        // 0xDEADDEAD is not in CFG bitmap -> call BLOCKED
        printf("\n[*] TEST 2: Redirect vtable to 0xDEADDEAD (invalid)\n");
        void* bad_vtable[] = { (void*)0xDEADDEAD, NULL };
        *(void**)shape = bad_vtable;
        printf("[*] Calling shape->draw()...\n");
        fflush(stdout);
        shape->draw();  // CFG BLOCKS — 0xDEADDEAD not in bitmap!
        printf("[-] Should not reach here\n");
    }

    delete shape;
    return 0;
}
```

**Compile & Run**:

```bash
# Save to C:\Windows_Mitigations_Lab\src\vtable_cfg_test.cpp
cd C:\Windows_Mitigations_Lab

# 1. Without CFG — both tests "work" (no validation)
cl /EHsc /Zi src\vtable_cfg_test.cpp /Fe:bin\vtable_no_cfg.exe /link /DEBUG
.\bin\vtable_no_cfg.exe 1
# [!] PWNED: Malicious code executed!
.\bin\vtable_no_cfg.exe 2
# (Process crashes - Access violation at 0xDEADDEAD)

# 2. With CFG — Test 1 STILL works! Test 2 is blocked.
cl /EHsc /Zi /guard:cf src\vtable_cfg_test.cpp /Fe:bin\vtable_cfg.exe /link /guard:cf /DEBUG
.\bin\vtable_cfg.exe 1
# [!] PWNED: Malicious code executed!
# [!] This proves CFG is coarse-grained — malicious_code

.\bin\vtable_cfg.exe 2
# (Process killed by __fastfail - Exit code: 0x80000003 via int 0x29)
# CFG blocks it — 0xDEADDEAD is NOT in the CFG bitmap
```

> [!WARNING]
> **CFG does NOT prevent vtable-to-valid-function redirects!** `malicious_code` is a
> legitimate function entry point in the binary, so CFG allows the call. This is the
> same coarse-grained limitation proven in Day 2 Technique 3: CFG checks "is target
> ANY valid function?" — not "should THIS vtable dispatch THAT function."
> Only XFG (type-hash validation) or Clang's `-fsanitize=cfi` would block this.

**Verifying CFG Instrumentation at Call Sites**:

```bash
# Example with CFG-enabled binary (vtable_cfg.exe):
dumpbin /headers /loadconfig bin\vtable_cfg.exe | findstr -i "guard"
#    00000001400B8000 Guard CF address of check-function pointer
#    00000001400B8020 Guard CF address of dispatch-function pointer
#    00000001400B7000 Guard CF function table
#                  6D Guard CF function count        ← 109 functions protected
#            10014500 Guard Flags                    ← CF Instrumented (bit 0x10000000)
#    00000001400B8010 Guard XFG address of check-function pointer

# Example without CFG (vtable_no_cfg.exe):
dumpbin /headers /loadconfig bin\vtable_no_cfg.exe | findstr -i "guard"
#    00000001400A6000 Guard CF address of check-function pointer
#    00000001400A6020 Guard CF address of dispatch-function pointer
#    0000000000000000 Guard CF function table        ← No table (null)
#                   0 Guard CF function count        ← Zero functions protected
#            00000100 Guard Flags                    ← NOT instrumented (no 0x10000000)

# Key differences:
#   CFG Enabled:  Guard CF function count > 0, Guard Flags has 0x10000000 bit set
#   CFG Disabled: Guard CF function count = 0, Guard Flags = 0x100 (reserved bits only)
```

**Exercise: CFG Heap Function Pointer Overwrite — Coarse vs Fine Grained**:

```c
// cfg_heap_test.c
// Demonstrates the coarse-grained nature of CFG with heap function pointers.
//
// Test 1 (mode 1): Overwrite with malicious_code (valid function entry)
//   -> CFG ALLOWS because malicious_code is in the CFG bitmap
// Test 2 (mode 2): Overwrite with arbitrary address (not a function entry)
//   -> CFG BLOCKS with __fastfail -> exit code 0x80000003
//
// Lesson: CFG prevents shellcode/ROP via indirect calls, but does NOT
// prevent redirecting to valid-but-dangerous functions.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*Callback)(void);

void legitimate_callback() {
    printf("[*] Legitimate callback called\n");
}

void malicious_code() {
    printf("[!] MALICIOUS CODE EXECUTED!\n");
    printf("[!] CFG allowed this — malicious_code is a valid function entry.\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    int mode = 1;  // 1 = valid function, 2 = invalid address
    if (argc > 1) mode = atoi(argv[1]);

    Callback* cb_table = (Callback*)HeapAlloc(GetProcessHeap(), 0, sizeof(Callback) * 4);
    cb_table[0] = legitimate_callback;
    cb_table[1] = legitimate_callback;
    cb_table[2] = legitimate_callback;

    printf("[*] Callback table at: %p\n", cb_table);
    printf("[*] Original cb_table[2]: %p (legitimate_callback)\n",
           (void*)cb_table[2]);
    fflush(stdout);

    if (mode == 1) {
        printf("[*] Mode 1: Overwriting cb_table[2] with malicious_code (valid entry)\n");
        cb_table[2] = malicious_code;
    } else {
        printf("[*] Mode 2: Overwriting cb_table[2] with 0xDEADDEAD (invalid)\n");
        cb_table[2] = (Callback)0xDEADDEAD;
    }

    printf("[*] cb_table[2] now: %p\n", (void*)cb_table[2]);
    printf("[*] Calling through corrupted pointer...\n");
    fflush(stdout);

    cb_table[2]();  // CFG check happens here

    printf("[*] Call returned.\n");
    HeapFree(GetProcessHeap(), 0, cb_table);
    return 0;
}
```

**Compile & Run**:

```bash
# Save to C:\Windows_Mitigations_Lab\src\cfg_heap_test.c
cd C:\Windows_Mitigations_Lab

# Compile WITH CFG
cl /Zi /guard:cf src\cfg_heap_test.c /Fe:bin\cfg_heap_test.exe /link /guard:cf /DEBUG

# Test 1: Redirect to valid function -> CFG ALLOWS
.\bin\cfg_heap_test.exe 1
# [*] Callback table at: 0000017CCDFDE660
# [*] Original cb_table[2]: 00007FF656727AA0 (legitimate_callback)
# [*] Mode 1: Overwriting cb_table[2] with malicious_code (valid entry)
# [*] cb_table[2] now: 00007FF656725140
# [*] Calling through corrupted pointer...
# [!] MALICIOUS CODE EXECUTED!
# [!] CFG allowed this — malicious_code is a valid function entry.
# [*] Call returned.
# Exit code: 0x0

# Test 2: Redirect to invalid address -> CFG BLOCKS
.\bin\cfg_heap_test.exe 2
# [*] Callback table at: 00000290182719C0
# [*] Original cb_table[2]: 00007FF656727AA0 (legitimate_callback)
# [*] Mode 2: Overwriting cb_table[2] with 0xDEADDEAD (invalid)
# [*] cb_table[2] now: 00000000DEADDEAD
# [*] Calling through corrupted pointer...
# (Process terminated by __fastfail - Exit code: 0x80000003)

# Compile WITHOUT CFG for comparison
cl /Zi src\cfg_heap_test.c /Fe:bin\cfg_heap_test_nocfg.exe /link /DEBUG

.\bin\cfg_heap_test_nocfg.exe 1
# [*] Callback table at: 0000022F1BF8E580
# [*] Original cb_table[2]: 00007FF7847B3152 (legitimate_callback)
# [*] Mode 1: Overwriting cb_table[2] with malicious_code (valid entry)
# [*] cb_table[2] now: 00007FF7847B2464
# [*] Calling through corrupted pointer...
# [!] MALICIOUS CODE EXECUTED!
# [!] CFG allowed this — malicious_code is a valid function entry.
# [*] Call returned.

.\bin\cfg_heap_test_nocfg.exe 2
# [*] Callback table at: 000002AFCF2F0D60
# [*] Original cb_table[2]: 00007FF7847B3152 (legitimate_callback)
# [*] Mode 2: Overwriting cb_table[2] with 0xDEADDEAD (invalid)
# [*] cb_table[2] now: 00000000DEADDEAD
# [*] Calling through corrupted pointer...
# (Access violation crash - no CFG protection)
```

**CFG Bitmap**:

- Process Creation:
  - OS creates CFG bitmap for process
  - Each bit represents 16-byte aligned address
  - Bit set = valid indirect call target
  - Bit clear = invalid
- Runtime:
  - Before indirect call, check bitmap
  - If target bit is set -> allow
  - If target bit is clear -> terminate

**Valid CFG Targets**:

- Function entry points (address-taken)
- Exported functions
- Dispatch tables
- **Excluded**: Functions marked with `__declspec(guard(suppress))` are explicitly NOT valid targets.

**CFG Check Assembly** (x64):

```asm
; Before indirect call
mov rax, [function_pointer]
call [__guard_check_icall_fptr]  ; Validation
call rax                          ; Actual call (if valid)

; __guard_check_icall_fptr:
; - Checks if target is in CFG bitmap
; - Returns if valid, terminates if invalid
```

#### Deep Dive: CFG Bitmap Structure and Validation

**CFG Bitmap Architecture**:

```text
CFG Bitmap Memory Layout:
-------------------------

The CFG bitmap is a large array where each BIT represents whether
a 16-byte aligned address is a valid indirect call target.

> Note: With XFG enabled, the bitmap uses 2 bits per entry instead of 1,
> encoding both validity and type-hash metadata.

Address Space (User Mode):     CFG Bitmap:
┌────────────────────────┐    ┌──────────────┐
│ 0x00000000`00000000    │--->│ Bit 0        │
│ 0x00000000`00000010    │--->│ Bit 1        │
│ 0x00000000`00000020    │--->│ Bit 2        │
│ ...                    │    │ ...          │
│ 0x00007FFF`FFFFFFFF    │--->│ Bit N        │
└────────────────────────┘    └──────────────┘

Bitmap Size Calculation (x64 user mode):
- User address space: ~128TB (0x7FFFFFFFFFFF)
- Granularity: 16 bytes per bit
- Bits needed: 128TB / 16 = 8TB bits = 1TB bytes
- Actual: Sparse, on-demand allocation

Bitmap Lookup Algorithm:
bit_index = target_address >> 4  (divide by 16)
byte_index = bit_index >> 3      (divide by 8)
bit_offset = bit_index & 7       (mod 8)
is_valid = (bitmap[byte_index] >> bit_offset) & 1
```

**CFG Dispatch Function Internals**:

```c
// Simplified __guard_check_icall_fptr implementation
// NOTE: This is a conceptual simplification. The actual bitmap pointer
// comes from ntdll internals, not directly from PEB.
void __fastcall __guard_check_icall_fptr(void *target) {
    // Get bitmap base (simplified — actual source is ntdll internal)
    ULONG_PTR bitmap_base = NtCurrentPeb()->CfgBitMap;

    // Calculate bit position
    ULONG_PTR bit_index = (ULONG_PTR)target >> 4;
    ULONG_PTR byte_index = bit_index >> 3;
    ULONG bit_offset = bit_index & 7;

    // Check if valid
    BYTE bitmap_byte = *(BYTE*)(bitmap_base + byte_index);
    if (!((bitmap_byte >> bit_offset) & 1)) {
        // Invalid target - terminate
        __fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE);
        // Process dies immediately, no exception handling
    }
    // Valid - return and allow call
}
```

**CFG Failure Codes**:

```bash
# When CFG blocks a call, it uses __fastfail()
# __fastfail executes: int 0x29 (traps directly to kernel)
# Kernel kills the process immediately — no user-mode handler runs

# Process exit code: 0x80000003 (STATUS_BREAKPOINT)
# This is the ACTUAL exit code you see from GetExitCodeProcess()
# NOTE: NOT 0xC0000409 — that's the old-style /GS cookie failure.
# __fastfail via int 0x29 produces STATUS_BREAKPOINT.

# Fast Fail Codes passed via ECX to int 0x29 (winnt.h):
FAST_FAIL_GUARD_ICALL_CHECK_FAILURE = 10  # CFG indirect call check failed
FAST_FAIL_GUARD_WRITE_CHECK_FAILURE = 11  # CFG write check (rare)
FAST_FAIL_GUARD_JUMP_CHECK_FAILURE  = 12  # CFG jump check
FAST_FAIL_GUARD_SS_FAILURE          = 37  # CET shadow stack mismatch

# In WinDbg after CFG kill:
!analyze -v
# FAILURE_BUCKET_ID: FAIL_FAST_GUARD_ICALL_CHECK_FAILURE
# Look for: SubCode = 10 (0xA) in the exception parameters

# Exception record:
.exr -1
# ExceptionCode: 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN)
# ExceptionInformation[0]: fast fail code (10 = CFG, 37 = CET)
# BUT the PROCESS EXIT CODE is 0x80000003 (STATUS_BREAKPOINT)
# This distinction matters when checking exit codes in exploits!

# Verifying from command line:
echo %errorlevel%
# Or in Python: p.returncode & 0xFFFFFFFF == 0x80000003
```

**Populating the CFG Bitmap**:

```text
When is a bit SET in the CFG bitmap?

At Image Load Time:
1. Loader reads Guard CF Function Table from PE
   - This table is created by the linker.
   - It includes all address-taken functions *except* those marked with `__declspec(guard(suppress))`.
2. For each address in table:
   - Calculate bit position
   - Set bit in bitmap
3. Export table entries also marked valid
4. DLL entry points marked valid

PE Header Fields:
- GuardCFCheckFunctionPointer
- GuardCFDispatchFunctionPointer
- GuardCFFunctionTable (array of valid targets)
- GuardCFFunctionCount
- GuardFlags

Viewing in PE:
dumpbin /loadconfig myapp.exe
# Look for:
# Guard CF address of check-function pointer
# Guard CF function table
# Guard CF function count
```

**Compiler Instrumentation**:

```c
// What the compiler does with /guard:cf

// Original code:
void (*callback)(int);
callback = get_function_pointer();
callback(42);

// Compiled with CFG:
void (*callback)(int);
callback = get_function_pointer();

// Compiler inserts:
__guard_check_icall_fptr(callback);  // <-- Added
callback(42);

// In assembly (x64):
mov     rax, [rbp+callback]
mov     rcx, rax                    ; target in rcx
call    [__guard_check_icall_fptr]  ; validate
call    rax                         ; call if valid
```

**CFG Export Suppression**:

```c
// Some functions should NOT be valid CFG targets
// Use __declspec(guard(suppress))

__declspec(guard(suppress))
void internal_gadget_like_function() {
    // This function won't be in CFG bitmap
    // Attackers can't call it via indirect call
}

// Useful for functions that look like ROP gadgets
// or have dangerous functionality
```

**Testing CFG — Valid vs Invalid Targets**:

```c
// cfg_test.c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Valid CFG Target 1
void legitimate_function() {
    printf("[*] Legitimate function called\n");
    fflush(stdout);
}

// Valid CFG Target 2
void another_function() {
    printf("[*] Another function called\n");
    fflush(stdout);
}

// Invalid CFG Target (Suppressed)
// This function exists and is executable, but we tell the compiler
// NOT to add it to the CFG valid target bitmap.
__declspec(guard(suppress))
void suppressed_function() {
    printf("[!] EXPLOIT SUCCESS: Suppressed function executed!\n");
    printf("[!] This should ONLY happen if CFG is disabled.\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    void (*func_ptr)();

    // Test 1: Call valid function
    printf("[*] Test 1: Calling legitimate_function (valid)\n");
    fflush(stdout);
    func_ptr = legitimate_function;
    func_ptr();

    // Test 2: Redirect to another valid function
    // CFG Limitation: It validates "is this A start of A function",
    // not "is this the INTENDED function".
    printf("[*] Test 2: Redirecting to another_function (valid)\n");
    fflush(stdout);
    func_ptr = another_function;
    func_ptr();

    // Test 3: Call suppressed function
    // - Memory: Valid (it's a real function)
    // - CFG Bitmap: Invalid (suppressed)
    // This distinguishes CFG protection from generic Access Violations.
    printf("[*] Test 3: Calling suppressed_function (invalid CFG target)\n");
    fflush(stdout);

    // Use volatile to prevent the compiler from optimizing away the indirect call
    void (* volatile vfunc_ptr)() = suppressed_function;
    vfunc_ptr();  // With CFG: Terminate (__fastfail). Without CFG: Execute.

    printf("[-] Should not reach here if CFG is working\n");
    return 0;
}
```

**Compile & Run**:

```bash
# With CFG
cl /Zi /guard:cf src\cfg_test.c /Fe:bin\cfg_test.exe /link /guard:cf /DEBUG
.\bin\cfg_test.exe
#[*] Test 1: Calling legitimate_function (valid)
#[*] Legitimate function called
#[*] Test 2: Redirecting to another_function (valid)
#[*] Another function called
#[*] Test 3: Calling suppressed_function (invalid CFG target)

# Without CFG
cl /Zi src\cfg_test.c /Fe:bin\cfg_test_nocfg.exe /link /DEBUG
.\bin\cfg_test_nocfg.exe
#[*] Test 1: Calling legitimate_function (valid)
#[*] Legitimate function called
#[*] Test 2: Redirecting to another_function (valid)
#[*] Another function called
#[*] Test 3: Calling suppressed_function (invalid CFG target)
#[!] EXPLOIT SUCCESS: Suppressed function executed!
#[!] This should ONLY happen if CFG is disabled.
#[-] Should not reach here if CFG is working
```

### Intel Control-Flow Enforcement Technology (CET)

**What is CET?**:

- Hardware-based control-flow integrity
- Two components: Shadow Stack + Indirect Branch Tracking
- Requires CPU support (Intel 11th gen+ / AMD Zen 3+)
- Available on Windows 11, increasingly enabled by default on 24H2+
- **Important**: Full enforcement requires:
  - Supported CPU with CET capability
  - Binary compiled with `/CETCOMPAT` flag (CETCOMPAT bit in PE header)
  - Process mitigation policy enabling UserShadowStack
  - Verify actual status via `Get-ProcessMitigation -Name <process>` (Warning: Shows policy, not hardware enforcement)

**Shadow Stack**:

```text
Regular Stack:        Shadow Stack (Hardware):
┌────────────┐       ┌────────────┐
│ Local vars │       │            │
├────────────┤       ├────────────┤
│ Saved RBP  │       │ Return addr│ <- Copy of return address
├────────────┤       └────────────┘
│ Return addr│ <- User-accessible   Hardware-protected
└────────────┘

On function call:
- Regular return address pushed to stack
- ALSO pushed to shadow stack (by CPU)

On function return:
- Pop return address from regular stack
- Pop from shadow stack
- Compare both
- If mismatch -> terminate
```

**Benefits**:

- Prevents ROP attacks
- Return address cannot be overwritten
- Hardware enforcement (can't bypass)

**Shadow Stack in Action**:

```c
// ROP attempt
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Overflow
}

// Without CET:
// Overflow overwrites return address
// ROP chain executes

// With CET:
// Overflow overwrites stack return address
// But shadow stack still has original
// On return: mismatch detected -> crash
```

**Indirect Branch Tracking (IBT)**:

```asm
; Valid indirect jump target must have ENDBR instruction

; Without IBT:
jmp rax  ; Jumps anywhere

; With IBT:
jmp rax  ; Target MUST start with ENDBR64/ENDBR32

; Valid target:
target_function:
    endbr64     ; Required for indirect jumps
    push rbp
    mov rbp, rsp
    ...

; Invalid target:
bad_gadget:
    pop rdi     ; No ENDBR = crash if targeted
    ret
```

**Testing CET**:

```bash
# Check if CPU supports CET
Get-CimInstance Win32_Processor | Select-Object Name

# Check if process has CET
Get-ProcessMitigation -Name bin\cet_shadow.exe | findstr "UserShadowStack"
```

**Lab: Shadow Stack Protection vs Return Address Overwrite**

This lab demonstrates CET shadow stack protection by compiling a vulnerable program
with and without CET support, then attempting to overwrite the return address.

Create `src\cet_shadow_test.c`:

```c
// cet_shadow_test.c
// Demonstrates CET Shadow Stack protection against return address overwrites.
//
// Without CET: Buffer overflow overwrites return address, executes malicious_function
// With CET: Buffer overflow overwrites stack return, but shadow stack has original
//           -> Mismatch detected on RET -> #CP exception -> process killed
//
// Compile WITHOUT CET: cl /Zi /GS- src\cet_shadow_test.c /Fe:bin\cet_no_shadow.exe /link /DEBUG
// Compile WITH CET:    cl /Zi /GS- /guard:cf /cetcompat src\cet_shadow_test.c /Fe:bin\cet_shadow.exe /link /guard:cf /CETCOMPAT /DEBUG

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Malicious function - target for redirection
void malicious_function() {
    // Use puts() instead of printf() to be safer against stack misalignment
    // printf uses vector instructions (movaps) which crash if RSP isn't 16-byte aligned
    puts("");
    puts("PWNED: malicious_function executed!");
    puts("Return address was successfully overwritten");
    puts("This proves CET shadow stack is NOT enabled");
    puts("");

    // Exit cleanly to avoid crashing on return (since stack is trashed)
    ExitProcess(0);
}

void legitimate_function() {
    printf("[*] This is the legitimate function (should never print in exploit)\n");
}

void vulnerable_function(char *input, size_t input_len) {
    char buffer[64];

    printf("[*] Buffer at: %p\n", buffer);
    printf("[*] Input length: %zu bytes\n", input_len);
    printf("[*] Calling memcpy (vulnerable)...\n");
    fflush(stdout);

    // VULNERABILITY: No bounds checking!
    memcpy(buffer, input, input_len);

    printf("[+] memcpy completed\n");
    printf("[*] Returning from vulnerable_function...\n");
    fflush(stdout);

    // On return:
    // - Without CET: Uses overwritten return address from stack
    // - With CET: Compares stack return vs shadow stack return
    //             If mismatch -> #CP exception -> __fastfail
}

void print_addresses() {
    printf("\n[*] Function Addresses:\n");
    printf("  legitimate_function  = %p\n", (void*)legitimate_function);
    printf("  malicious_function   = %p\n", (void*)malicious_function);
    printf("  vulnerable_function  = %p\n\n", (void*)vulnerable_function);
    fflush(stdout);
}

int main(int argc, char **argv) {
    // Disable buffering to ensure we see output before any crash
    setbuf(stdout, NULL);

    printf("CET Shadow Stack Protection Test\n");
    printf("--------------------------------\n\n");

    print_addresses();

    if (argc < 2) {
        printf("Usage: %s <mode>\n", argv[0]);
        printf("  mode:\n");
        printf("  0     - No overflow (normal execution)\n");
        printf("  1     - Overwrite return address (trigger exploit)\n");
        return 1;
    }

    // Check mode
    int mode = 0;
    if (argc > 1) {
        mode = atoi(argv[1]);
    }

    if (mode == 0) {
        printf("[*] Mode 0: Normal execution (no overflow)\n");
        char safe_input[32] = "Hello, World!";
        vulnerable_function(safe_input, strlen(safe_input));
        printf("[+] Returned safely from vulnerable_function\n");
        legitimate_function();
    }
    else {
        printf("[*] Mode 1: Exploit mode - will attempt return address overwrite\n");
        printf("[!] Expected: WITHOUT CET -> malicious_function executes\n");
        printf("[!] Expected: WITH CET -> process killed by #CP exception\n\n");

        // AGGRESSIVE SPRAY: Fill the entire payload with the target address.
        // x64 stack frames can be large and variable. We'll fill enough to cover
        // any reasonable buffer-to-return-address distance.
        char payload[256];
        ULONG_PTR target = (ULONG_PTR)malicious_function;

        // Fill the WHOLE buffer with the address (repeated)
        // This guarantees we hit the return address wherever it is
        for (size_t i = 0; i < sizeof(payload); i += sizeof(target)) {
            memcpy(&payload[i], &target, sizeof(target));
        }

        printf("[*] Crafted payload:\n");
        printf("  Strategy: FULL SPRAY (offsets 0-256)\n");
        printf("  Target: %p (malicious_function)\n", (void*)target);
        printf("  Total payload: %zu bytes\n\n", sizeof(payload));

        vulnerable_function(payload, sizeof(payload));

        printf("[*] If you see this, CET shadow stack blocked the exploit!\n");
        legitimate_function();
    }

    printf("\n[+] Program completed normally\n");
    return 0;
}
```

**Compile & Run**:

```bash
cl /Zi /GS- src\cet_shadow_test.c /Fe:bin\cet_no_shadow.exe /link /DEBUG
.\bin\cet_no_shadow.exe 0
#[*] Mode 0: Normal execution (no overflow)
#[*] Buffer at: 000000893B77F9F0
#[*] Input length: 13 bytes
#[*] Calling memcpy (vulnerable)...
#[+] memcpy completed
#[*] Returning from vulnerable_function...
#[+] Returned safely from vulnerable_function
#[*] This is the legitimate function (should never print in exploit)

#[+] Program completed normally

.\bin\cet_no_shadow.exe 1
#[PWNED: malicious_function executed!]
#[Return address was successfully overwritten]
#[This proves CET shadow stack is NOT enabled]

cl /Zi /GS- /guard:cf /cetcompat src\cet_shadow_test.c /Fe:bin\cet_shadow.exe /link /guard:cf /CETCOMPAT /DEBUG
.\bin\cet_shadow.exe 1
#[*] Mode 1: Exploit mode - will attempt return address overwrite
#[!] Expected: WITHOUT CET -> malicious_function executes
#[!] Expected: WITH CET -> process killed by #CP exception
```

> [!WARNING]
> **Why did my CET test fail in a VM?**
>
> If you see "UserShadowStack: ON" but the exploit still works, **your VM likely does not emulate the required hardware**.
>
> CET requires Intel 11th Gen+ / AMD Zen 3+ physical CPUs _AND_ hypervisor support.
>
> - **VirtualBox**: Does NOT support CET pass-through (as of v7.0).
> - **VMWare**: Requires "Virtualize Intel VT-x/EPT" and specific config.
> - **Hyper-V**: Requires Nested Virtualization enabled correctly.
>
> Without actual hardware `SHSTK` instructions exposed to the guest OS, Windows silently falls back to software-only mode (which does nothing for ROP/buffer overflows), even if the policy says "ON".

#### Deep Dive: CET Shadow Stack Hardware Implementation

**Shadow Stack CPU Instructions**:

```asm
; New instructions added by CET:

; INCSSP - Increment Shadow Stack Pointer
incssp rax      ; Advance SSP by rax * 8 bytes
                ; Used to skip frames during unwinding

; RDSSP - Read Shadow Stack Pointer
rdssp rax       ; Read current SSP into rax
                ; Allows software to inspect shadow stack

; SAVEPREVSSP - Save previous SSP
saveprevssp     ; Saves SSP on shadow stack
                ; Used for stack switching

; RSTORSSP - Restore SSP
rstorssp [mem]  ; Restore SSP from memory
                ; Used when switching back

; WRSS - Write to Shadow Stack
wrss [rsp], rax ; Write rax to shadow stack at rsp
                ; Requires special privileges

; CLRSSBSY - Clear shadow stack busy flag
clrssbsy [mem]  ; Clear busy bit in shadow stack token
```

**Shadow Stack Memory Region**:

```text
Shadow Stack Layout:
--------------------

Regular Stack:                    Shadow Stack:
High Address                      High Address (SSP starts here)
┌────────────────────┐           ┌────────────────────┐
│ Return addr (main) │           │ Return addr (main) │ ← Token
├────────────────────┤           ├────────────────────┤
│ Saved RBP          │           │ Return addr (func1)│
├────────────────────┤           ├────────────────────┤
│ Local vars         │           │ Return addr (func2)│
├────────────────────┤           ├────────────────────┤
│ Return addr (func1)│           │         ...        │
├────────────────────┤           └────────────────────┘
│ ...                │           ^
└────────────────────┘           SSP (Shadow Stack Pointer)
^
RSP

Key Differences:
- Shadow stack ONLY stores return addresses
- No local variables, no saved registers
- Hardware manages writes (software can only read)
- Separate memory region with special protections
```

**CET Exception Handling**:

```text
When CET Detects Mismatch:
--------------------------

1. CALL instruction:
   - CPU pushes return address to regular stack
   - CPU pushes return address to shadow stack (automatically)

2. RET instruction:
   - CPU pops return address from regular stack
   - CPU pops return address from shadow stack
   - CPU COMPARES both values

3. If mismatch:
   - CPU raises #CP (Control Protection Exception)
   - Exception code: STATUS_CONTROL_STACK_VIOLATION (0xC0000407)
   - OS converts to __fastfail(FAST_FAIL_GUARD_SS_FAILURE = 37)
   - __fastfail executes int 0x29 -> kernel kills process
   - Process exit code: 0x80000003 (STATUS_BREAKPOINT)
   - NOTE: The exception code (0xC0000407) and process exit code
     (0x80000003) are DIFFERENT — same mechanism as CFG failures.

4. In WinDbg:
   !analyze -v
   # Shows CONTROL_PROTECTION_VIOLATION
   # Parameters indicate specific CET violation type
   # SubCode = 37 (0x25) = FAST_FAIL_GUARD_SS_FAILURE
   .exr -1
   # ExceptionCode: 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN)
   # ExceptionInformation[0]: 37 (shadow stack failure)
```

**Indirect Branch Tracking (IBT) Detail**:

```asm
; IBT requires ENDBR at valid branch targets

; Compiler generates:
my_callback:
    endbr64                 ; Must be first instruction!
    push rbp
    mov rbp, rsp
    ; ... function body ...

; On indirect branch:
call rax                    ; CPU sets TRACKER state to WAIT_FOR_ENDBR
; At target:
endbr64                     ; Clears TRACKER state, execution continues

; If target lacks ENDBR:
; CPU raises #CP (Control Protection Exception)

; ENDBR64 encoding: F3 0F 1E FA
; Just a fancy NOP on older CPUs (backward compatible)
```

### Kernel Shadow Stack

**What is Kernel Shadow Stack?**:

- Extends CET shadow stack protection to kernel mode
- Requires VBS (Virtualization-Based Security) enabled
- Hypervisor-enforced integrity - even kernel read/write can't bypass
- Enabled by default on Windows 11 24H2 with supported hardware

**Requirements**:

- Intel 11th gen+ or AMD Zen 3+ CPU with CET support
- VBS/HVCI enabled
- Windows 11 24H2 or later

**Checking Kernel Shadow Stack**:

```bash
# Check if enabled
# Look for value 5 in the output (Kernel-mode Hardware-enforced Stack Protection)
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object -ExpandProperty SecurityServicesRunning
# Output Reference:
# 0 = None (Disabled)
# 1 = Credential Guard
# 2 = Memory Integrity (HVCI)
# 5 = Kernel-mode Hardware-enforced Stack Protection (Shadow Stack)

# Via msinfo32
msinfo32.exe
# Look for: Kernel DMA Protection, Virtualization-based security
```

**Impact on Kernel Exploitation**:

- ROP chains in kernel mode detected and blocked
- Return address tampering causes immediate bugcheck
- Significantly raises bar for kernel exploits

### eXtended Flow Guard (XFG)

**What is XFG?**:

- Enhanced version of CFG
- Validates function pointer types
- Prevents type confusion attacks

**XFG vs CFG Comparison**:

| Feature           | CFG               | XFG                                                                    |
| ----------------- | ----------------- | ---------------------------------------------------------------------- |
| Validation        | Address in bitmap | Address + type signature                                               |
| Granularity       | Function-level    | Call-site specific                                                     |
| Bypass difficulty | Known bypasses    | Significantly harder                                                   |
| Availability      | Windows 8.1+      | Windows 11 (metadata generated; enforcement rolling out incrementally) |

**How XFG Works**:

```c
// CFG check (simplified):
if (bitmap[target >> 4] & (1 << (target & 0xF))) {
    call target;  // Valid function address
}

// XFG check (simplified):
if (target_hash == expected_hash) {
    call target;  // Valid AND correct type signature
}
```

**XFG Type Hashes**:

- Compiler generates hash based on function prototype
- Hash stored at function entry point (before ENDBR)
- Runtime validates hash matches expected call signature

**How XFG Improves CFG**:

```c
// CFG only checks: is target a valid function?
// XFG also checks: does target match expected signature?

typedef void (*HandlerA)(int);
typedef void (*HandlerB)(char*);

void process(HandlerA handler) {
    handler(42);  // Expects (int) parameter
}

// Attack: Pass HandlerB with different signature
HandlerB wrong_handler = get_wrong_handler();

// CFG: Allows (both are valid functions)
// XFG: Blocks (signature mismatch!)
```

**XFG Metadata**:

- Each function pointer has associated metadata:
  - Expected function signature hash
  - Parameter count and types
  - Return type
- Before call:
  - Check CFG bitmap (address valid?)
  - Check XFG metadata (signature matches?)
  - If both pass -> allow call

**Understanding XFG Behavior**:

```c
// xfg_concept.c — Type Confusion Demonstration (CFG vs XFG)
// Demonstrates that CFG allows type-confused calls between valid functions,
// while XFG (when enforced) would block them based on signature mismatch.
//
// Test modes:
//   1: Correct type call (always works)
//   2: Type-confused call (CFG allows, XFG would block)
//   3: Invalid address call (CFG blocks with __fastfail)

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*IntHandler)(int);
typedef void (*StrHandler)(char*);
typedef void (*NoArgHandler)(void);

void int_handler(int x) {
    printf("[*] int_handler called with: %d\n", x);
    fflush(stdout);
}

void str_handler(char *s) {
    // Print pointer value (%p) instead of string (%s) to avoid Access Violation
    // when called with an integer (e.g., 42) during type confusion test.
    printf("[*] str_handler called with: %p\n", (void*)s);
    fflush(stdout);
}

void noarg_handler(void) {
    printf("[*] noarg_handler called (no arguments)\n");
    fflush(stdout);
}

void call_int_handler(IntHandler handler, int value) {
    printf("[*] Calling through IntHandler pointer...\n");
    fflush(stdout);
    handler(value);
}

int main(int argc, char **argv) {
    int test_mode = 1;
    if (argc > 1) test_mode = atoi(argv[1]);

    printf("[*] XFG Type Confusion Test\n");
    printf("[*] int_handler at: %p\n", (void*)int_handler);
    printf("[*] str_handler at: %p\n", (void*)str_handler);
    printf("[*] noarg_handler at: %p\n\n", (void*)noarg_handler);
    fflush(stdout);

    if (test_mode == 1) {
        // TEST 1: Correct type — always works
        printf("[*] TEST 1: Correct type (IntHandler -> int_handler)\n");
        IntHandler correct = int_handler;
        call_int_handler(correct, 42);
        printf("[+] Call succeeded (correct signature)\n");
    }
    else if (test_mode == 2) {
        // TEST 2: Type confusion — CFG allows, XFG would block
        printf("[*] TEST 2: Type confusion (IntHandler -> str_handler)\n");
        printf("[!] Casting StrHandler (char*) to IntHandler (int)\n");
        printf("[!] CFG: Allows (both are valid function entries)\n");
        printf("[!] XFG: Would block (signature mismatch)\n\n");
        fflush(stdout);

        IntHandler confused = (IntHandler)str_handler;
        call_int_handler(confused, 42);
        printf("[+] Call succeeded — CFG is coarse-grained!\n");
        printf("[!] str_handler received garbage (42 instead of char*)\n");
    }
    else if (test_mode == 3) {
        // TEST 3: Invalid address — CFG blocks
        printf("[*] TEST 3: Invalid address (0xDEADBEEF)\n");
        printf("[!] Not a valid function entry — CFG will block\n");
        fflush(stdout);

        IntHandler invalid = (IntHandler)0xDEADBEEF;
        call_int_handler(invalid, 42);
        printf("[-] Should not reach here\n");
    }

    fflush(stdout);
    return 0;
}
```

**Compile & Run**:

```bash
cl /Zi /guard:cf src\xfg_concept.c /Fe:bin\xfg_concept.exe /link /guard:cf /DEBUG
.\bin\xfg_concept.exe 1
#[*] XFG Type Confusion Test
#[*] int_handler at: 00007FF64B8C1C50
#[*] str_handler at: 00007FF64B8C6670
#[*] noarg_handler at: 00007FF64B8C5FE0

#[*] TEST 1: Correct type (IntHandler -> int_handler)
#[*] Calling through IntHandler pointer...
#[*] int_handler called with: 42
#[+] Call succeeded (correct signature)

.\bin\xfg_concept.exe 2
#[*] XFG Type Confusion Test
#[*] int_handler at: 00007FF64B8C1C50
#[*] str_handler at: 00007FF64B8C6670
#[*] noarg_handler at: 00007FF64B8C5FE0

#[*] TEST 2: Type confusion (IntHandler -> str_handler)
#[!] Casting StrHandler (char*) to IntHandler (int)
#[!] CFG: Allows (both are valid function entries)
#[!] XFG: Would block (signature mismatch)

#[*] Calling through IntHandler pointer...
#[*] str_handler called with: 000000000000002A
#[+] Call succeeded — CFG is coarse-grained!
#[!] str_handler received garbage (42 instead of char*)

# =========================================================================
# NOTE: If XFG were strictly ENFORCED, the process would terminate silently
# before printing the "str_handler called with..." line above.
# The fact that it prints means XFG is in audit/permissive mode or unsupported.
# =========================================================================

.\bin\xfg_concept.exe 3
#[*] XFG Type Confusion Test
#[*] int_handler at: 00007FF64B8C1C50
#[*] str_handler at: 00007FF64B8C6670
#[*] noarg_handler at: 00007FF64B8C5FE0

#[*] TEST 3: Invalid address (0xDEADBEEF)
#[!] Not a valid function entry — CFG will block
#[*] Calling through IntHandler pointer...
# NOTE: (Process terminated via __fastfail)

dumpbin /loadconfig bin\xfg_concept.exe | findstr -i "XFG"
#Dump of file bin\xfg_concept.exe
#    00000001400B7010 Guard XFG address of check-function pointer
#    00000001400B7030 Guard XFG address of dispatch-function pointer
#    00000001400B7040 Guard XFG address of dispatch-table-function pointer
```

> [!IMPORTANT]
> **XFG Enforcement is OS-Level, Not Compiler-Level**: The compiler generates XFG metadata
> (type hashes) when `/guard:cf` is used on recent MSVC versions. However, **whether XFG
> type checking is actually enforced** depends on the Windows version and configuration.
> On most current systems, Test 2 will SUCCEED because CFG is enforced (coarse-grained)
> but XFG type validation is not yet widely enforced. XFG represents the **future direction**
> of Windows CFI, where type-confused calls will be blocked.

### Practical Exercise

#### Task 1: CFG Coarse-Grained Analysis

Build a program that demonstrates BOTH what CFG blocks and what it allows:

```c
// cfg_analysis.c — Task 1: Prove CFG's coarse-grained limitation
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*MathOp)(int, int);

int add(int a, int b) { printf("[+] add(%d,%d) = %d\n", a, b, a+b); return a+b; }
int sub(int a, int b) { printf("[+] sub(%d,%d) = %d\n", a, b, a-b); return a-b; }
int pwn(int a, int b) { printf("[!] PWNED via redirect to pwn()!\n"); return 0xDEAD; }

int main(int argc, char **argv) {
    MathOp op = add;
    printf("[*] add at %p, sub at %p, pwn at %p\n",
           (void*)add, (void*)sub, (void*)pwn);
    fflush(stdout);

    if (argc > 1 && argv[1][0] == '1') {
        // Redirect to another valid function — CFG ALLOWS
        printf("[*] Redirecting function pointer to pwn()...\n");
        op = pwn;
    } else if (argc > 1 && argv[1][0] == '2') {
        // Redirect to shellcode address — CFG BLOCKS
        printf("[*] Redirecting function pointer to 0xBAADF00D...\n");
        op = (MathOp)0xBAADF00D;
    }
    fflush(stdout);
    int result = op(10, 5);
    printf("[*] Result: %d\n", result);
    return 0;
}
```

```bash
# Compile with and without CFG
cl /Zi /guard:cf src\cfg_analysis.c /Fe:bin\cfg_analysis.exe /link /guard:cf /DEBUG

# Test 1: valid redirect -> CFG allows
.\bin\cfg_analysis.exe 1
# Expected: [!] PWNED via redirect to pwn()!

# Test 2: invalid redirect -> CFG blocks
.\bin\cfg_analysis.exe 2
# Expected: Process terminates immediately.
# Note: You may see 0xC0000005 (Access Violation) if the CFG bitmap for that address is unmapped.

# Verify in WinDbg:
windbg bin\cfg_analysis.exe 2
# > g
# !analyze -v -> FAIL_FAST_GUARD_ICALL_CHECK_FAILURE or INVALID_POINTER_READ
```

#### Task 2: CET Shadow Stack Verification

Verify that CET is active on your system and understand its impact:

```bash
# 1. Check CPU support for CET
Get-CimInstance -ClassName Win32_Processor | Select-Object Name, Caption
# Intel 12th gen+ or AMD Zen 3+ have CET

# 2. Check if shadow stacks are enforced
Get-ProcessMitigation -System | Select-Object -ExpandProperty UserShadowStack
# Look for: Enable = ON, AuditMode = OFF

# 3. Check per-process CET status
Get-ProcessMitigation -Name notepad.exe | Select-Object -ExpandProperty UserShadowStack

# 4. Verify in WinDbg (needs kernel debugging enabled)
# bcdedit -debug on, and the rest ...
windbg -pn notepad.exe
# In WinDbg:
# !process 0 0
# .process /i <EPROCESS>
# g
# dt nt!_KTHREAD @$thread UserShadowStacksEnabled
```

> [!NOTE]
> You cannot easily test CET bypass because CET **completely blocks** return address
> tampering — there is no "allowed" case. Any ROP chain or return address overwrite
> causes immediate shadow stack mismatch -> `__fastfail(37)` -> exit code `0x80000003`.
> This is fundamentally different from CFG, which has a coarse-grained bypass.

### Comparing CFG, CET, and XFG

| Feature               | CFG                          | CET                          | XFG                       |
| --------------------- | ---------------------------- | ---------------------------- | ------------------------- |
| **Protects**          | Indirect calls/jumps         | Return addresses             | Function type matching    |
| **Mechanism**         | Software bitmap              | Hardware shadow stack        | Enhanced CFG + type hash  |
| **Requires**          | Windows 8.1+                 | Intel 11th+ / Zen 3+ + Win11 | Windows 11 22H2+          |
| **Overhead**          | ~1-5%                        | <1% (hardware)               | ~2-7%                     |
| **Granularity**       | Coarse (any valid function)  | Exact (per-return address)   | Fine (per-call-site type) |
| **Bypass Difficulty** | Medium (valid-func redirect) | Very Hard (hardware)         | Hard                      |
| **Exit code on kill** | 0x80000003 (\_\_fastfail)    | 0x80000003 (\_\_fastfail)    | 0x80000003 (\_\_fastfail) |

### Key Takeaways

1. **CFG is coarse-grained**: It checks "is the target ANY valid function entry?" — not
   "should THIS call site dispatch to THAT function." This means redirecting a function
   pointer to a different-but-valid function **bypasses CFG**. We proved this in Day 2
   Technique 3 and again in the vtable test above.
2. **CET completely blocks ROP**: Shadow stacks are hardware-enforced — any return address
   mismatch causes immediate termination. Unlike CFG, there is no "allowed" bypass case.
   CET eliminates return-oriented programming entirely on supported hardware.
3. **CFG exit code is 0x80000003**: `__fastfail` executes `int 0x29` which traps to the
   kernel. The process exit code is STATUS_BREAKPOINT (0x80000003), NOT 0xC0000409. The
   exception record contains the detailed fast-fail code (10 for CFG, 37 for CET).
4. **XFG improves CFG with type hashes**: XFG validates that the target function's
   signature matches what the call site expects. This closes the coarse-grained gap.
   However, XFG is OS-managed — there is no public `/guard:xfg` compiler flag.
5. **Data-only attacks bypass all CFI**: Since CFG/CET/XFG only protect control flow
   (function pointers and return addresses), attacks that corrupt data without changing
   code flow remain effective. Example: overwriting an `is_admin` flag or authentication
   token without touching any function pointer.
6. **Layered defense is essential**: CFG handles indirect calls, CET handles returns,
   XFG handles type confusion. No single mechanism covers everything.
7. **Win32k filtering removes massive attack surface**: Browser renderers that block
   win32k.sys syscalls eliminate 1200+ kernel attack surface functions.
8. **IBT (Indirect Branch Tracking)** requires `ENDBR64` at branch targets — backward
   compatible (it's a NOP on older CPUs), but provides forward-edge protection on CET
   hardware.
9. **Kernel shadow stacks** extend CET to ring 0 via VBS/HVCI — even kernel ROP chains
   are detected and cause bugcheck.

### Discussion Questions

1. **Why does CFG allow any valid function, not just compatible types?**

   > CFG uses a single bitmap with 1 bit per 16-byte slot. It only records which
   > addresses are valid function entries — not which functions are valid for a
   > particular call site. Per-call-site validation would require much more metadata
   > and runtime overhead. XFG addresses this with type hashes, but it's still not
   > deployed universally.

2. **How does CET shadow stack affect legitimate exception handling?**

   > Exception unwinding must update both the regular and shadow stacks. The OS
   > exception dispatcher uses `INCSSP` / `RSTORSSP` to adjust the shadow stack
   > during unwinding. `setjmp`/`longjmp` also save/restore shadow stack state.
   > This is handled transparently by the CRT — application code doesn't need changes.

3. **What attack surfaces remain even with CFG + CET + XFG?**

   > Data-only attacks: corrupt `is_admin` flags, authentication tokens, file paths,
   > SQL query strings, or configuration data — none of which involve function pointers
   > or return addresses. Also: JIT-compiled code (if ACG is not enabled), DLL injection
   > (if CIG is not enabled), and kernel attacks via drivers not covered by HVCI.

4. **Can CFI be perfect, or will bypasses always exist?**
   > Perfect CFI requires knowing the complete, precise set of valid targets for every
   > indirect call at every point in execution — essentially a complete program analysis.
   > This is undecidable in general (halting problem). In practice, we can get very close
   > with XFG + CET + ACG + CIG, but novel attack classes (data-only, confused deputies,
   > side channels) will always exist outside the CFI protection model.

