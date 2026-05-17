## offensive-windows-mitigations

> Source: `/Users/ryan-osome-infosec/.claude/skills/offensive-windows-mitigations//SKILL.md`

# SKILL: Week 6: Understanding Windows Mitigations

## Metadata
- **Skill Name**: windows-mitigations
- **Folder**: offensive-windows-mitigations

## Description
Deep-dive on Windows exploit mitigations: ASLR, DEP/NX, CFG, CET/Shadow Stack, SEHOP, Heap Guard, ACG, Arbitrary Code Guard. Covers both the protection mechanism and known bypass techniques. Use when researching Windows exploit mitigations, planning bypass strategies, or understanding protection depth.

## Trigger Phrases
Use this skill when the conversation involves any of:
`Windows mitigations, ASLR, DEP, NX, CFG, CET, shadow stack, SEHOP, heap guard, ACG, mitigation bypass, exploit mitigation, Windows hardening`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

## Full Methodology

# Week 6: Understanding Windows Mitigations

## Overview

_created by AnotherOne from @Pwn3rzs Telegram channel_.

Last week you learned basic exploitation in an environment without protections.
This week, you'll learn about the defensive mechanisms that modern Windows systems employ to prevent those attacks.
Understanding these mitigations is essential before learning to bypass them (Week 8). Week 7 continues with enterprise security topics (offensive reconnaissance, Windows 11 24H2/25H2 mitigations, cross-platform defenses).

**This Week's Focus**:

- Understand how each mitigation works
- Learn to detect active mitigations
- Verify mitigation effectiveness
- Test exploits against protected binaries
- Prepare for Week 7's boundaries and Week 8's bypass techniques

### Prerequisites

Before starting this week, ensure you have:

- Completed Week 5: Basic Exploitation (Linux) - you should be able to exploit stack overflows, build ROP chains, and use pwntools
- A Windows 11 VM (isolated, snapshot before each exercise)
- Visual Studio 2022 Build Tools installed
- WinDbg Preview installed
- Basic familiarity with x64 assembly and calling conventions

### Week 6 Deliverables

By the end of this week, you should have completed the following:

- [ ] **Lab Environment**: Windows 11 VM with Visual Studio Build Tools, WinDbg Preview, and Sysinternals installed
- [ ] **Test Binaries**: Compiled `vulnerable_suite_win_mitigated.c` and `vuln_server_win.c` with various mitigation flags
- [ ] **DEP Verified**: Demonstrated DEP blocking shellcode execution with crash analysis (Exception Code 0xC0000005, Param 8)
- [ ] **ASLR Measured**: Recorded addresses of `check_aslr.exe` across 3 reboots and documented randomization behavior
- [ ] **Stack Cookie Tested**: Triggered `/GS` cookie check failure and analyzed in WinDbg
- [ ] **CFG Validated**: Demonstrated CFG blocking indirect call to invalid target
- [ ] **Crash Dumps Analyzed**: Created at least 3 crash dumps and identified which mitigation caused each termination using `!analyze -v`
- [ ] **Week 5 Exploit Retesting**: Re-ran Week 5 exploits against mitigated binaries and documented failures
- [ ] **Mitigation Audit Report**: Generated system-wide and per-binary mitigation audit using PowerShell scripts
- [ ] **Hardening Capstone**: Completed the SecureServer v1.0 hardening exercise (Day 7)

### Context

Why Mitigations Matter: Modern exploits chain multiple vulnerabilities and bypass layers of protection. Understanding mitigations helps you:

- Recognize when an exploit is blocked vs. when it succeeds
- Analyze crash dumps to identify exploitation attempts
- Design defense-in-depth strategies
- Prepare for Weeks 7-8 (advanced mitigations and bypass techniques)

**Recent CVEs Demonstrating Mitigation Importance**:

| CVE            | Vulnerability                   | Mitigations Involved | Outcome                               |
| -------------- | ------------------------------- | -------------------- | ------------------------------------- |
| CVE-2024-21338 | AppLocker (appid.sys) EoP       | KASLR, SMEP, kCFG    | Admin-to-Kernel bypass of kCFG        |
| CVE-2024-30088 | Authz Kernel TOCTOU             | KASLR, SMEP, CFG     | Exploited via race condition          |
| CVE-2023-36802 | MSKSSRV Object Type Confusion   | KASLR, SMEP, CFG     | Pool spray + type confusion to EoP    |
| CVE-2025-29824 | CLFS Driver Use-After-Free      | KASLR, SMEP          | Zero-day exploited in wild (Apr 2025) |
| CVE-2024-49138 | CLFS Heap-Based Buffer Overflow | DEP, ASLR, KASLR     | EoP exploited in wild (Dec 2024)      |
| CVE-2023-32019 | Windows Kernel Info Disclosure  | KASLR                | Leaked kernel memory bypassing KASLR  |
| CVE-2023-28252 | CLFS Driver EoP                 | KASLR, SMEP          | Abused CLFS log file parsing          |
| CVE-2022-34718 | Windows TCP/IP RCE (EvilESP)    | DEP, ASLR, CFG       | Required sophisticated heap grooming  |

**Connection to Week 4 (Crash Analysis)**:

When you receive a crash dump, the exception codes reveal which mitigation stopped the exploit:

```text
Week 4 Crash Analysis -> Week 6 Mitigation Identification
─────────────────────────────────────────────────────────
Process Exit Code         WinDbg Exception Code        Mitigation
──────────────────────    ─────────────────────        ──────────
0xC0000005 (Param[0]=8)   0xC0000005                   DEP violation (execute on NX page)
0xC0000409                0xC0000409 (subcode 2)        /GS stack cookie corruption
0x80000003                0xC0000409 (subcode 10)       CFG indirect call validation failed
0x80000003                0xC0000407                    CET shadow stack mismatch
0xC0000374                0xC0000374                    Heap integrity check failed

IMPORTANT: Python/cmd see the PROCESS EXIT CODE. WinDbg sees the EXCEPTION CODE.
CFG and CET both use __fastfail() which raises int 0x29 -> exit code 0x80000003,
but the EXCEPTION RECORD inside WinDbg shows the original status code.
```

### Windows Mitigations Relevance

Understanding these bug classes prepares you for real-world vulnerability research:

| Bug Class        | Example CVE                | Mitigation Interaction                            | Week 8 Bypass        |
| ---------------- | -------------------------- | ------------------------------------------------- | -------------------- |
| Race Condition   | CVE-2024-30088 (Authz)     | TOCTOU bypasses simple checks                     | Timing manipulation  |
| Type Confusion   | CVE-2023-36802 (MSKSSRV)   | CFG validates calls, but confused object bypasses | Object spray         |
| Pointer Deref    | CVE-2024-21338 (appid.sys) | kCFG bypass via direct manipulation               | Arbitrary read/write |
| Integer Overflow | CVE-2021-34535 (RDP)       | Safe integer functions                            | Find unchecked paths |
| Arbitrary Write  | CVE-2023-28252 (CLFS)      | KASLR, SMEP                                       | Info leak chain      |

