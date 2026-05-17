## offensive-crash-analysis

> Source: `/Users/ryan-osome-infosec/.claude/skills/offensive-crash-analysis//SKILL.md`

# SKILL: Week 4: Crash Analysis and Exploitability Assessment

## Metadata
- **Skill Name**: crash-analysis
- **Folder**: offensive-crash-analysis

## Description
Week 4 exploit development curriculum. Crash triage and analysis methodology: WinDbg/GDB analysis, ASAN/MSAN output interpretation, exploitability assessment, register/stack trace reading, root cause identification. Use when analyzing crash dumps, assessing exploitability, or understanding fuzzer-generated crashes.

## Trigger Phrases
Use this skill when the conversation involves any of:
`crash analysis, crash triage, WinDbg, GDB, ASAN, MSAN, exploitability, stack trace, register dump, segfault, null deref, access violation, week 4`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

## Full Methodology

# Week 4: Crash Analysis and Exploitability Assessment

## Overview

_created by AnotherOne from @Pwn3rzs Telegram channel_.

After finding potential vulnerabilities through fuzzing (Week 2) or patch diffing (Week 3), the next critical step is analyzing crashes to determine if they're exploitable. This week focuses on crash triage, debugger mastery, and techniques for identifying how to reach vulnerable code paths from attacker-controlled input.

Once you've confirmed a crash is exploitable and built a PoC, you'll be ready for Basic Exploitation in Week 5.

### Prerequisites

Before starting this week, ensure you have:

- A Windows VM (for WinDbg labs) and a Linux VM (for GDB/ASAN/CASR labs).
- Completed Week 2 fuzzing labs, including running AFL++ or libFuzzer against at least one C/C++ target
- Completed (or skimmed) Week 3 patch diffing labs:
  - Familiar with Ghidriff/Diaphora diff reports and how to interpret changed functions
  - Understand how to extract Windows updates and Linux kernel patches
  - Reviewed at least one case study (CVE-2022-34718 EvilESP, CVE-2024-1086 nf_tables, or 7-Zip symlink bugs)
- Comfortable understanding from Week 1 of basic vulnerability classes (buffer overflow, UAF, integer bugs, info leaks) and their exploit primitives

### Crash Analysis Decision Tree

Use this decision tree to select the appropriate tools and workflow for any crash you encounter:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CRASH RECEIVED                               │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Source code available?│
                    └───────────────────────┘
                      │                    │
                     Yes                   No
                      │                    │
                      ▼                    ▼
        ┌─────────────────────┐   ┌──────────────────────────┐
        │ Recompile with      │   │ What platform?           │
        │ ASAN + UBSAN        │   └──────────────────────────┘
        │ (Day 2)             │     │         │         │
        └─────────────────────┘     │         │         │
                      │          Windows   Linux    Mobile
                      │             │         │         │
                      ▼             ▼         ▼         ▼
        ┌─────────────────────┐ ┌───────┐ ┌───────┐ ┌───────────┐
        │ Run crash input     │ │WinDbg │ │Pwndbg │ │ Tombstone │
        │ Get detailed report │ │+ TTD  │ │+ rr   │ │ + Frida   │
        └─────────────────────┘ │(Day 1)│ │(Day 1)│ │ (Future)  │
                      │         └───────┘ └───────┘ └───────────┘
                      │             │         │         │
                      └─────────────┴────┬────┴─────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────┐
                    │ Crash requires special environment? │
                    └─────────────────────────────────────┘
                       │                              │
                      Yes                             No
                       │                              │
                       ▼                              │
        ┌─────────────────────────────┐               │
        │ Setup reproduction env:     │               │
        │ - Network (tcpdump, proxy)  │               │
        │ - Files (strace, procmon)   │               │
        │ - Services (docker, VM)     │               │
        └─────────────────────────────┘               │
                       │                              │
                       └──────────────┬───────────────┘
                                      │
                                      ▼
                            ┌─────────────────────┐
                            │ Crash type known?   │
                            └─────────────────────┘
                              │                 │
                             Yes                No
                              │                 │
                              ▼                 ▼
                ┌─────────────────────┐  ┌─────────────────────┐
                │ Run CASR for        │  │ Manual analysis:    │
                │ classification      │  │ - Examine registers │
                │ (Day 3)             │  │ - Check memory      │
                └─────────────────────┘  │ - Disassemble       │
                              │          │ (Day 3)             │
                              │          └─────────────────────┘
                              │                 │
                              └────────┬────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ EXPLOITABILITY ASSESS   │
                          │ - Check mitigations     │
                          │ - Control analysis      │
                          │ - Reachability (Day 4)  │
                          └─────────────────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ Multiple crashes?       │
                          └─────────────────────────┘
                            │                    │
                           Yes                   No
                            │                    │
                            ▼                    ▼
              ┌─────────────────────┐   ┌─────────────────────┐
              │ Deduplicate (Day 5) │   │ Minimize (Day 5)    │
              │ - CASR cluster      │   │ - afl-tmin          │
              │ - Stack hash        │   │ - Manual reduction  │
              └─────────────────────┘   └─────────────────────┘
                            │                    │
                            └────────┬───────────┘
                                     │
                                     ▼
                        ┌─────────────────────────┐
                        │ Create PoC (Day 6)      │
                        │ - Python + pwntools     │
                        │ - Verify reliability    │
                        │ - Document findings     │
                        └─────────────────────────┘
```

**Quick Reference - Tool Selection by Scenario**:

| Scenario                    | Primary Tool               | Secondary Tool   | Sanitizer    |
| --------------------------- | -------------------------- | ---------------- | ------------ |
| Linux binary, have source   | GDB + Pwndbg               | rr               | ASAN + UBSAN |
| Linux binary, no source     | GDB + Pwndbg               | Ghidra           | N/A          |
| Windows binary, have source | WinDbg + TTD               | Visual Studio    | ASAN         |
| Windows binary, no source   | WinDbg + TTD               | IDA/Ghidra       | N/A          |
| Fuzzer crash corpus         | CASR                       | afl-tmin         | ASAN         |
| Non-deterministic crash     | rr (Linux) / TTD (Windows) | Chaos mode       | TSAN         |
| Kernel crash (Linux)        | crash utility              | GDB + KASAN      | KASAN        |
| Kernel crash (Windows)      | WinDbg kernel              | Driver Verifier  | N/A          |
| Android app crash           | Tombstone + ndk-stack      | Frida            | HWASan       |
| Rust/Go crash               | Native debugger            | Sanitizer output | Built-in     |

