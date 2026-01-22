---
name: c-review-general
description: >
  This skill should be used when the user asks to "review C code for security issues",
  "audit C/C++ codebase", "find vulnerabilities in C code", "security review C program",
  "check C code for bugs", "find memory corruption bugs", "audit native code security",
  or needs comprehensive C/C++ security analysis covering general bug classes like
  buffer overflows, use-after-free, integer overflows, type confusion, format strings,
  race conditions, and other common vulnerability patterns.
---

# C/C++ General Security Review

Performs comprehensive security review of C/C++ codebases using specialized parallel
agents, each focused on a specific bug class. Uses iterative refinement with false
positive judging to maximize finding quality.

## When to Use

- Auditing C/C++ applications for security vulnerabilities
- Pre-release security review of native code
- Finding memory safety issues (buffer overflows, use-after-free)
- Identifying integer overflow and type confusion bugs
- Detecting race conditions and concurrency issues
- Comprehensive review before deployment or open-source release

## When NOT to Use

- For Linux userspace-specific issues (use `c-review:linux-userspace` instead)
- For Windows kernel driver review (different checklist needed)
- For managed languages (Java, C#, Python)
- For quick single-file reviews (overkill for small scope)

## Rationalizations to Reject

Common excuses that lead to missed findings:

- **"This code path is unreachable"** - Prove it. Trace all callers including indirect calls.
- **"ASLR/DEP will prevent exploitation"** - Mitigations are bypass targets, not security boundaries.
- **"This is too complex to exploit"** - Exploit developers are creative. Report it.
- **"The input is validated elsewhere"** - Verify the validation exists and is correct.
- **"This only crashes, not exploitable"** - Memory corruption that crashes may be controllable.
- **"The static analyzer didn't find anything"** - Analyzers have blind spots. Manual review required.
- **"This is just test/debug code"** - Debug code ships to production. Report it.

## Workflow Overview

### Step 1: Threat Model Selection

Before starting, determine the threat model using AskUserQuestion:

- **Remote** - Attacker can only send data over the network
- **Local Unprivileged** - Attacker has shell access as unprivileged user
- **Both** - Consider both threat models

### Step 2: Context Building

Build comprehensive codebase context before spawning analysis agents:

1. Use the `audit-context-building` skill to create architectural understanding
2. Identify entry points, trust boundaries, and attack surface
3. Map data flows from untrusted input sources
4. Document memory allocation patterns and ownership

### Step 3: Parallel Bug Analysis

Spawn all bug-finding agents in parallel, providing each with:
- Codebase context from Step 2
- Threat model context from Step 1
- Specific bug class focus

### Step 4: False Positive Judging

Invoke `fp-judge` agent with all findings to evaluate validity and generate
feedback for refined analysis.

### Step 5: Refined Analysis

Re-run bug-finding agents with FP feedback, avoiding identified false positive
patterns and focusing on uncovered areas.

### Step 6: Deduplication and Reporting

Invoke `dedup-judge` to merge duplicates, then generate Markdown and SARIF reports.

For complete workflow details, see [{baseDir}/../../workflows/review-workflow.md](../../workflows/review-workflow.md).

## Bug-Finding Agents

Spawn all in parallel during analysis rounds:

| Agent | Focus Area |
|-------|------------|
| `buffer-overflow-finder` | Spatial safety (bounds checking, off-by-one) |
| `use-after-free-finder` | Temporal safety (UAF, double-free, dangling pointers) |
| `integer-overflow-finder` | Numeric errors (arithmetic, widthness, signedness) |
| `type-confusion-finder` | Type safety (casts, deserialize, unions) |
| `format-string-finder` | Variadic misuse (printf, scanf format bugs) |
| `string-issues-finder` | String handling (null termination, encoding) |
| `uninitialized-data-finder` | Uninitialized memory usage |
| `null-deref-finder` | Null pointer dereferences |
| `error-handling-finder` | Unhandled errors and exceptions |
| `memory-leak-finder` | Memory and resource leaks |
| `init-order-finder` | Initialization order bugs (static init fiasco) |
| `race-condition-finder` | TOCTOU, double fetch, locking issues |
| `filesystem-issues-finder` | Symlinks, paths, temp files |
| `iterator-invalidation-finder` | Iterator/container invalidation |
| `banned-functions-finder` | Error-prone function usage |
| `dos-finder` | Denial of service vectors |
| `undefined-behavior-finder` | UB patterns |
| `compiler-bugs-finder` | Compiler-introduced issues |
| `operator-precedence-finder` | Precedence mistakes |
| `time-issues-finder` | Clock/time problems |
| `access-control-finder` | Privilege and access issues |
| `regex-issues-finder` | ReDoS and regex bypasses |

## Related Skills

For Linux userspace-specific issues, see the `c-review:linux-userspace` skill.
