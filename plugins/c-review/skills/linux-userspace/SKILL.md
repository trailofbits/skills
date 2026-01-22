---
name: c-review-linux-userspace
description: >
  This skill should be used when the user asks to "review Linux C code",
  "audit Linux userspace application", "check glibc usage", "find Linux-specific bugs",
  "review signal handlers", "check privilege dropping", "audit setuid program",
  "find thread safety issues", "check errno handling", "review Linux daemon",
  or needs security review of C/C++ code targeting Linux userspace, covering
  thread safety, signal handling, privilege management, and glibc-specific pitfalls.
---

# C/C++ Linux Userspace Security Review

Performs comprehensive security review of C/C++ Linux userspace applications using
specialized parallel agents, each focused on a specific Linux/glibc pitfall.
Uses iterative refinement with false positive judging to maximize finding quality.

## When to Use

- Auditing Linux daemons and services
- Reviewing setuid/setgid programs
- Checking multi-threaded Linux applications
- Auditing signal handler implementations
- Reviewing privilege dropping code
- Finding glibc-specific vulnerabilities
- Auditing POSIX API usage

## When NOT to Use

- For general C/C++ bugs (use `c-review:general` instead, or combine both)
- For Windows applications
- For Linux kernel modules (different checklist)
- For embedded/bare-metal code

## Rationalizations to Reject

Common excuses specific to Linux userspace that lead to missed findings:

- **"The signal handler is simple enough"** - Even simple handlers can call non-async-signal-safe functions.
- **"This function is only called from one thread"** - Thread usage patterns change. Make it safe now.
- **"The program drops privileges correctly"** - Verify the exact sequence. Check saved-set-user-ID.
- **"That function is standard, it must be safe"** - `system()`, `popen()`, `wordexp()` use shell.
- **"Nobody would create a symlink there"** - Attackers create symlinks in any writable directory.
- **"The race window is too small"** - Race conditions can be widened via resource exhaustion.
- **"The environment is trusted"** - Environment variables come from many sources. Treat as attacker-controlled.

## Workflow Overview

### Step 1: Threat Model Selection

Before starting, determine the threat model using AskUserQuestion:

- **Remote** - Attacker can only send data over the network
- **Local Unprivileged** - Attacker has shell access as unprivileged user (most common for setuid)
- **Both** - Consider both threat models

For setuid/setgid binaries, the Local Unprivileged threat model is typically most relevant.

### Step 2: Context Building

Build codebase context with Linux-specific focus:

1. Use the `audit-context-building` skill for architectural understanding
2. Run `checksec` on binaries to assess exploit mitigations
3. Map signal handlers and multi-threaded sections
4. Document environment variable usage and privilege transitions

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
| `thread-safety-finder` | Non-thread-safe function usage |
| `signal-handler-finder` | Non-reentrant functions in signal handlers |
| `oob-comparison-finder` | Out-of-bounds comparisons (std::equal, memcmp) |
| `envvar-finder` | Environment variable security issues |
| `open-issues-finder` | open/access/rename race conditions |
| `privilege-drop-finder` | Privilege dropping mistakes |
| `unsafe-stdlib-finder` | Banned stdlib functions (sprintf, strcpy, gets) |
| `errno-handling-finder` | Return value and errno handling |
| `eintr-handling-finder` | EINTR error handling |
| `overlapping-buffers-finder` | Overlapping buffer undefined behavior |
| `strlen-strcpy-finder` | strlen/strcpy null byte miscounting |
| `scanf-uninit-finder` | scanf uninitialized data leaks |
| `snprintf-retval-finder` | snprintf return value misuse |
| `negative-retval-finder` | Negative return value handling |
| `strncat-misuse-finder` | strncat size argument confusion |
| `strncpy-termination-finder` | strncpy null termination |
| `qsort-finder` | Non-transitive qsort comparator |
| `memcpy-size-finder` | memcpy/memmove negative size |
| `spinlock-init-finder` | Uninitialized spinlock usage |
| `inet-aton-finder` | inet_aton validation issues |
| `socket-disconnect-finder` | connect(AF_UNSPEC) issues |
| `half-closed-socket-finder` | Half-closed socket handling |
| `flexible-array-finder` | Zero-length/one-element array issues |
| `printf-attr-finder` | Missing format attribute on printf-like functions |
| `va-start-end-finder` | va_start without va_end |
| `null-zero-finder` | Zero used instead of NULL |

## Related Skills

For general C/C++ bugs not specific to Linux, see the `c-review:general` skill.
For comprehensive coverage, run both skills on Linux codebases.
