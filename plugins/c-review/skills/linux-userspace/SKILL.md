---
name: c-review-linux-userspace
version: 2.0.0
description: >
  This skill should be used when the user asks to "review Linux C code",
  "audit Linux userspace application", "check glibc usage", "find Linux-specific bugs",
  "review signal handlers", "check privilege dropping", "audit setuid program",
  "find thread safety issues", "check errno handling", "review Linux daemon",
  "audit POSIX API usage", "check for race conditions in Linux code",
  or needs security review of C/C++ code targeting Linux userspace.
---

# C/C++ Linux Userspace Security Review

Comprehensive security review of Linux userspace C/C++ code using the coordinator pattern.
The coordinator spawns parallel bug-finding tasks for glibc pitfalls, signal handling, and privilege management.

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

## Workflow

**Execute rounds sequentially. Do not skip.**

### Round 0: Prerequisites

Check clangd is available:
```bash
which clangd
```

If not found, provide platform-specific installation instructions.

Check for compile_commands.json:
```bash
find . -name compile_commands.json -type f
```

### Round 1: Threat Model

**CRITICAL: Ask the user before proceeding.**

Use AskUserQuestion:
- **Question:** "What is the threat model for this review?"
- **Options:**
  - Remote - Attacker can only send data over the network
  - Local Unprivileged - Attacker has shell access as unprivileged user
  - Both - Consider both threat models

**Note:** For setuid/setgid binaries, Local Unprivileged is typically most relevant.

### Round 2: Context Building

Use the `audit-context-building` skill to build codebase context:
- Entry points and trust boundaries
- Signal handlers and multi-threaded sections
- Environment variable usage
- Privilege transitions

### Round 3: Spawn Coordinator

**Invoke the linux-userspace-coordinator agent** with the collected context:

```
Task(
  subagent_type="c-review:linux-userspace-coordinator",
  prompt="""
  ## Codebase Context
  [context from Round 2]

  ## Threat Model: [REMOTE | LOCAL_UNPRIVILEGED | BOTH]
  [threat model description from Round 1]

  ## Instructions
  1. Read all prompt templates from prompts/linux-userspace/
  2. Spawn bug-finding tasks in parallel using general-purpose subagent
  3. Collect findings from all tasks
  4. Pass findings to fp-judge for false positive filtering
  5. Pass valid findings to dedup-judge for consolidation
  6. Pass deduplicated findings to severity-agent for ranking
  7. Generate final report
  """
)
```

The coordinator handles all bug-finding orchestration internally.

### Round 4: Review Output

After coordinator completes:
1. Review the generated report
2. Present findings to user organized by severity
3. Offer SARIF output if requested

## Bug Classes Covered

The coordinator spawns tasks for these Linux userspace-specific bug classes:

thread-safety, signal-handler, oob-comparison, envvar, open-issues, privilege-drop,
unsafe-stdlib, errno-handling, eintr-handling, overlapping-buffers, strlen-strcpy,
scanf-uninit, snprintf-retval, negative-retval, strncat-misuse, strncpy-termination,
qsort, memcpy-size, spinlock-init, inet-aton, socket-disconnect, half-closed-socket,
flexible-array, printf-attr, va-start-end, null-zero

## Rationalizations to Reject

Reject these excuses—they lead to missed findings:

- "Signal handler is simple enough" → Even simple handlers can call non-async-signal-safe functions
- "Only called from one thread" → Thread usage patterns change
- "Drops privileges correctly" → Verify exact sequence, check saved-set-user-ID
- "Standard function, must be safe" → system(), popen(), wordexp() use shell
- "Nobody would create a symlink there" → Attackers create symlinks in any writable directory
- "Race window is too small" → Race conditions can be widened via resource exhaustion
- "Environment is trusted" → Environment variables are attacker-controlled

## Resources

- **`workflows/review-workflow.md`** - Full workflow details, threat model templates, finding formats

## Related Skills

For general C/C++ bugs, use `c-review:general`. For comprehensive coverage, run both.
