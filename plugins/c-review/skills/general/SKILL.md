---
name: c-review-general
version: 2.0.0
description: >
  This skill should be used when the user asks to "review C code for security issues",
  "audit C/C++ codebase", "find vulnerabilities in C code", "security review C program",
  "check C code for bugs", "find memory corruption bugs", "audit native code security",
  "find buffer overflows", "check for use-after-free", "review parser code",
  or needs comprehensive C/C++ security analysis covering memory corruption,
  integer overflows, type confusion, format strings, and race conditions.
---

# C/C++ General Security Review

Comprehensive security review of C/C++ codebases using the coordinator pattern.
The coordinator spawns parallel bug-finding tasks from prompt templates.

## When to Use

- Auditing C/C++ applications for security vulnerabilities
- Pre-release security review of native code
- Finding memory safety issues (buffer overflows, use-after-free)
- Identifying integer overflow and type confusion bugs
- Detecting race conditions and concurrency issues

## When NOT to Use

- For Linux userspace-specific issues (use `c-review:linux-userspace` instead)
- For Windows kernel driver review (different checklist needed)
- For managed languages (Java, C#, Python)

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

### Round 2: Context Building

Use the `audit-context-building` skill to build codebase context:
- Entry points and trust boundaries
- Data flows and control flows
- Memory allocation patterns

### Round 3: Spawn Coordinator

**Invoke the general-coordinator agent** with the collected context:

```
Task(
  subagent_type="c-review:general-coordinator",
  prompt="""
  ## Codebase Context
  [context from Round 2]

  ## Threat Model: [REMOTE | LOCAL_UNPRIVILEGED | BOTH]
  [threat model description from Round 1]

  ## Instructions
  1. Read all prompt templates from prompts/general/
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

The coordinator spawns tasks for these bug classes:

**Core C (always):**
buffer-overflow, use-after-free, integer-overflow, type-confusion, format-string,
string-issues, uninitialized-data, null-deref, error-handling, memory-leak,
race-condition, filesystem-issues, banned-functions, dos, undefined-behavior,
compiler-bugs, operator-precedence, time-issues, access-control, regex-issues

**C++ (if detected):**
init-order, iterator-invalidation, exception-safety, move-semantics,
smart-pointer, virtual-function, lambda-capture

## Rationalizations to Reject

Reject these excuses—they lead to missed findings:

- "Code path is unreachable" → Prove it with caller trace
- "ASLR/DEP prevents exploitation" → Mitigations are bypass targets
- "Too complex to exploit" → Report it anyway
- "Input validated elsewhere" → Verify the validation exists
- "Only crashes, not exploitable" → Memory corruption may be controllable
- "Static analyzer found nothing" → Analyzers have blind spots
- "Test/debug code" → Debug code ships to production

## Resources

- **`workflows/review-workflow.md`** - Full workflow details, threat model templates, finding formats
