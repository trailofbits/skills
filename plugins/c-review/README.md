# c-review

Comprehensive C/C++ security code review plugin with task-based orchestration and automatic prompt selection.

## Overview

This plugin provides thorough security review of C/C++ codebases using parallel specialized agents, each focused on a specific vulnerability class. The unified coordinator automatically selects which prompts to use based on code analysis and threat model.

## Features

- **53 specialized bug-finders** covering all major C/C++ bug classes
- **Automatic prompt selection** based on code characteristics (C++, POSIX/Linux/macOS)
- **Threat model filtering** to disable irrelevant prompts
- **Task-based progress tracking** with TaskCreate/TaskUpdate
- **Judge pipeline** for FP filtering, deduplication, and severity assignment
- **Dual output formats**: Markdown (human-readable) and SARIF (tooling)

## Usage

```
/c-review
```

The unified command automatically:
1. Detects C++ code and enables C++ prompts
2. Detects POSIX code (Linux, macOS, BSD) and enables userspace prompts
3. Asks for threat model and filters prompts accordingly
4. Tracks progress via task management

### Threat Models

| Model | Description | Auto-Disabled Prompts |
|-------|-------------|----------------------|
| Remote | Attacker sends network data only | privilege-drop, envvar |
| Local Unprivileged | Attacker has shell access | (none) |
| Both | Consider all scenarios | (none) |

## Prompt Selection

```
                    Code Analysis
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   Always: 20      If C++: +7      If POSIX: +26
   C prompts     C++ prompts    userspace prompts
        │                │         (Linux/macOS/BSD)
        └────────────────┼────────────────┘
                         │
                         ▼
              Filter by threat model
                         │
                         ▼
              Final prompt set (20-53)
```

## Workflow

The review uses task management to track progress:

| Phase | Tasks | Description |
|-------|-------|-------------|
| 0 | 1 | Initialize master tracking task |
| 1 | 1 | Check prerequisites (clangd, compile_commands.json) |
| 2 | 1 | Analyze code (detect C++, POSIX) |
| 3 | 1 | Select threat model, configure filtering |
| 4 | 1 | Build codebase context |
| 5 | N+1 | Coordinator spawns N bug-finders (20-53) |
| 6 | 3 | Judge pipeline (FP, dedup, severity) |
| 7 | 1 | Present findings, optional SARIF |

**Total:** 30-63 tasks depending on code type

## Bug Classes

### General C (20 prompts - always enabled)

| Bug Class | Description |
|-----------|-------------|
| buffer-overflow | Spatial safety, bounds checking |
| use-after-free | Temporal safety, UAF, double-free |
| integer-overflow | Numeric errors, signedness |
| type-confusion | Type safety, casts, unions |
| format-string | Printf/scanf format bugs |
| string-issues | Null termination, encoding |
| uninitialized-data | Uninitialized memory |
| null-deref | Null pointer dereferences |
| error-handling | Unchecked errors |
| memory-leak | Resource leaks |
| race-condition | TOCTOU, double fetch |
| filesystem-issues | Symlinks, temp files |
| banned-functions | Dangerous functions |
| dos | Denial of service |
| undefined-behavior | UB patterns |
| compiler-bugs | Compiler optimizations |
| operator-precedence | Precedence mistakes |
| time-issues | Clock/time bugs |
| access-control | Privilege issues |
| regex-issues | ReDoS, bypasses |

### C++ (7 prompts - if C++ detected)

| Bug Class | Description |
|-----------|-------------|
| init-order | Static initialization order |
| iterator-invalidation | Container modification |
| exception-safety | RAII, exception handling |
| move-semantics | Move-after-use bugs |
| smart-pointer | unique_ptr, shared_ptr misuse |
| virtual-function | VTable, vtable hijacking |
| lambda-capture | Capture lifetime issues |

### POSIX Userspace (26 prompts - if Linux/macOS/BSD detected)

These prompts apply to all POSIX-compliant systems including Linux, macOS, and BSD.
The directory is named `linux-userspace` for historical reasons but covers standard
libc/POSIX patterns common to all Unix-like systems.

| Bug Class | Description |
|-----------|-------------|
| thread-safety | Non-thread-safe functions |
| signal-handler | Async-signal safety |
| privilege-drop | setuid/setgid bugs |
| errno-handling | Return value/errno |
| eintr-handling | EINTR retry logic |
| envvar | Environment variable security |
| open-issues | File operation races |
| unsafe-stdlib | sprintf, strcpy, gets |
| oob-comparison | memcmp/strncmp bounds |
| overlapping-buffers | memcpy overlap UB |
| strlen-strcpy | Null byte miscounting |
| scanf-uninit | Uninitialized leaks |
| snprintf-retval | Return value misuse |
| negative-retval | Negative as size |
| strncat-misuse | Size argument confusion |
| strncpy-termination | Null termination |
| qsort | Non-transitive comparator |
| memcpy-size | Negative size |
| spinlock-init | Uninitialized locks |
| inet-aton | IP validation bypass |
| socket-disconnect | AF_UNSPEC disconnect |
| half-closed-socket | Partial shutdown |
| flexible-array | Zero-length arrays |
| printf-attr | Missing format attr |
| va-start-end | Variadic pairing |
| null-zero | 0 vs NULL |

## Judge Agents

| Agent | Purpose |
|-------|---------|
| `fp-judge` | Evaluates findings for false positives |
| `dedup-judge` | Merges duplicate and related findings |
| `severity-agent` | Assigns severity based on threat model |

## Output Formats

### Markdown Report

Human-readable report with:
- Findings grouped by severity (CRITICAL → HIGH → MEDIUM → LOW)
- Code snippets and locations
- Impact and recommendations
- Severity rationale based on threat model

### SARIF Report

Machine-readable SARIF 2.1.0 format for:
- IDE integration (VS Code, etc.)
- CI/CD pipelines
- GitHub Security tab

## Requirements

- Claude Code with plugin support
- `clangd` for accurate LSP analysis (recommended)
- `compile_commands.json` for symbol resolution (recommended)
- `audit-context-building` skill for codebase context

## Reference

Based on [Trail of Bits C/C++ Security Checklist](https://github.com/trailofbits/publications).
