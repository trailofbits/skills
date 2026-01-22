# c-review

Comprehensive C/C++ security code review plugin with specialized bug-finding agents.

## Overview

This plugin provides thorough security review of C/C++ codebases using parallel specialized agents, each focused on a specific vulnerability class. It uses iterative refinement with false positive judging and deduplication to maximize finding quality.

## Features

- **52 specialized agents** covering all major C/C++ bug classes
- **Iterative review workflow** with FP judging and refinement
- **Two review modes**: general C/C++ bugs and Linux userspace-specific issues
- **Dual output formats**: Markdown (human-readable) and SARIF (tooling)

## Usage

### General C/C++ Review

```
/c-review:general
```

Reviews code for general vulnerability classes:
- Buffer overflows and spatial safety
- Use-after-free and temporal safety
- Integer overflows and numeric errors
- Type confusion
- Format string bugs
- Race conditions
- And 16 more bug classes...

### Linux Userspace Review

```
/c-review:linux-userspace
```

Reviews code for Linux/glibc-specific issues:
- Thread safety violations
- Signal handler safety
- Privilege dropping bugs
- Environment variable security
- EINTR handling
- And 21 more checklist items...

## Workflow

Both review modes follow the same iterative workflow:

1. **Context Building** - Understand codebase architecture, entry points, and trust boundaries
2. **Round 1 Analysis** - Spawn all bug-finding agents in parallel
3. **FP Judging** - Evaluate findings for false positives
4. **Round 2 Analysis** - Re-run agents with FP feedback
5. **Deduplication** - Merge and consolidate findings
6. **Report Generation** - Produce Markdown and SARIF reports

## Agents

### Judge Agents (shared)

| Agent | Purpose |
|-------|---------|
| `fp-judge` | Evaluates findings for false positives |
| `dedup-judge` | Merges duplicate and related findings |

### General Bug-Finding Agents (22)

| Agent | Bug Class |
|-------|-----------|
| `buffer-overflow-finder` | Spatial safety, bounds checking |
| `use-after-free-finder` | Temporal safety, UAF, double-free |
| `integer-overflow-finder` | Numeric errors, signedness |
| `type-confusion-finder` | Type safety, casts, unions |
| `format-string-finder` | Printf/scanf format bugs |
| `string-issues-finder` | Null termination, encoding |
| `uninitialized-data-finder` | Uninitialized memory |
| `null-deref-finder` | Null pointer dereferences |
| `error-handling-finder` | Unchecked errors |
| `memory-leak-finder` | Resource leaks |
| `init-order-finder` | Static initialization order |
| `race-condition-finder` | TOCTOU, double fetch |
| `filesystem-issues-finder` | Symlinks, temp files |
| `iterator-invalidation-finder` | Container modification |
| `banned-functions-finder` | Dangerous functions |
| `dos-finder` | Denial of service |
| `undefined-behavior-finder` | UB patterns |
| `compiler-bugs-finder` | Compiler optimizations |
| `operator-precedence-finder` | Precedence mistakes |
| `time-issues-finder` | Clock/time bugs |
| `access-control-finder` | Privilege issues |
| `regex-issues-finder` | ReDoS, bypasses |

### Linux Userspace Bug-Finding Agents (26)

| Agent | Bug Class |
|-------|-----------|
| `thread-safety-finder` | Non-thread-safe functions |
| `signal-handler-finder` | Async-signal safety |
| `oob-comparison-finder` | memcmp/strncmp bounds |
| `envvar-finder` | Environment variable security |
| `open-issues-finder` | File operation races |
| `privilege-drop-finder` | setuid/setgid bugs |
| `unsafe-stdlib-finder` | sprintf, strcpy, gets |
| `errno-handling-finder` | Return value/errno |
| `eintr-handling-finder` | EINTR retry logic |
| `overlapping-buffers-finder` | memcpy overlap UB |
| `strlen-strcpy-finder` | Null byte miscounting |
| `scanf-uninit-finder` | Uninitialized leaks |
| `snprintf-retval-finder` | Return value misuse |
| `negative-retval-finder` | Negative as size |
| `strncat-misuse-finder` | Size argument confusion |
| `strncpy-termination-finder` | Null termination |
| `qsort-finder` | Non-transitive comparator |
| `memcpy-size-finder` | Negative size |
| `spinlock-init-finder` | Uninitialized locks |
| `inet-aton-finder` | IP validation bypass |
| `socket-disconnect-finder` | AF_UNSPEC disconnect |
| `half-closed-socket-finder` | Partial shutdown |
| `flexible-array-finder` | Zero-length arrays |
| `printf-attr-finder` | Missing format attr |
| `va-start-end-finder` | Variadic pairing |
| `null-zero-finder` | 0 vs NULL |

## Output Formats

### Markdown Report

Human-readable report with:
- Executive summary
- Findings grouped by severity
- Code snippets and locations
- Impact and recommendations

### SARIF Report

Machine-readable SARIF 2.1.0 format for:
- IDE integration (VS Code, etc.)
- CI/CD pipelines
- GitHub Security tab

## Reference

Based on [Trail of Bits C/C++ Security Checklist](https://github.com/trailofbits/publications).

## Requirements

- Claude Code with plugin support
- Optionally: `checksec` for binary mitigation analysis
