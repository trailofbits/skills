---
name: c-review:linux-userspace
description: Run comprehensive C/C++ security review for Linux userspace issues
allowed-tools:
  - Read
  - Grep
  - Glob
  - Task
  - Write
  - Bash
---

# C/C++ Linux Userspace Security Review

Perform comprehensive security review of C/C++ code for Linux userspace-specific vulnerabilities.

## Workflow

### Step 1: Build Context

First, gather codebase context:
1. Run `checksec` on binaries if available to assess mitigations
2. Identify privilege boundaries (setuid, capabilities)
3. Map signal handlers and multi-threaded sections
4. Document environment variable usage
5. Identify glibc function usage patterns

If the user hasn't specified target files, ask what code to review.

### Step 2: Round 1 - Initial Analysis

Spawn ALL of the following bug-finding agents in parallel using the Task tool.
Provide each agent with the codebase context and target files.

**Agents to spawn (in parallel):**
- `thread-safety-finder` - Non-thread-safe functions
- `signal-handler-finder` - Signal handler safety
- `oob-comparison-finder` - Out-of-bounds comparisons
- `envvar-finder` - Environment variable issues
- `open-issues-finder` - File operation issues
- `privilege-drop-finder` - Privilege dropping bugs
- `unsafe-stdlib-finder` - Banned stdlib functions
- `errno-handling-finder` - Return value/errno issues
- `eintr-handling-finder` - EINTR handling
- `overlapping-buffers-finder` - Overlapping buffer UB
- `strlen-strcpy-finder` - Null byte miscounting
- `scanf-uninit-finder` - scanf uninitialized leaks
- `snprintf-retval-finder` - snprintf return value misuse
- `negative-retval-finder` - Negative return handling
- `strncat-misuse-finder` - strncat size confusion
- `strncpy-termination-finder` - strncpy null termination
- `qsort-finder` - Non-transitive comparator
- `memcpy-size-finder` - Negative size arguments
- `spinlock-init-finder` - Uninitialized spinlocks
- `inet-aton-finder` - IP address validation
- `socket-disconnect-finder` - Socket disconnect issues
- `half-closed-socket-finder` - Half-closed sockets
- `flexible-array-finder` - Zero/one-element arrays
- `printf-attr-finder` - Missing format attribute
- `va-start-end-finder` - va_start/va_end pairing
- `null-zero-finder` - Zero instead of NULL

Collect all findings from Round 1.

### Step 3: Round 2 - False Positive Judging

Invoke the `fp-judge` agent with all Round 1 findings.
The FP judge will:
- Evaluate each finding for validity
- Provide reasoning for FP determinations
- Generate feedback patterns to avoid

### Step 4: Round 3 - Refined Analysis

Re-run the bug-finding agents with the FP feedback.
Agents should:
- Avoid patterns marked as FP
- Focus on areas not yet covered
- Provide refined findings

### Step 5: Deduplication

Invoke the `dedup-judge` agent with all valid findings to:
- Merge duplicate findings
- Group related issues
- Assign final severity ratings

### Step 6: Report Generation

Generate two report formats:

1. **Markdown Report** (`c-review-linux-report.md`):
   - Executive summary
   - Exploit mitigation assessment (from checksec)
   - Findings grouped by severity (Critical, High, Medium, Low)
   - Each finding with: description, location, impact, recommendation
   - Statistics and metrics

2. **SARIF Report** (`c-review-linux-report.sarif`):
   - Standard SARIF 2.1.0 format
   - Suitable for IDE/CI integration
   - Include all findings with locations

## Output

Present findings summary to user showing:
- Total findings by severity
- Exploit mitigation status
- Top critical/high findings
- Links to generated reports
