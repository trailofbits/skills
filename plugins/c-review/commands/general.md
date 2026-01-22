---
name: c-review:general
description: Run comprehensive C/C++ security review for general bug classes
allowed-tools:
  - Read
  - Grep
  - Glob
  - Task
  - Write
  - Bash
---

# C/C++ General Security Review

Perform comprehensive security review of C/C++ code for general vulnerability classes.

## Workflow

### Step 1: Build Context

First, gather codebase context using the audit-context-building skill or by:
1. Identifying entry points and attack surface
2. Mapping data flows from untrusted input
3. Understanding memory allocation patterns
4. Documenting trust boundaries

If the user hasn't specified target files, ask what code to review.

### Step 2: Round 1 - Initial Analysis

Spawn ALL of the following bug-finding agents in parallel using the Task tool.
Provide each agent with the codebase context and target files.

**Agents to spawn (in parallel):**
- `buffer-overflow-finder` - Spatial safety issues
- `use-after-free-finder` - Temporal safety issues
- `integer-overflow-finder` - Numeric errors
- `type-confusion-finder` - Type safety issues
- `format-string-finder` - Variadic function misuse
- `string-issues-finder` - String handling bugs
- `uninitialized-data-finder` - Uninitialized memory
- `null-deref-finder` - Null pointer dereferences
- `error-handling-finder` - Unhandled errors
- `memory-leak-finder` - Resource leaks
- `init-order-finder` - Initialization order bugs
- `race-condition-finder` - Concurrency issues
- `filesystem-issues-finder` - File operation bugs
- `iterator-invalidation-finder` - Iterator bugs
- `banned-functions-finder` - Dangerous functions
- `dos-finder` - Denial of service
- `undefined-behavior-finder` - UB patterns
- `compiler-bugs-finder` - Compiler issues
- `operator-precedence-finder` - Precedence bugs
- `time-issues-finder` - Time handling bugs
- `access-control-finder` - Privilege issues
- `regex-issues-finder` - Regex vulnerabilities

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

1. **Markdown Report** (`c-review-report.md`):
   - Executive summary
   - Findings grouped by severity (Critical, High, Medium, Low)
   - Each finding with: description, location, impact, recommendation
   - Statistics and metrics

2. **SARIF Report** (`c-review-report.sarif`):
   - Standard SARIF 2.1.0 format
   - Suitable for IDE/CI integration
   - Include all findings with locations

## Output

Present findings summary to user showing:
- Total findings by severity
- Top critical/high findings
- Links to generated reports
