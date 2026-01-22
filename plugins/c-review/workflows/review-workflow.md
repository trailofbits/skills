# C/C++ Security Review Workflow

Shared workflow for all c-review skills. The review proceeds in iterative rounds.

## Round 0: Threat Model Selection

Before starting the review, determine the threat model by asking the user.
Store the selected threat model and pass it to all subsequent agents.

**Threat Model Context Template (include in all agent prompts):**

```
## Threat Model: [REMOTE | LOCAL_UNPRIVILEGED | BOTH]

[If REMOTE:]
- Attacker can only send data over the network
- No local system access, cannot run code
- Focus on: network input parsing, authentication, protocol handling
- Bugs requiring local access are LOW severity

[If LOCAL_UNPRIVILEGED:]
- Attacker has shell access as unprivileged user
- Can run arbitrary code, read/write user-owned files
- Focus on: privilege escalation, symlink attacks, setuid/setgid issues
- Bugs requiring root access to trigger are LOW severity

[If BOTH:]
- Consider both threat models
- Remote-triggerable bugs are higher priority
- Local privilege escalation bugs are also valuable
```

## Round 1: Context Building

Build comprehensive codebase context before spawning analysis agents.

1. Use the `audit-context-building` skill to create architectural understanding
2. Identify entry points, trust boundaries, and attack surface
3. Map data flows and control flows
4. Document memory allocation patterns and ownership

For Linux userspace reviews, also:
- Run `checksec` on binaries to assess exploit mitigations
- Map signal handlers and multi-threaded sections
- Document environment variable usage

## Round 2: Initial Analysis

Spawn all bug-finding agents in parallel, providing each with:
- Codebase context from Round 1
- Threat model context from Round 0
- Specific bug class focus (one class per agent)

See individual skill files for the specific agent list.

## Round 3: False Positive Judging

After Round 2 completes, invoke `fp-judge` agent with all findings:
- Evaluate each finding for validity
- Provide reasoning for FP determinations
- Generate feedback for agents on what patterns are FPs in this codebase

## Round 4: Refined Analysis

Re-run bug-finding agents with FP feedback:
- Agents receive list of FP patterns to avoid
- Agents focus on areas not yet covered
- Collect refined findings

## Round 5: Deduplication

Invoke `dedup-judge` agent with all valid findings:
- Group similar/related findings
- Merge duplicates while preserving best description
- Assign severity ratings

## Round 6: Final FP Judging

Invoke `fp-judge` agent again on deduplicated findings:
- Catch FPs that were harder to identify before grouping
- Final quality check before report generation
- Remove any remaining low-confidence findings

## Round 7: Report Generation

Generate final reports in both formats:
1. **Markdown report** - Human-readable, severity-grouped
2. **SARIF report** - Machine-readable for tooling integration

## Finding Format

Each finding should include:

```
## [SEVERITY] Finding Title

**Bug Class:** [category]
**Location:** file.c:123
**Confidence:** High/Medium/Low

### Description
[What the bug is]

### Code
```c
[Relevant code snippet]
```

### Impact
[Security impact if exploited]

### Recommendation
[How to fix]
```

## Severity Classification

Severity depends on the threat model selected in Round 0.

### Remote Threat Model
- **Critical**: Remote code execution, authentication bypass, remote memory corruption
- **High**: Remote DoS, information disclosure over network, SSRF
- **Medium**: Bugs requiring unusual network conditions, timing-dependent remote bugs
- **Low**: Bugs requiring local access to trigger, theoretical issues

### Local Unprivileged Threat Model
- **Critical**: Privilege escalation to root, kernel code execution, sandbox escape
- **High**: Access to other users' data, escape from containers, local arbitrary file access
- **Medium**: Local DoS, information disclosure of privileged data
- **Low**: Bugs requiring attacker to already have elevated privileges

### Both Threat Models
- Use Remote classification for remotely-triggerable bugs
- Use Local classification for local-only bugs
- When a bug is triggerable both ways, use the higher severity
