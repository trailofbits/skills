# C/C++ Security Review Workflow

Shared workflow for all c-review skills. The review proceeds in iterative rounds.

## Round 0: Prerequisites Check

Before starting, verify required tooling:

**Required: clangd LSP**

Check if clangd is available:
```bash
which clangd
```

If clangd is not found, use AskUserQuestion to inform the user:

**Question:** "clangd is required for accurate C/C++ analysis but was not found. How would you like to proceed?"
**Options:**
- Install clangd (recommended) - I'll provide installation instructions
- Continue without LSP - Analysis will be less accurate

If user chooses to install, provide platform-specific instructions:
- **macOS:** `brew install llvm` or `xcode-select --install`
- **Ubuntu/Debian:** `apt install clangd`
- **Fedora:** `dnf install clang-tools-extra`
- **Arch:** `pacman -S clang`

Also verify `compile_commands.json` exists for accurate symbol resolution:
```bash
find . -name compile_commands.json -type f
```

If not found, suggest generating it:
- **CMake:** `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`
- **Bear:** `bear -- make`
- **compiledb:** `pip install compiledb && compiledb make`

**Required: audit-context-building skill**

Check if the `audit-context-building` skill is available. If not, use AskUserQuestion:

**Question:** "The audit-context-building skill is required for comprehensive context analysis but was not found."
**Options:**
- Install it - I'll explain how to add this skill
- Skip context building - Analysis will have less architectural context

## Round 1: Threat Model Selection

Determine the threat model using AskUserQuestion:

**Question:** "What is the threat model for this review?"
**Options:**
- **Remote** - Attacker can only send data over the network
- **Local Unprivileged** - Attacker has shell access as unprivileged user
- **Both** - Consider both threat models

Store the selected threat model and pass it to all subsequent agents.

**Threat Model Context Template (include in all agent prompts):**

```
## Threat Model: [REMOTE | LOCAL_UNPRIVILEGED | BOTH]

[If REMOTE:]
- Attacker can only send data over the network
- No local system access, cannot run code
- Focus on: network input parsing, authentication, protocol handling, memory corruptions
- Findings requiring local access are lower priority

[If LOCAL_UNPRIVILEGED:]
- Attacker has shell access as unprivileged user
- Can run arbitrary code, read/write user-owned files
- Focus on: privilege escalation, symlink attacks, setuid/setgid issues
- Findings requiring root access to trigger are lower priority

[If BOTH:]
- Consider both threat models
- Remote-triggerable findings are higher priority
- Local privilege escalation findings are also valuable
```

## Round 2: Context Building

Build comprehensive codebase context before spawning analysis agents.

1. **Use the `audit-context-building` skill** to create architectural understanding
2. Identify entry points, trust boundaries, and attack surface
3. Map data flows and control flows
4. Document memory allocation patterns and ownership

For Linux userspace reviews, also:
- Map signal handlers and multi-threaded sections
- Document environment variable usage

## Round 3: Initial Analysis

Spawn all bug-finding agents in parallel, providing each with:
- Codebase context from Round 2
- Threat model context from Round 1
- Specific bug class focus (one class per agent)

See individual skill files for the specific agent list.

**Agent Output Requirements:**
- Each finding MUST include a unique Finding ID
- Format: `[BUG_CLASS]-[SEQUENCE]` (e.g., `BOF-001`, `UAF-003`)
- Agents report confidence only, NOT severity

## Round 4: False Positive Judging

After Round 3 completes, invoke `fp-judge` agent with all findings:
- Evaluate each finding for validity **within the threat model**
- Provide reasoning for FP determinations
- Generate feedback for agents on what patterns are FPs in this codebase
- Assign confidence verdict (TRUE_POSITIVE, LIKELY_TP, LIKELY_FP, FALSE_POSITIVE, OUT_OF_SCOPE)

## Round 5: Refined Analysis

Re-run bug-finding agents with FP feedback:
- Agents receive list of FP patterns to avoid
- Agents focus on areas not yet covered
- Collect refined findings with new Finding IDs

## Round 6: Deduplication

Invoke `dedup-judge` agent with all valid findings:
- Group similar/related findings
- Merge duplicates while preserving best description
- Preserve all Finding IDs for traceability

## Round 7: Severity Assessment

Invoke `severity-agent` with deduplicated findings and threat model:
- Assigns severity based on threat model context
- Considers exploitability and impact within the defined threat model
- Produces final severity-ranked finding list

## Round 8: Report Generation

Generate final reports in both formats:
1. **Markdown report** - Human-readable, severity-grouped
2. **SARIF report** - Machine-readable for tooling integration

## Finding Format

Each finding should include:

```
## Finding ID: [BUG_CLASS]-[SEQUENCE]

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

## Final Report Format

After severity assessment, findings are organized by severity:

```
## [CRITICAL/HIGH/MEDIUM/LOW] [Finding ID]: [Title]

**Bug Class:** [category]
**Location:** file.c:123
**Confidence:** High/Medium/Low
**Severity Rationale:** [Why this severity for this threat model]

[Description, Code, Impact, Recommendation as above]
```
