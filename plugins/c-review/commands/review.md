---
name: c-review
description: Run comprehensive C/C++ security review with automatic prompt selection
allowed-tools:
  - Read
  - Grep
  - Glob
  - Task
  - Bash
  - AskUserQuestion
  - Skill
---

# C/C++ Security Review

Thin entry point that gathers user input and invokes the coordinator agent.

## Step 1: Check Prerequisites

```bash
which clangd
```

If NOT found:
- AskUserQuestion: "clangd not found. Install or continue without LSP?"

```bash
fd compile_commands.json . --type f 2>/dev/null | head -5
```

If NOT found, suggest: CMake, Bear, or compiledb.

## Step 2: Detect Code Characteristics

```bash
fd -e cpp -e cxx -e cc -e hpp . | head -5
```
→ `is_cpp = true/false`

```
Grep: pattern="#include.*<(pthread|signal|sys/(socket|stat|types|wait)|unistd|errno)\.h>"
```
→ `is_posix = true/false` (applies to Linux, macOS, BSD)

```
Grep: pattern="#include.*<(windows|winbase|winnt|winuser|winsock|ntdef|ntstatus)\.h>"
```
→ `is_windows = true/false`

Report to user:
- C++ detected: yes/no
- POSIX userspace code detected: yes/no (Linux/macOS/BSD patterns)
- Windows userspace code detected: yes/no

## Step 3: Select Threat Model and Worker Model

AskUserQuestion (ask both in one call):

**Question 1:** "What is the threat model?"
- Options:
  1. Remote - Network attacker only
  2. Local Unprivileged - Shell access as unprivileged user
  3. Both (Recommended)

→ `threat_model = REMOTE | LOCAL_UNPRIVILEGED | BOTH`

**Question 2:** "Which model should workers use for bug finding?"
- Options:
  1. Haiku - Fast, cost-effective, good for large codebases (Recommended)
  2. Sonnet - Deeper reasoning, better for subtle bugs
  3. Opus - Maximum capability, highest cost

→ `worker_model = haiku | sonnet | opus`

Calculate disabled prompts:
```
if threat_model == REMOTE:
    disabled_prompts = ["privilege-drop-finder", "envvar-finder"]
else:
    disabled_prompts = []
```

## Step 4: Build Context (Optional)

If `audit-context-building` skill available:
```
Skill(skill="audit-context-building:audit-context-building")
```
→ `codebase_context`

Otherwise: `codebase_context = ""`

## Step 5: Invoke Coordinator

```
Task(
  subagent_type="c-review:coordinator",
  prompt="""
## Review Parameters

is_cpp: [true/false]
is_posix: [true/false]  # Linux, macOS, BSD userspace
is_windows: [true/false]  # Windows userspace
threat_model: [REMOTE|LOCAL_UNPRIVILEGED|BOTH]
worker_model: [haiku|sonnet|opus]
disabled_prompts: [list]
codebase_context: [context or empty]

## Instructions

Follow the skill instructions at ${CLAUDE_PLUGIN_ROOT}/skills/SKILL.md.
Execute the full review workflow using task management.
Return the final findings report.
"""
)
```

## Step 6: Present Results

After coordinator completes:
1. Present findings by severity (CRITICAL → LOW)
2. AskUserQuestion: "Generate SARIF output?" → If yes, write `findings.sarif.json`
