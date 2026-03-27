---
name: c-review
description: Run comprehensive C/C++ security review with automatic prompt selection
allowed-tools:
  - Task
  - AskUserQuestion
---

# C/C++ Security Review

Thin entry point - gathers user options and invokes the skill.

**Tool inheritance:** This command only needs `Task` and `AskUserQuestion`. The spawned `general-purpose` task has access to all tools required by the skill (Read, Grep, Glob, LSP, Bash, TaskCreate, TaskUpdate, TaskList, TaskGet).

## Step 1: Select Options

AskUserQuestion (both questions in one call):

**Question 1:** "What is the threat model?"
- Remote - Network attacker only
- Local Unprivileged - Shell access as unprivileged user
- Both (Recommended)

**Question 2:** "Which model should workers use?"
- Haiku - Fast, cost-effective (Recommended)
- Sonnet - Deeper reasoning
- Opus - Maximum capability

## Step 2: Execute Review

```
Task(
  subagent_type="general-purpose",
  prompt="""
Read ${CLAUDE_PLUGIN_ROOT}/skills/SKILL.md for the complete workflow.

## Parameters

threat_model: [REMOTE|LOCAL_UNPRIVILEGED|BOTH]
worker_model: [haiku|sonnet|opus]

Execute the full C/C++ security review. Return findings report.
"""
)
```

## Step 3: Present Results

Present deduplicated findings grouped by bug class. Offer SARIF export if requested (omit severity/level fields — the pipeline does not assign them).
