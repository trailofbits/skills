---
name: c-review
description: Run comprehensive C/C++ security review with automatic prompt selection
allowed-tools:
  - Skill
  - AskUserQuestion
---

# C/C++ Security Review

Thin entry point — gathers user options and invokes the `c-review` skill **in the main conversation**.

**Why `Skill`, not `Agent(subagent_type="general-purpose", ...)`:** the skill's orchestration uses `TaskCreate`/`TaskUpdate`/`TaskList`/`TaskGet` for the shared worker queue. Those are deferred tools in a `general-purpose` subagent. Keeping orchestration in the main conversation (via `Skill`) means the orchestrator gets them via its skill `allowed-tools`; workers and judges run as **named plugin subagents** (`c-review:c-review-worker`, etc.) whose tool sets are declared eagerly in `plugins/c-review/agents/*.md`, so no bootstrap ceremony is needed at any level.

## Step 1: Collect options

Call `AskUserQuestion` once with all three questions:

**Question 1 — Threat model:**
- Remote — Network attacker only
- Local Unprivileged — Shell access as unprivileged user
- Both (Recommended)

**Question 2 — Worker model:**
- Haiku — Fast, cost-effective (Recommended)
- Sonnet — Deeper reasoning
- Opus — Maximum capability

**Question 3 — Severity filter:**
- All — Report every finding
- Medium and above (Recommended) — Drop Low-severity findings
- High and above — Critical/High only

Parse any arguments the user passed on the slash-command line (e.g. `only medium,high,and critical issues` → `severity_filter=medium`) and use them to pre-fill answers.

## Step 2: Invoke the skill in the main conversation

Call the `Skill` tool:

```
Skill(
  skill="c-review:c-review",
  args="threat_model=<REMOTE|LOCAL_UNPRIVILEGED|BOTH> worker_model=<haiku|sonnet|opus> severity_filter=<all|medium|high>"
)
```

The skill's `SKILL.md` is loaded into the main conversation and drives the full orchestration: output-directory setup, task queue, parallel worker spawn, judge pipeline. Do **not** wrap the call in `Agent(subagent_type="general-purpose", ...)` — that makes the orchestrator's own `Task*` tools deferred and requires a bootstrap step it's not set up to do.

## Step 3: Present results

The skill writes the final report to `${output_dir}/REPORT.md` and returns its contents. Present the report to the user grouped by severity (Critical → High → Medium → Low, filtered per `severity_filter`) and point at `${output_dir}/` for the raw artifacts (individual finding files, FP/dedup summaries). Offer SARIF export if requested.
