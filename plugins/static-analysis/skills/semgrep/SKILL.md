---
name: semgrep
description: >-
  Run Semgrep static analysis scan on a codebase using parallel subagents.
  Supports two scan modes — "run all" (full ruleset coverage) and "important
  only" (high-confidence security vulnerabilities). Automatically detects and
  uses Semgrep Pro for cross-file taint analysis when available. Use when asked
  to scan code for vulnerabilities, run a security audit with Semgrep, find
  bugs, or perform static analysis. Spawns parallel workers for multi-language
  codebases.
allowed-tools:
  - Bash
  - Read
  - Glob
  - Task
  - AskUserQuestion
  - TaskCreate
  - TaskList
  - TaskUpdate
---

# Semgrep Security Scan

Run a Semgrep scan with automatic language detection, parallel execution via Task subagents, and merged SARIF output.

## Essential Principles

1. **Always use `--metrics=off`** — Semgrep sends telemetry by default; `--config auto` also phones home. Every `semgrep` command must include `--metrics=off` to prevent data leakage during security audits.
2. **User must approve the scan plan (Step 3 is a hard gate)** — The original "scan this codebase" request is NOT approval. Present exact rulesets, target, engine, and mode; wait for explicit "yes"/"proceed" before spawning scanners.
3. **Third-party rulesets are required, not optional** — Trail of Bits, 0xdea, and Decurity rules catch vulnerabilities absent from the official registry. Include them whenever the detected language matches.
4. **Spawn all scan Tasks in a single message** — Parallel execution is the core performance advantage. Never spawn Tasks sequentially; always emit all Task tool calls in one response.
5. **Always check for Semgrep Pro before scanning** — Pro enables cross-file taint tracking and catches ~250% more true positives. Skipping the check means silently missing critical inter-file vulnerabilities.

## When to Use

- Security audit of a codebase
- Finding vulnerabilities before code review
- Scanning for known bug patterns
- First-pass static analysis

## When NOT to Use

- Binary analysis → Use binary analysis tools
- Already have Semgrep CI configured → Use existing pipeline
- Need cross-file analysis but no Pro license → Consider CodeQL as alternative
- Creating custom Semgrep rules → Use `semgrep-rule-creator` skill
- Porting existing rules to other languages → Use `semgrep-rule-variant-creator` skill

## Prerequisites

**Required:** Semgrep CLI (`semgrep --version`). If not installed, see [Semgrep installation docs](https://semgrep.dev/docs/getting-started/).

**Optional:** Semgrep Pro — enables cross-file taint tracking, inter-procedural analysis, and additional languages (Apex, C#, Elixir). Check with:

```bash
semgrep --pro --validate --config p/default 2>/dev/null && echo "Pro available" || echo "OSS only"
```

**Limitations:** OSS mode cannot track data flow across files. Pro mode uses `-j 1` for cross-file analysis (slower per ruleset, but parallel rulesets compensate).

## Scan Modes

Select mode in Step 2 of the workflow. Mode affects both scanner flags and post-processing.

| Mode | Coverage | Findings Reported |
|------|----------|-------------------|
| **Run all** | All rulesets, all severity levels | Everything |
| **Important only** | All rulesets, pre- and post-filtered | Security vulns only, medium-high confidence/impact |

**Important only** applies two filter layers:
1. **Pre-filter**: `--severity MEDIUM --severity HIGH --severity CRITICAL` (CLI flag)
2. **Post-filter**: JSON metadata — keeps only `category=security`, `confidence∈{MEDIUM,HIGH}`, `impact∈{MEDIUM,HIGH}`

See [scan-modes.md](references/scan-modes.md) for metadata criteria and jq filter commands.

## Orchestration Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ MAIN AGENT (this skill)                                          │
│ Step 1: Detect languages + check Pro availability                │
│ Step 2: Select scan mode + rulesets (ref: rulesets.md)           │
│ Step 3: Present plan + rulesets, get approval [⛔ HARD GATE]     │
│ Step 4: Spawn parallel scan Tasks (approved rulesets + mode)     │
│ Step 5: Merge results and report                                 │
└──────────────────────────────────────────────────────────────────┘
         │ Step 4
         ▼
┌─────────────────┐
│ Scan Tasks      │
│ (parallel)      │
├─────────────────┤
│ Python scanner  │
│ JS/TS scanner   │
│ Go scanner      │
│ Docker scanner  │
└─────────────────┘
```

## Workflow

**Follow the detailed workflow in [scan-workflow.md](workflows/scan-workflow.md).** Summary:

| Step | Action | Gate | Key Reference |
|------|--------|------|---------------|
| 1 | Detect languages + Pro availability | — | Use Glob, not Bash |
| 2 | Select scan mode + rulesets | — | [rulesets.md](references/rulesets.md) |
| 3 | Present plan, get explicit approval | ⛔ HARD | AskUserQuestion |
| 4 | Spawn parallel scan Tasks | — | [scanner-task-prompt.md](references/scanner-task-prompt.md) |
| 5 | Merge results and report | — | Merge script (below) |

**Task enforcement:** On invocation, create 5 tasks with blockedBy dependencies (each step blocks the previous). Step 3 is a HARD GATE — mark complete ONLY after user explicitly approves.

**Merge command (Step 5):**

```bash
uv run {baseDir}/scripts/merge_triaged_sarif.py [OUTPUT_DIR]
```

## Agents

| Agent | Tools | Purpose |
|-------|-------|---------|
| `static-analysis:semgrep-scanner` | Bash | Executes parallel semgrep scans for a language category |

Use `subagent_type: static-analysis:semgrep-scanner` in Step 4 when spawning Task subagents.

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "User asked for scan, that's approval" | Original request ≠ plan approval. Present plan, use AskUserQuestion, await explicit "yes" |
| "Step 3 task is blocking, just mark complete" | Lying about task status defeats enforcement. Only mark complete after real approval |
| "I already know what they want" | Assumptions cause scanning wrong directories/rulesets. Present plan for verification |
| "Just use default rulesets" | User must see and approve exact rulesets before scan |
| "Add extra rulesets without asking" | Modifying approved list without consent breaks trust |
| "Third-party rulesets are optional" | Trail of Bits, 0xdea, Decurity catch vulnerabilities not in official registry — REQUIRED |
| "Use --config auto" | Sends metrics; less control over rulesets |
| "One Task at a time" | Defeats parallelism; spawn all Tasks together |
| "Pro is too slow, skip --pro" | Cross-file analysis catches 250% more true positives; worth the time |
| "Semgrep handles GitHub URLs natively" | URL handling fails on repos with non-standard YAML; always clone first |
| "Cleanup is optional" | Cloned repos pollute the user's workspace and accumulate across runs |
| "Use `.` or relative path as target" | Subagents need absolute paths to avoid ambiguity |

## Reference Index

| File | Content |
|------|---------|
| [rulesets.md](references/rulesets.md) | Complete ruleset catalog and selection algorithm |
| [scan-modes.md](references/scan-modes.md) | Pre/post-filter criteria and jq commands |
| [scanner-task-prompt.md](references/scanner-task-prompt.md) | Template for spawning scanner subagents |

| Workflow | Purpose |
|----------|---------|
| [scan-workflow.md](workflows/scan-workflow.md) | Complete 5-step scan execution process |

## Success Criteria

- [ ] Languages detected with file counts; Pro status checked
- [ ] Scan mode selected by user (run all / important only)
- [ ] Rulesets include third-party rules for all detected languages
- [ ] User explicitly approved the scan plan (Step 3 gate passed)
- [ ] All scan Tasks spawned in a single message and completed
- [ ] Every `semgrep` command used `--metrics=off`
- [ ] `findings.sarif` exists in the output directory and is valid JSON
- [ ] Important-only mode: post-filter applied before merge
- [ ] Results summary reported with severity and category breakdown
- [ ] Cloned repos (if any) cleaned up from `[OUTPUT_DIR]/repos/`
