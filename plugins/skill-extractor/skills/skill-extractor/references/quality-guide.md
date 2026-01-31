# Skill Quality Guide

Standards for generating high-quality skills that provide lasting value.

## Before Generating

**Required:** Use the `claude-code-guide` subagent to review Anthropic's skill best practices
documentation before generating. This ensures the skill follows current conventions for:
- Frontmatter structure
- Naming conventions
- Content organization
- Trigger descriptions

## Value-Add Principle

Skills should provide guidance Claude doesn't already have.

**DO:**
- Behavioral guidance - When and how to apply knowledge
- Explain WHY - Trade-offs, decision criteria, judgment calls
- Anti-patterns WITH explanations - Why something is wrong, not just that it's wrong

**DON'T:**
- Reference dumps - Don't paste entire specs or docs
- Step-only instructions - "Do X, then Y" without explaining when or why
- Vague guidance - "Be careful with X" without specifics

**Good example:** A DWARF debugging skill doesn't include the full DWARF spec. It teaches
how to use `dwarfdump`, `readelf`, and `pyelftools` to look up what's needed, plus
judgment about when each tool is appropriate.

## Description Triggers

Your skill competes with 100+ others for activation. The description determines when
Claude uses it.

| Quality | Example |
|---------|---------|
| Bad | "Helps with security" |
| Bad | "Smart contract tool" |
| Good | "Detects reentrancy vulnerabilities in Solidity. Use when auditing external calls." |

## Anti-Pattern Examples

### Bad: Reference Dump

```markdown
## Solution
Here is the complete API documentation for the library...
[500 lines of copied docs]
```

**Why it's bad:** Claude can already look this up. No added value.

### Bad: Steps Without Context

```markdown
## Solution
1. Run `uv add httpx`
2. Add `import httpx`
3. Call `httpx.get(url)`
```

**Why it's bad:** No explanation of when this applies or what problems it solves.

### Bad: Vague Triggers

```yaml
description: "Helps with database issues"
```

**Why it's bad:** Will either never trigger or trigger too often.

### Good: Behavioral Guidance

```markdown
## When to Use
- `ECONNREFUSED` on port 5432 after mass test runs
- "too many connections" in CI but not locally
- Connection works initially, fails after ~100 requests

## Problem
Connection pool exhaustion in serverless environments where each invocation
creates new connections but the runtime persists.

## Solution
### Why this happens
Serverless functions reuse the execution context but not the connection state...

### Step 1: Diagnose
Check current connections: `SELECT count(*) FROM pg_stat_activity;`
If > max_connections, this is the issue.

### Step 2: Fix
[Specific fix with explanation of WHY it works]
```

## Scope Boundaries

Match prescriptiveness to task risk:

| Task Type | Approach |
|-----------|----------|
| Security audits, crypto | Rigid step-by-step, no shortcuts |
| Bug investigation | Flexible, multiple approaches |
| Code exploration | Options and judgment calls |
