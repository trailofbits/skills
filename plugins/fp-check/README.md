# fp-check

A Claude Code plugin that enforces systematic false positive verification when verifying suspected security bugs.

## Overview

When Claude is asked to verify suspected security bugs, this plugin activates a rigorous per-bug verification process. Bugs are routed through one of two paths:

- **Standard verification** — a linear single-pass checklist for straightforward bugs (clear claim, single component, well-understood bug class). No task creation overhead.
- **Deep verification** — full task-based orchestration with parallel sub-phases for complex bugs (cross-component, race conditions, ambiguous claims, logic bugs without spec).

Both paths end with six mandatory gate reviews. Each bug receives a **TRUE POSITIVE** or **FALSE POSITIVE** verdict with documented evidence.

## Installation

```
/plugin install fp-check
```

## Components

### Skills

| Skill | Description |
|-------|-------------|
| [fp-check](skills/fp-check/SKILL.md) | Systematic false positive verification for security bug analysis |

### Agents

| Agent | Phases | Description |
|-------|--------|-------------|
| [data-flow-analyzer](agents/data-flow-analyzer.md) | 1.1–1.4 | Traces data flow from source to sink, maps trust boundaries, checks API contracts and environment protections |
| [exploitability-verifier](agents/exploitability-verifier.md) | 2.1–2.4 | Proves attacker control, creates mathematical bounds proofs, assesses race condition feasibility |
| [poc-builder](agents/poc-builder.md) | 4.1–4.5 | Creates pseudocode, executable, unit test, and negative PoCs |

### Hooks

| Hook | Event | Purpose |
|------|-------|---------|
| Verification completeness | Stop | Blocks the agent from stopping until all bugs have completed all 5 phases, gate reviews, and verdicts |
| Agent output completeness | SubagentStop | Blocks agents from stopping until they produce complete structured output for their assigned phases |

### Reference Files

| File | Purpose |
|------|---------|
| [standard-verification.md](skills/fp-check/references/standard-verification.md) | Linear single-pass checklist for straightforward bugs |
| [deep-verification.md](skills/fp-check/references/deep-verification.md) | Full task-based orchestration with parallel sub-phases for complex bugs |
| [gate-reviews.md](skills/fp-check/references/gate-reviews.md) | Six mandatory gates and verdict format |
| [false-positive-patterns.md](skills/fp-check/references/false-positive-patterns.md) | 13-item checklist of common false positive patterns and red flags |
| [evidence-templates.md](skills/fp-check/references/evidence-templates.md) | Documentation templates for verification evidence |
| [bug-class-verification.md](skills/fp-check/references/bug-class-verification.md) | Bug-class-specific verification requirements (memory corruption, logic bugs, race conditions, etc.) |

## Triggers

The skill activates when the user asks to verify a suspected bug:

- "Is this bug real?" / "Is this a true positive?"
- "Is this a false positive?" / "Verify this finding"
- "Check if this vulnerability is exploitable"

The skill does **not** activate for bug hunting ("find bugs", "security analysis", "audit code").

## Methodology

Each bug is routed based on complexity:

### Standard Path

For bugs with a clear claim, single component, and well-understood bug class:

1. **Data flow** — trace source to sink, check API contracts and protections
2. **Exploitability** — prove attacker control, bounds proofs, race feasibility
3. **Impact** — real security impact vs operational robustness
4. **PoC sketch** — pseudocode PoC required
5. **Devil's advocate spot-check** — 5+2 targeted questions
6. **Gate review** — six mandatory gates

Standard verification escalates to deep at two checkpoints if complexity warrants it.

### Deep Path

For bugs with ambiguous claims, cross-component paths, concurrency, or logic bugs:

1. **Claim analysis** — restate the vulnerability claim precisely, classify the bug class
2. **Context extraction** — execution context, caller analysis, architectural and historical context
3. **Phase 1: Data flow analysis** — trust boundary mapping, API contracts, environment protections, cross-references
4. **Phase 2: Exploitability verification** — attacker control, mathematical bounds proofs, race condition proof, adversarial analysis
5. **Phase 3: Impact assessment** — real security impact vs operational robustness, primary controls vs defense-in-depth
6. **Phase 4: PoC creation** — pseudocode with data flow diagrams, executable PoC, unit test PoC, negative PoC
7. **Phase 5: Devil's advocate review** — 13-question challenge with LLM hallucination self-check
8. **Gate reviews** — six mandatory gates before any verdict
