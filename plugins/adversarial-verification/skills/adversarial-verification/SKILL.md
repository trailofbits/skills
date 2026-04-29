---
name: adversarial-verification
description: Verify a claim, idea, approach, design, or finding by dispatching two isolated sub-agents — an advocate (argues the claim is correct/best) and a skeptic (argues it is wrong/inferior) — then synthesize their arguments into a structured verdict. Counters sycophancy and agreement bias by forcing maximal disagreement before the caller commits. Use when making technical decisions ("should we use X or Y?"), verifying bug findings ("is this a real bug?"), reviewing system designs ("is this architecture sound?"), evaluating strategic claims, or whenever the caller suspects their own reasoning may be one-sided. Triggers on phrases like "verify this claim", "adversarial verification", "is this right?", "prove this is a real bug", "which approach is best", "stress-test this idea", "get a second opinion on", "argue against this", "devil's advocate", or whenever pattern-breaking from agreement is needed.
---

# Adversarial Verification

## Overview

Dispatch two sub-agents with isolated context — one **advocate**, one **skeptic** — to argue opposite sides of a claim as strongly as possible. Then synthesize their arguments into a structured verdict table. This breaks the pattern of single-agent reasoning converging toward agreement and surfaces the strongest objections and the strongest supports in one pass.

**Core principle:** Independent isolated context is non-negotiable. An agent that has read the other side's arguments will soften to accommodate them. The adversarial value comes from each agent arguing without knowledge of the counter-argument.

**Announce at start:** "I'm using the adversarial-verification skill to stress-test this claim."

## When to use

| Situation | Use this skill? |
|-----------|----------------|
| Choosing between 2+ technical approaches | YES |
| Verifying a bug finding is real (not false positive) | YES |
| Reviewing a design decision before commit | YES |
| User asks "is this correct?" on non-trivial claim | YES |
| Any claim you're inclined to agree with by default | YES — that's the tell |
| Simple factual lookup ("what version is X?") | NO |
| Obvious syntax error fix | NO |
| User has already made the decision and is executing | NO |

## The Process

### Step 1: State the claim precisely

Before dispatching agents, state the claim in a single sentence. Ambiguous claims produce worthless verifications.

**Bad:** "Should we use yarpgen?"
**Good:** "YARPGen program-level differential testing is the best strategy for finding semantic translation bugs in Rosetta 2, better than grammar-aware x86 mutation or a Cascade-style oracle."

The claim must be **falsifiable** — something the skeptic could in principle prove wrong.

### Step 2: Select the mode

Two modes, chosen by the claim type:

| Claim type | Mode | Details |
|-----------|------|---------|
| Bug finding / security claim | **Proof mode** | Structured N-proof hypotheses (e.g., P1-P5). See [references/proof-mode.md](references/proof-mode.md) |
| Approach / design decision | **Decision mode** | Free-form arguments with evidence. See [references/decision-mode.md](references/decision-mode.md) |

If unsure, default to decision mode.

### Step 3: Dispatch both agents in parallel

Use the Agent tool with TWO tool calls in a SINGLE message (parallel dispatch). Each agent is a fresh context with no knowledge of the other.

Load prompt templates from [references/prompt-templates.md](references/prompt-templates.md). The templates enforce:
- Each agent argues ONE side maximally, not balanced
- Each agent is told explicitly "do not be balanced" and "argue as hard as possible"
- Each agent cites specific evidence (files, line numbers, facts)
- Each agent anticipates and pre-refutes the obvious counter-arguments

Give each agent the **same claim**, the **same background context**, but **opposite instructions**. Never mention the other agent's existence or arguments in either prompt.

### Step 4: Synthesize with a verdict table

After both agents return, produce a verdict table. For each significant point raised by either side:

| Point | Advocate position | Skeptic position | Verdict |
|-------|-------------------|------------------|---------|

Verdict values:
- **Survives** — one side's position held up; the other failed to counter it
- **Weakens** — partially rebutted; position should be qualified
- **Falls** — cleanly refuted by the other side

Then write a one-paragraph **recommendation**: which overall position won, which specific claims survived, and what the caller should actually do.

See [references/synthesis.md](references/synthesis.md) for the full synthesis template.

### Step 5: Report to the caller

Present three things:
1. The claim (one sentence, as stated in Step 1)
2. The verdict table
3. The recommendation (what action follows from the verdict)

Do NOT dump the raw agent outputs unless the user asks. The verdict is the product.

## Anti-patterns

See [references/anti-patterns.md](references/anti-patterns.md) for full failure modes. The three most important:

1. **False symmetry** — treating both sides as equally valid when one is clearly stronger. The verdict must pick a winner, not split the difference.
2. **Hedged agents** — agents that softened their argument. If an agent returns a balanced view, re-dispatch with a stronger prompt. Real adversarial value requires real adversarial arguments.
3. **Shared context leakage** — mentioning the other agent's arguments in either prompt. This collapses independence. Each prompt must be written as if that agent is the only one you've asked.

## Examples

### Example A — approach decision (decision mode)

Claim: *"Using YARPGen to generate C programs is the fastest path to finding semantic translation bugs in Rosetta 2."*

Dispatch:
- Advocate prompt: "Make the strongest case FOR this claim. Cite known bugs YARPGen would catch, expected exec/s, why compiler-emitted code is the right attack surface. Do not be balanced."
- Skeptic prompt: "Make the strongest case AGAINST. YARPGen has no FP support, known Rosetta bugs are in FP/SIMD/implicit registers, oracle problem without Intel hardware. Do not be balanced."

Result: verdict table shows skeptic's "no FP support" and "oracle problem" survive; advocate's "fastest to set up" survives. Recommendation: use YARPGen as complement, not primary strategy.

### Example B — bug verification (proof mode)

Claim: *"FINDING-001 (pcmpestrm register allocator abort) is a real translation bug, not a false positive."*

Dispatch with 5 proofs, each tests one null hypothesis:
- P1: "This is just normal input rejection (exit -302)."
- P2: "This is a harness artifact (doesn't reproduce in clean env)."
- P3: "This is a benign assertion (SIGABRT in validation code)."
- P4: "The input is unreachable in practice (no compiler emits it)."
- P5: "Already fixed in a newer macOS."

Skeptic tries to prove each null; advocate tries to refute each. If all 5 fail to prove = CONFIRMED bug.

## Integration

**Called by:**
- User directly via explicit request
- Any skill that needs to verify a claim before acting on it — e.g., when brainstorming an approach choice, when evaluating a code review suggestion that seems technically questionable, or when verifying a proposed root cause before applying a fix
