---
name: adversarial-verification
description: Verify a claim, idea, approach, design, or finding by dispatching two isolated sub-agents — an advocate (argues the claim is correct/best) and a skeptic (argues it is wrong/inferior) — then synthesize their arguments into a structured verdict. Counters sycophancy and agreement bias by forcing maximal disagreement before the caller commits. Use when making technical decisions ("should we use X or Y?"), reviewing system designs ("is this architecture sound?"), verifying a non-security "X is real" claim such as a performance regression, evaluating strategic claims, or whenever the caller suspects their own reasoning may be one-sided. For deciding whether a security finding is a false positive, use fp-check instead. Triggers on phrases like "verify this claim", "adversarial verification", "is this right?", "which approach is best", "stress-test this idea", "get a second opinion on", "argue against this", or "devil's advocate".
allowed-tools: Agent Read Grep Glob
---

# Adversarial Verification

## Overview

Dispatch two sub-agents with isolated context — one **advocate**, one **skeptic** — to argue opposite sides of a claim as strongly as possible. Then synthesize their arguments into a structured verdict table. This breaks the pattern of single-agent reasoning converging toward agreement and surfaces the strongest objections and the strongest supports in one pass.

**Core principle:** Independent isolated context is non-negotiable. An agent that has read the other side's arguments will soften to accommodate them. The adversarial value comes from each agent arguing without knowledge of the counter-argument.

**Announce at start:** "I'm using the adversarial-verification skill to stress-test this claim."

## When to Use

- Choosing between 2+ technical approaches
- Verifying an "X is real" claim outside fp-check's scope — a performance regression, a reproducibility claim
- Reviewing a design decision before commit
- User asks "is this correct?" about a non-trivial claim
- Any claim you're inclined to agree with by default — that's the tell

## When NOT to Use

- Simple factual lookup ("what version is X?")
- Obvious syntax error fix
- User has already made the decision and is executing
- **Deciding whether a specific security finding is a true or false positive — use `fp-check` instead.** fp-check owns that job and does it properly: full data-flow tracing, exploitability analysis, and a TRUE POSITIVE / FALSE POSITIVE verdict. Proof mode's five-nulls-to-CONFIRMED/DISMISSED is the same verdict in different words, and when two skills match the same request the choice becomes a coin flip. Use proof mode only for "X is real" claims outside fp-check's scope — a performance regression, a reproducibility claim, a non-security assertion.
- Triaging an incoming vulnerability report for whether it merits attention at all — `vulnerability-triage-brocards` applies a fixed rule set to that intake decision. The overlap is weaker (it filters what arrives; this skill stress-tests a claim you already care about), but "should we even look at this?" starts there.

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
| "X is real" claim — reproducibility, regression, attribution | **Proof mode** | Structured N-proof hypotheses (e.g., P1-P5). See [references/proof-mode.md](references/proof-mode.md) |
| Approach / design decision | **Decision mode** | Free-form arguments with evidence. See [references/decision-mode.md](references/decision-mode.md) |

If unsure, default to decision mode.

### Step 3: Dispatch both agents in parallel

Use the Agent tool with TWO tool calls in a SINGLE message (parallel dispatch): one to `adversarial-verification:advocate`, one to `adversarial-verification:skeptic`. Each agent is a fresh context with no knowledge of the other.

Both agents ship with read-only tools (Read, Grep, Glob, WebSearch), declared in the agent definitions. The templates still open with "RESEARCH ONLY", but that line is a reminder, not the enforcement: a prompt marker is a request an agent can talk itself out of, while a `tools:` list is a constraint. Verification must not be able to modify the tree it is verifying — a skeptic testing "this doesn't reproduce in a clean environment" would otherwise be one edit away from changing the user's code during what was sold as a read-only check.

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

Verdict values — the row holds both positions, so the verdict names the party that won it:
- **Advocate wins** — the advocate's position held up; the skeptic's counter did not land
- **Skeptic wins** — the skeptic's objection landed and the advocate did not answer it
- **Split** — both landed partially; the surviving position needs a stated qualification
- **No basis** — neither side brought evidence you can check. Record it as such or cut the point; do not invent a winner out of two speculations

Proof mode uses REFUTED / PROVED / UNCERTAIN instead, because its rows are null hypotheses and the skeptic is the side arguing them. The two vocabularies are not interchangeable — see [references/proof-mode.md](references/proof-mode.md).

Read the verdict off the **evidence**, not off the label each agent gave itself. Both were instructed to argue one side, so their own verdict lines report assigned positions, not findings of fact.

Then write a one-paragraph **recommendation**: which overall position won, which specific claims survived, and what the caller should actually do. The recommendation must commit to a direction even when individual rows came back unresolved.

See [references/synthesis.md](references/synthesis.md) for the full synthesis template.

### Step 5: Report to the caller

Present three things:
1. The claim (one sentence, as stated in Step 1)
2. The verdict table
3. The recommendation (what action follows from the verdict)

Do NOT dump the raw agent outputs unless the user asks. The verdict is the product.

## Reference Guide

- Mode selection quick reference: [references/decision-mode.md](references/decision-mode.md) and [references/proof-mode.md](references/proof-mode.md)
- Prompt templates for advocate and skeptic dispatch: [references/prompt-templates.md](references/prompt-templates.md)
- Verdict table and recommendation shape: [references/synthesis.md](references/synthesis.md)
- Failure modes and recovery patterns: [references/anti-patterns.md](references/anti-patterns.md)

## Anti-patterns

See [references/anti-patterns.md](references/anti-patterns.md) for full failure modes. The three most important:

1. **False symmetry** — treating both sides as equally valid when one is clearly stronger. The *recommendation* must pick a direction, not split the difference. Individual rows may legitimately come back unresolved; a recommendation may not.
2. **Hedged agents** — agents that softened their argument. If an agent returns a balanced view, re-dispatch once with a stronger prompt. If the retry hedges too, the question is undecidable on the available evidence — record **No basis** (decision mode) or **UNCERTAIN** (proof mode) rather than dispatching again.
3. **Shared context leakage** — mentioning the other agent's arguments in either prompt. This collapses independence. Each prompt must be written as if that agent is the only one you've asked.

## Examples

### Example A — approach decision (decision mode)

Setup: a fuzzing project hunting for bugs in Rosetta 2, Apple's x86-to-ARM64 translator on macOS. YARPGen is an off-the-shelf random C program generator; the competing options are hand-written grammar-aware x86 mutation and a Cascade-style oracle. The team has no Intel hardware to use as a reference implementation.

Claim: *"Using YARPGen to generate C programs is the fastest path to finding semantic translation bugs in Rosetta 2."*

Dispatch:
- Advocate prompt: "Make the strongest case FOR this claim. Cite known bugs YARPGen would catch, expected exec/s, why compiler-emitted code is the right attack surface. Do not be balanced."
- Skeptic prompt: "Make the strongest case AGAINST. YARPGen has no FP support, known Rosetta bugs are in FP/SIMD/implicit registers, oracle problem without Intel hardware. Do not be balanced."

Result: the verdict table gives **Skeptic wins** on FP coverage and on the oracle problem, **Advocate wins** on setup effort. Recommendation: use YARPGen as a complement, not the primary strategy.

### Example B — reproducibility claim (proof mode)

Setup: same project as Example A. The fuzzer hit a SIGABRT inside Rosetta's own translation library on an input using the `pcmpestrm` SSE 4.2 instruction, in a register-allocation routine. FINDING-001 is the project's label for that crash. The question here is reproducibility and attribution — is the crash real, and is it in the translator — not exploitability; a claim of the form "this is an exploitable vulnerability" belongs to `fp-check`.

Claim: *"FINDING-001 (pcmpestrm register allocator abort) is a real translation bug."*

Dispatch with 5 proofs, each tests one null hypothesis:
- P1: "This is just normal input rejection (exit -302)."
- P2: "This is a harness artifact (doesn't reproduce in clean env)."
- P3: "This is a benign assertion (SIGABRT in validation code)."
- P4: "The input is unreachable in practice (no compiler emits it)."
- P5: "Already fixed in a newer macOS."

Skeptic tries to prove each null; advocate tries to refute each. CONFIRMED requires all 5 **affirmatively refuted** with evidence the caller can check — a null neither side managed to reach is UNCERTAIN, not refuted.

## Integration

**Dispatches:** `adversarial-verification:advocate` and `adversarial-verification:skeptic` — the two read-only research agents this skill sends out in parallel in Step 3. These are the names a caller needs; a caller that wants only one side of a claim can dispatch either on its own.

**Called by:**
- User directly via explicit request
- Any skill that needs to verify a claim before acting on it — e.g., when brainstorming an approach choice, when evaluating a code review suggestion that seems technically questionable, or when verifying a proposed root cause before applying a fix
