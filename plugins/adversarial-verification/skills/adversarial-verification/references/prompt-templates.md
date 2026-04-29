# Prompt Templates

Prompts are the most important part of this skill. A weak prompt produces a hedged agent, and a hedged agent produces a worthless verdict. These templates enforce maximal adversarial stance.

## Table of contents

- [Template: Advocate (decision mode)](#template-advocate-decision-mode)
- [Template: Skeptic (decision mode)](#template-skeptic-decision-mode)
- [Template: Advocate (proof mode)](#template-advocate-proof-mode)
- [Template: Skeptic (proof mode)](#template-skeptic-proof-mode)
- [Required elements](#required-elements)
- [How to fill in context](#how-to-fill-in-context)

## Required elements

Every prompt MUST include all of these. Missing any produces a weak agent.

1. **Role statement** — "You are the ADVOCATE/SKEPTIC for X"
2. **Explicit side assignment** — "argue FOR / argue AGAINST"
3. **Background context** — claim, alternatives, prior findings, file paths the agent can read
4. **Anti-balance directive** — "Do NOT be balanced. Argue as hard as possible for your side"
5. **Evidence requirement** — "Cite specific files, line numbers, facts, CVEs, benchmarks"
6. **Counter-refutation requirement** — "Anticipate and pre-refute the obvious counter-arguments"
7. **Output shape** — what the agent should produce (arguments with headers, specific claims)
8. **Research-only marker** (if applicable) — "RESEARCH ONLY — do not write code or edit files"

## Template: Advocate (decision mode)

```
RESEARCH ONLY — do not write any code or edit files.

You are the ADVOCATE for {CLAIM}.

Context: {BACKGROUND — 2-5 sentences of project state, what's been tried, why this matters}

The competing alternatives are: {LIST_ALTERNATIVES}

Make the STRONGEST possible case FOR {CLAIM}. Specifically address:
1. {KEY_POINT_1 — e.g., "Why it will find bugs the alternatives miss"}
2. {KEY_POINT_2 — e.g., "Why it's the fastest path to results"}
3. {KEY_POINT_3 — e.g., "Counter the argument that <X>"}
4. {KEY_POINT_4 — e.g., "Concrete expected metrics"}
5. {KEY_POINT_5 — e.g., "Cite specific prior bugs this would catch"}

Relevant files to read: {FILE_PATHS}

Be specific. Cite papers, CVEs, file:line references where possible.

DO NOT BE BALANCED. Argue as hard as possible FOR the claim. The caller has a SEPARATE skeptic agent that will argue the other side; your job is to produce the strongest possible pro-claim argument, not a balanced view.
```

## Template: Skeptic (decision mode)

```
RESEARCH ONLY — do not write any code or edit files.

You are the SKEPTIC arguing AGAINST {CLAIM}. You should argue for one of the alternatives instead.

Context: {BACKGROUND — same as advocate prompt}

The competing alternatives are: {LIST_ALTERNATIVES}

Make the STRONGEST possible case AGAINST {CLAIM} and FOR one of the alternatives. Specifically address:
1. {KEY_POINT_1 — e.g., "Why the claim's reasoning has a structural flaw"}
2. {KEY_POINT_2 — e.g., "The oracle/measurement problem"}
3. {KEY_POINT_3 — e.g., "Why the alternatives are fundamentally better"}
4. {KEY_POINT_4 — e.g., "Specific scenarios where the claim fails"}
5. {KEY_POINT_5 — e.g., "Expected false positive/false negative rate"}

Relevant files to read: {FILE_PATHS}

Be specific. Cite papers, CVEs, file:line references where possible.

DO NOT BE BALANCED. Argue as hard as possible AGAINST the claim. The caller has a SEPARATE advocate agent that will argue for it; your job is to produce the strongest possible anti-claim argument, not a balanced view.
```

## Template: Advocate (proof mode)

```
RESEARCH ONLY — do not write any code or edit files.

You are the ADVOCATE proving {FINDING/BUG/CLAIM} is real.

Context: {BACKGROUND — what the finding is, how it was discovered, initial evidence}

Your job: REFUTE each of the N null hypotheses below. Each null hypothesis, if true, would dismiss the finding. Show each one is false.

Null hypotheses to refute:
- P1: {e.g., "This is just normal input rejection"}
- P2: {e.g., "This is a harness artifact"}
- P3: {e.g., "This is a benign assertion"}
- P4: {e.g., "The input is unreachable in practice"}
- P5: {e.g., "Already fixed"}

For each P, provide:
- Evidence against the null (files, logs, reproducers)
- Concrete reproduction in a clean environment if applicable
- Verdict: REFUTED (with evidence) vs CANNOT REFUTE (with reason)

Relevant files to read: {FILE_PATHS}

DO NOT BE BALANCED. Your job is to defend the finding. A skeptic is being run separately to argue the other side.
```

## Template: Skeptic (proof mode)

```
RESEARCH ONLY — do not write any code or edit files.

You are the SKEPTIC trying to prove {FINDING/BUG/CLAIM} is NOT a real finding.

Context: {BACKGROUND — same as advocate}

Your job: PROVE each of the N null hypotheses below. If any is true, the finding should be dismissed.

Null hypotheses to prove:
- P1: {e.g., "This is just normal input rejection (exit -302)"}
- P2: {e.g., "This is a harness artifact (doesn't reproduce in clean env)"}
- P3: {e.g., "This is a benign assertion in validation code"}
- P4: {e.g., "The input is unreachable by any real attacker"}
- P5: {e.g., "Already fixed in a newer version"}

For each P, provide:
- Evidence FOR the null hypothesis
- What would confirm it (repro steps, logs)
- Verdict: PROVED (with evidence) vs CANNOT PROVE (with reason)

Relevant files to read: {FILE_PATHS}

DO NOT BE BALANCED. Your job is to dismiss the finding if at all possible. An advocate is being run separately to defend it.
```

## How to fill in context

**Keep context tight (≤200 words).** Each agent should have enough to reason, not so much that the adversarial assignment gets diluted. Include:

- **Claim/finding** — one sentence, verbatim
- **What's already known** — 2-3 sentences; prior findings, constraints
- **What the agent should read** — 3-5 specific file paths with line numbers if relevant
- **Known-buggy scenarios** (for claim verification) — a concrete list the agent can cross-reference

Do NOT include:
- The other agent's arguments (even hints)
- Your own inclination ("I think this is probably...")
- The expected answer

## Re-dispatching on hedged agents

If an agent returns something like "I see merits on both sides" or "this is a nuanced question" or "both approaches have tradeoffs" — that is a failure. The prompt was too weak.

Re-dispatch with stronger phrasing:

> "Your previous response was too balanced. You are the ADVOCATE/SKEPTIC. Do not acknowledge merit in the opposing position. Do not hedge. Argue ONE side as hard as possible — the synthesis step happens separately. Return ONLY the strongest pro-{SIDE} argument. If you cannot make a strong case for your side, say so explicitly, but do not substitute a balanced view."
