# Anti-patterns

Common failure modes that destroy the adversarial value of this skill. Each has a diagnosis and a fix.

## 1. False symmetry

**Symptom:** The verdict says "both sides have merit" and splits the difference. No clear winner. Vague recommendation like "consider both approaches."

**Why it happens:** Reluctance to pick a side. Treating the adversarial structure as performative rather than decisional.

**Fix:** Pick a winner **in the recommendation**. That is where the refusal to fence-sit belongs: the recommendation must commit to a direction and name the dimensions that decided it. If the table is a 3/3 split, the winner is whichever dimensions matter most for the caller's actual decision — say which, explicitly. "Consider both approaches" is not an output.

Individual rows are a different matter, and forcing every one of them is its own failure. A dimension where both agents returned speculation — no benchmark, no file:line, no citation — has no winner, and inventing one renders a coin flip in the same typeface as an evidence-backed row. Mark that row **No basis**, say what evidence would settle it, or cut the dimension outright if it does not move the decision (§9). What you must never do is manufacture a winner to avoid an empty cell; that is the same error §10 warns about, one column over.

## 2. Hedged agents

**Symptom:** Agent returns things like "I see merits on both sides," "this is a nuanced question," "both approaches have tradeoffs." No strong adversarial position.

**Why it happens:** Weak prompt. The agent defaulted to balanced reasoning because nothing stopped it.

**Fix:** Re-dispatch **once** with a stronger prompt. The key phrase: "Do not acknowledge merit in the opposing position. Do not hedge." Carry the escape clause with it — "If you cannot make a strong case for your side, say so explicitly and state what evidence is missing, but do not substitute a balanced view" — because an agent given no way to report that there is nothing there will hedge again. The retry is a fresh context with no memory of the first answer, so write the addition as a standing instruction rather than as a correction of a response the receiving agent cannot see.

One retry is the cap. If the second dispatch hedges too, or comes back with the escape clause invoked, that is the honest answer: the evidence does not decide this dimension. Record it as **No basis** per §1 and move on. Looping a third time on a genuinely balanced question spends budget to manufacture a verdict you are not entitled to.

If you need the full templates, return to [SKILL.md](../SKILL.md) Step 3.

## 3. Shared context leakage

**Symptom:** Advocate mentions the skeptic's arguments (or vice versa), softening the tone to accommodate. Arguments collapse toward agreement.

**Why it happens:** Prompt mentioned the other agent's existence or previewed their arguments.

**Fix:** Each prompt must be written as if that agent is the ONLY agent you've asked. Do not mention the other side. Do not say "another agent will argue X." Do not give hints about counter-arguments. The synthesis happens separately after both return.

## 4. Unfalsifiable claim

**Symptom:** The skeptic can't argue against the claim because it's too vague or too broad.

**Why it happens:** Claim wasn't stated precisely in Step 1.

**Fix:** Return to Step 1. Rewrite the claim as a specific, falsifiable sentence. "YARPGen is good" (YARPGen being a random C program generator) is unfalsifiable. "YARPGen will catch more Rosetta 2 semantic bugs than grammar-aware mutation in 7 days of fuzzing" is falsifiable — it names a comparison, a target, and a budget.

## 5. Missing evidence

**Symptom:** Agents make claims but don't cite specific files, line numbers, CVEs, benchmarks. Arguments are plausible but unverifiable.

**Why it happens:** Prompt didn't require citations.

**Fix:** Every prompt includes: "Cite specific files, line numbers, facts, CVEs, benchmarks where possible." Reject outputs that make unsupported claims on critical dimensions.

This rejection is not optional bookkeeping — it is the grading pass the verdict rules run on. Both agents were told to argue one side, so each one's own `Verdict:` line reports its assigned position, not a finding of fact. A REFUTED with nothing behind it does not count as refuted, and a Skeptic-wins row backed only by an assertion does not count as a win. Grade the evidence first, then read the labels.

## 6. Wrong mode

**Symptom:** Trying to prove a finding is real with "what do you think is best" prompts, or trying to pick between approaches with proof-style null hypotheses.

**Fix:** Reread [SKILL.md](../SKILL.md) Step 2. Decision mode = approach/design choice. Proof mode = an "X is real" claim: reproducibility, regression, attribution. Pick the right one. If the claim is that a security finding is a true or false positive, neither mode applies — that is `fp-check`'s job, and running this skill on it duplicates the work with two ways to disagree.

## 7. Synthesis dump

**Symptom:** Presenting both agents' full outputs as the result. No verdict table. No recommendation.

**Why it happens:** Skipping the synthesis step.

**Fix:** The verdict table is the product, not the raw arguments. Always produce the table + recommendation. Only dump raw agent outputs if the user explicitly asks for them.

## 8. Confirmation bias in prompt

**Symptom:** Advocate wins trivially because the prompt was stacked in its favor. The skeptic has nothing to work with.

**Why it happens:** Caller's preferred answer leaks into the prompt framing.

**Fix:** Both prompts should frame the claim neutrally. "Make the case FOR/AGAINST {CLAIM}" not "Make the case FOR the obviously correct {CLAIM}". Both agents get the SAME background. If the advocate gets more context than the skeptic, the test is rigged.

## 9. Too many dimensions

**Symptom:** Verdict table has 15 rows. Each row is shallow. Recommendation is unclear because so many points went each way.

**Fix:** Pick 3-5 dimensions. The dimensions should be the ones that actually determine the decision. Cut dimensions that don't move the verdict either way.

## 10. Ignoring UNCERTAIN

**Symptom:** Proof-mode verdict marks every null as REFUTED/PROVED when some were actually UNCERTAIN. Finding is reported as CONFIRMED when one null is still plausible.

**Fix:** UNCERTAIN is a valid outcome. If P4 ("input unreachable") has evidence on both sides, the finding is NOT confirmed. Either:
- Gather more evidence on that specific P before concluding, OR
- Report the finding WITH the caveat that P4 is uncertain

The same applies to a null that neither agent ever reached — no reproducer, no source access, budget exhausted. That is UNCERTAIN, not REFUTED: nobody looked, so nothing was ruled out, and a run that verified nothing must not report the verdict of a run that verified everything.

Do not round UNCERTAIN up to CONFIRMED. This does not conflict with §1: §1 requires the *recommendation* to commit to a direction, while an unresolved row stays unresolved. Committing to a direction and pretending a row was settled are different acts.
