# Anti-patterns

Common failure modes that destroy the adversarial value of this skill. Each has a diagnosis and a fix.

## 1. False symmetry

**Symptom:** The verdict says "both sides have merit" and splits the difference. No clear winner. Vague recommendation like "consider both approaches."

**Why it happens:** Reluctance to pick a side. Treating the adversarial structure as performative rather than decisional.

**Fix:** Pick a winner. The dimensions in the verdict table each have one winner, not a tie. If truly 3/3 split across dimensions, the winner is whichever dimensions matter most for the caller's actual decision — name those dimensions explicitly in the recommendation.

## 2. Hedged agents

**Symptom:** Agent returns things like "I see merits on both sides," "this is a nuanced question," "both approaches have tradeoffs." No strong adversarial position.

**Why it happens:** Weak prompt. The agent defaulted to balanced reasoning because nothing stopped it.

**Fix:** Re-dispatch with a stronger prompt. See [prompt-templates.md](prompt-templates.md#re-dispatching-on-hedged-agents). The key phrase: "Do not acknowledge merit in the opposing position. Do not hedge." Do not accept a hedged response as valid output.

## 3. Shared context leakage

**Symptom:** Advocate mentions the skeptic's arguments (or vice versa), softening the tone to accommodate. Arguments collapse toward agreement.

**Why it happens:** Prompt mentioned the other agent's existence or previewed their arguments.

**Fix:** Each prompt must be written as if that agent is the ONLY agent you've asked. Do not mention the other side. Do not say "another agent will argue X." Do not give hints about counter-arguments. The synthesis happens separately after both return.

## 4. Unfalsifiable claim

**Symptom:** The skeptic can't argue against the claim because it's too vague or too broad.

**Why it happens:** Claim wasn't stated precisely in Step 1.

**Fix:** Return to Step 1. Rewrite the claim as a specific, falsifiable sentence. "YARPGen is good" is unfalsifiable. "YARPGen will catch more Rosetta 2 semantic bugs than grammar-aware mutation in 7 days of fuzzing" is falsifiable.

## 5. Missing evidence

**Symptom:** Agents make claims but don't cite specific files, line numbers, CVEs, benchmarks. Arguments are plausible but unverifiable.

**Why it happens:** Prompt didn't require citations.

**Fix:** Every prompt includes: "Cite specific files, line numbers, facts, CVEs, benchmarks where possible." Reject outputs that make unsupported claims on critical dimensions.

## 6. Wrong mode

**Symptom:** Trying to prove a bug is real with "what do you think is best" prompts, or trying to pick between approaches with proof-style null hypotheses.

**Fix:** Reread [SKILL.md](../SKILL.md) Step 2. Decision mode = approach/design choice. Proof mode = bug/finding/security claim verification. Pick the right one.

## 7. Synthesis dump

**Symptom:** Presenting both agents' full outputs as the result. No verdict table. No recommendation.

**Why it happens:** Skipping the synthesis step.

**Fix:** The verdict table is the product, not the raw arguments. Always produce the table + recommendation. Only dump raw agent outputs if the user explicitly asks for them.

## 8. Confirmation bias in prompt

**Symptom:** Advocate wins trivially because the prompt was stacked in its favor. The skeptic has nothing to work with.

**Why it happens:** Caller's preferred answer leaks into the prompt framing.

**Fix:** Both prompts should frame the claim neutrally. "Make the case FOR/AGAINST {CLAIM}" not "Make the case FOR the obviously correct {CLAIM}". Both agents get the SAME background. If the advocate gets more context than the skeptic, the test is rigged.

## 9. Too many dimensions

**Symptom:** Verdict table has 15 rows. Each row is shallow. Recommendation is unclear because so many points survived/fell.

**Fix:** Pick 3-5 dimensions. The dimensions should be the ones that actually determine the decision. Cut dimensions that don't move the verdict either way.

## 10. Ignoring UNCERTAIN

**Symptom:** Proof-mode verdict marks every null as REFUTED/PROVED when some were actually UNCERTAIN. Finding is reported as CONFIRMED when one null is still plausible.

**Fix:** UNCERTAIN is a valid outcome. If P4 ("input unreachable") has evidence on both sides, the finding is NOT confirmed. Either:
- Gather more evidence on that specific P before concluding, OR
- Report the finding WITH the caveat that P4 is uncertain

Do not round UNCERTAIN up to CONFIRMED.
