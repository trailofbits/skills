# Synthesis Template

After both agents return, the caller produces the synthesis. This is where the adversarial value is extracted. Raw dumps of both sides are not the product — the verdict table is the product.

## The verdict table

### For decision mode

| Dimension | Advocate position | Skeptic position | Verdict |
|-----------|-------------------|------------------|---------|
| {dim 1} | {advocate claim} | {skeptic claim} | **Survives / Weakens / Falls** |
| {dim 2} | ... | ... | ... |

### For proof mode

| Null hypothesis | Skeptic proof attempt | Advocate refutation | Outcome |
|----------------|----------------------|--------------------|---------|
| P1: {null} | {skeptic evidence} | {advocate evidence} | **PROVED / REFUTED / UNCERTAIN** |
| P2: ... | ... | ... | ... |

## Verdict values

- **Survives** (or **REFUTED** in proof mode) — the side whose point held up. The counter-argument did not land.
- **Weakens** — partial rebuttal; position needs qualification
- **Falls** (or **PROVED** in proof mode) — the side whose point was cleanly defeated
- **UNCERTAIN** (proof mode only) — both sides made plausible cases; more evidence needed

## The recommendation paragraph

After the table, write ONE paragraph (3-5 sentences) that:

1. States the overall winner
2. Lists the 2-3 opposing points that survived (these become qualifications, caveats, or follow-ups)
3. Specifies what the caller should actually do next

**Template:**

> {Winner position} wins on {main dimensions}. However, {opposing side}'s points about {surviving objection 1} and {surviving objection 2} are valid and must be addressed. Recommended action: {specific next step}.

## Worked examples

### Example 1 — decision mode (YARPGen claim)

Claim: "YARPGen is the best primary strategy for finding Rosetta 2 semantic bugs."

| Dimension | Advocate | Skeptic | Verdict |
|-----------|----------|---------|---------|
| End-to-end execution | Tests entire pipeline including translation | Current fuzzer can't execute — true gap | Advocate wins |
| FP / SIMD coverage | Will exercise via auto-vectorization | YARPGen has no FP support; auto-vec rarely triggers | **Skeptic wins** |
| Oracle quality | Native ARM64 compile = ground truth | Clang can miscompile; can't disambiguate without Intel HW | **Skeptic wins** |
| Known-bug coverage | Would catch Bug 2.2, 2.3 | 0 of 6 known Rosetta bug classes reachable | **Skeptic wins** |
| Setup effort | 1 day, 50-line script | True | Advocate wins |
| FP rate estimate | ~1 per 10k programs genuine | 80-95% will be compiler bugs | **Skeptic wins** |

Recommendation: **Skeptic wins.** YARPGen is a weak PRIMARY strategy because it cannot reach the instruction classes where Rosetta bugs actually live (FP, SIMD, implicit registers) and has a fatal oracle problem at -O2. However, the advocate's point about low setup effort is real. Use YARPGen as a CHEAP COMPLEMENT running in the background, not as the primary direction. Primary direction should be Track 2 + Track 3 (fix current fuzzer, add ARM64 execution harness).

### Example 2 — proof mode (FINDING-001)

Claim: "FINDING-001 (pcmpestrm register allocator abort) is a real translation bug."

| Null | Skeptic | Advocate | Outcome |
|------|---------|----------|---------|
| P1: normal rejection | Exit codes in rejection range | Exit is SIGABRT -6, not rejection (-302) | **REFUTED** |
| P2: harness artifact | Test setup may interfere | Reproduces under `env -i` with fresh binary | **REFUTED** |
| P3: benign assertion | All aborts are assertions | Abort is in `AllocTempGPRByIndex` register allocator, not validation | **REFUTED** |
| P4: unreachable input | Requires crafted OOB memory | Real compilers emit RIP-relative addressing; any OOB offset is reachable | **REFUTED** |
| P5: already fixed | Untested on newer | Reproduces on macOS 26.4 (current) | **REFUTED** |

Recommendation: **CONFIRMED.** All 5 null hypotheses refuted with reproducible evidence. The crash is a real translation-path register allocator exhaustion in `libRosettaAot.dylib`. Severity: Low-Medium (local DoS, controlled SIGABRT, not memory corruption). Report as finding; do not pursue as critical vuln.

## When the verdict is mixed

Sometimes the skeptic wins some dimensions and the advocate wins others. That's not a failure — it's the most common outcome. The recommendation should:

- Pick the overall winner by weighing the most important dimensions for the caller's actual decision
- List surviving opposing points as required qualifications or follow-up work
- Not split the difference into "do neither" — pick a direction and note the caveats

## When to re-run

Re-dispatch one or both agents if:
- An agent returned a balanced / hedged response
- An agent didn't address a critical dimension
- Both agents agreed on something you think is wrong
- A key piece of evidence wasn't considered

Re-run with a tighter prompt. See [prompt-templates.md](prompt-templates.md#re-dispatching-on-hedged-agents).
