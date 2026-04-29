# Proof Mode

Use for bug findings, security claims, and any assertion of the form "X is real" or "X exists" or "X is a vulnerability."

## When to pick proof mode

- "This crash is a real bug, not a false positive"
- "This is exploitable"
- "This vulnerability affects version N"
- "This finding is valid"
- "This behavior is a bug, not by design"

If the claim is "X is the best approach," use [decision-mode.md](decision-mode.md) instead.

## The structure: N null hypotheses

Proof mode works by enumerating the **null hypotheses** — every way the finding could be wrong. The skeptic tries to prove each null; the advocate tries to refute each. If all null hypotheses fail to be proved, the finding is CONFIRMED.

Default set of 5 null hypotheses for security findings:

| # | Null hypothesis | What proves it |
|---|----------------|----------------|
| P1 | This is normal error handling, not a crash | Exit code matches spec; stderr shows intentional rejection |
| P2 | This is a harness artifact | Doesn't reproduce in a clean environment (different shell, fresh binary) |
| P3 | This is a benign assertion | SIGABRT in validation code with no exploitability path |
| P4 | The input is unreachable by a real attacker | Requires privileged access or an artificial construction |
| P5 | Already fixed in a newer version | Crash doesn't reproduce on current release |

Adapt the set to the claim. For non-security claims you might use different P values — e.g., for a performance regression claim: P1 = measurement noise, P2 = cold cache, P3 = unrelated background load, etc.

## How advocate and skeptic interact in proof mode

Both agents get the SAME list of null hypotheses. They argue the SAME Ps from opposite sides:

**Advocate (defends the finding):**
- For each P, produces evidence REFUTING the null
- Reproduces in clean env (refutes P2)
- Shows crash is in register allocator, not validation (refutes P3)
- Shows a real compiler can emit the triggering input (refutes P4)

**Skeptic (attacks the finding):**
- For each P, produces evidence FOR the null
- Cites similar crashes that were dismissed as config issues (attacks P2)
- Cites Apple's stance on similar bugs (attacks P3)
- Shows the input requires a non-standard construction (attacks P4)

## Verdict rule for proof mode

| All Ps REFUTED by advocate, NOT PROVED by skeptic | **CONFIRMED** — the finding is real |
| Any P clearly PROVED by skeptic | **DISMISSED** — the finding is a false positive |
| Any P in dispute (both sides plausible) | **UNCERTAIN** — gather more evidence for that specific P before committing |

## Structured output

Verdict table columns differ from decision mode:

| Null hypothesis | Skeptic says | Advocate says | Outcome |
|----------------|--------------|---------------|---------|
| P1: normal rejection | Exit codes match rejection pattern | Exit is SIGABRT -6, not rejection (-302) | REFUTED |
| P2: harness artifact | Setup script may interfere | Reproduces with clean `env -i` and direct binary call | REFUTED |
| P3: benign assertion | Assertion is in `check_bounds` | Assertion is in `AllocTempGPRByIndex`, not bounds check | REFUTED |
| P4: unreachable input | Input requires crafted OOB memory ref | Real compilers emit RIP-relative addressing to any offset | REFUTED |
| P5: already fixed | Untested on newer versions | Tested on current macOS, reproduces | REFUTED |

**Final verdict:** CONFIRMED — all 5 null hypotheses refuted with reproducible evidence.

## Common mistakes in proof mode

1. **Vague nulls** — "this might not be real" is not a falsifiable null. Nulls must be specific and testable.
2. **Shifting the burden** — advocate must provide REFUTATIONS, not just "this is clearly real." Each P requires specific evidence.
3. **Missing Ps** — if the skeptic raises a null not in your list, add it. The Ps are the structure of the proof, not a fixed ritual.
4. **Treating UNCERTAIN as CONFIRMED** — if P4 is in dispute, the finding is NOT confirmed. Either close out P4 with more evidence or report the finding with that specific caveat.
