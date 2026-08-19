# Proof Mode

Use for any assertion of the form "X is real" or "X exists" — a crash that reproduces, a performance regression, a behavioral claim about a system.

## When to pick proof mode

- "This crash reproduces, and it is in the component I think it is, not in my harness"
- "This performance regression is real, not measurement noise"
- "This behavior is a bug, not by design"
- "This finding is valid" — where validity means the observation itself holds up

**Not for false-positive verification of a security finding.** "Is this vulnerability real?" and "is this exploitable?" belong to `fp-check`, which does the data-flow tracing and exploitability analysis this skill does not. The five-nulls structure below produces the same CONFIRMED/DISMISSED shape as fp-check's TRUE POSITIVE / FALSE POSITIVE verdict, so running both on one finding is duplicated work with two ways to disagree. If the claim is about a vulnerability, stop here and use fp-check.

If the claim is "X is the best approach," return to [SKILL.md](../SKILL.md) Step 2 and pick Decision mode instead.

## The structure: N null hypotheses

Proof mode works by enumerating the **null hypotheses** — every way the finding could be wrong. The skeptic tries to prove each null; the advocate tries to refute each. The finding is CONFIRMED only when every null is affirmatively refuted with evidence — a null that merely went unproved is an open question, not a dead one.

Default set of 5 null hypotheses for a crash or fault finding:

| # | Null hypothesis | What proves it |
|---|----------------|----------------|
| P1 | This is normal error handling, not a crash | Exit code matches spec; stderr shows intentional rejection |
| P2 | This is a harness artifact | Doesn't reproduce in a clean environment (different shell, fresh binary) |
| P3 | This is a benign assertion | SIGABRT in validation code, on a path the program is designed to reject |
| P4 | The input is unreachable in practice | Requires an artificial construction no real caller produces |
| P5 | Already fixed in a newer version | Crash doesn't reproduce on current release |

Adapt the set to the claim. Other claim types need different P values — e.g., for a performance regression claim: P1 = measurement noise, P2 = cold cache, P3 = unrelated background load, etc.

## How advocate and skeptic interact in proof mode

Both agents get the SAME list of null hypotheses. They argue the SAME Ps from opposite sides.

The worked example below and in [Structured output](#structured-output) is one finding throughout: a differential fuzzer running x86-64 programs under Rosetta 2 (Apple's x86-to-ARM64 translator on macOS) hit a SIGABRT inside the translator itself. `AllocTempGPRByIndex` is a register-allocation routine in the translator; exit `-302` is Rosetta's own input-rejection code, which a signal death is not.

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

The verdict is the caller's, not either agent's. Each agent reports a label for every P — the advocate REFUTED or CANNOT REFUTE, the skeptic PROVED or CANNOT PROVE — but both were told to argue one side, so a label states the position that agent was *assigned*, not a finding of fact. Grade the evidence behind the label before you use it.

**Step 1 — grade every label.** A label counts only if the caller can check what backs it: a file:line, a reproducer that actually ran, a log excerpt, a version tested, a citation. An assertion ("clearly a real bug", "this is obviously benign") backs nothing. Downgrade an ungraded REFUTED to CANNOT REFUTE, and an ungraded PROVED to CANNOT PROVE, then apply the table below. This grading pass is why synthesis is a separate step and not a tally of the two `Verdict:` fields.

**Step 2 — resolve each P.** Exhaustive over the four state combinations the agents can return:

| Advocate on P | Skeptic on P | Outcome for that P |
|---------------|--------------|--------------------|
| REFUTED, evidence graded | CANNOT PROVE | **REFUTED** — the null is dead |
| REFUTED, evidence graded | PROVED, evidence graded | **UNCERTAIN** — both sides landed; the P is in dispute |
| CANNOT REFUTE | PROVED, evidence graded | **PROVED** — the null stands |
| CANNOT REFUTE | CANNOT PROVE | **UNCERTAIN** — neither side reached the question |

**Step 3 — combine into the finding's verdict.** First matching row wins, top to bottom: a proved null kills the finding regardless of what else is unresolved.

| Condition | Verdict |
|-----------|---------|
| Any P **PROVED** | **DISMISSED** — the finding is a false positive |
| Any P **UNCERTAIN** | **UNCERTAIN** — close out that specific P before committing |
| Every P **REFUTED** | **CONFIRMED** — the finding is real |

**CANNOT REFUTE on any P puts CONFIRMED out of reach.** The fourth row of step 2 is the one that matters most in practice: no reproducer, no source access, budget exhausted — neither agent ever reached the question. That is not a null the advocate killed, and it must never read as CONFIRMED. Absence of evidence against a finding is not evidence for it, so a run that verified nothing has to end in a different verdict from a run that verified everything. This is the rule that makes those two runs look different.

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
