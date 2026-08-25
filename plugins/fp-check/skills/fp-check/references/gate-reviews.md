# Gates and Verdicts

**This file is for whoever relays the result.** The gate *criteria* are spelled
out in the Stage 1 verdict prompt, in more detail than a table can carry, and
`decideVerdict` is what applies them — so the criteria are deliberately not
duplicated here. A second copy would drift, and the copy an agent reads would not
be the copy that decides.

## The six gates

| Gate | Passes when |
|------|-------------|
| 1 Process | every stage produced concrete evidence, not assertion |
| 2 Reachability | **attacker-controlled data reaches the sink through a path a real caller can drive**. On a finding whose root cause is anything but *internal* the first half is dropped and only the path is judged — 2.4b has already established that the value comes from outside, and it is priced there as a severity cap, so failing this gate on it would charge it twice |
| 3 Real Impact | RCE, privilege escalation or information disclosure — not operational robustness, and not a defence-in-depth failure behind intact primary controls |
| 4 PoC Validation | the attack path is demonstrated end to end |
| 5 Math Bounds | the algebra permits the vulnerable condition. `N/A` when it is not a bounds or arithmetic finding |
| 6 Environment | no compiler, runtime, OS or framework protection prevents exploitation **entirely**. Raising the bar is not preventing |

Gate 5 is the only one that may be `N/A`. Every other gate returning anything but
`PASS` or `FAIL` is treated as an incomplete review, not as a pass — the affirmative
value is read rather than inferred by exclusion.

**A FAIL does not mean the same thing on all six.** Gates 2, 3, 5 and 6 grade the
BUG: a FAIL there says there is no reachable path, no security consequence, no
algebra that permits the condition, or a protection that prevents exploitation
entirely. That is a refutation, and the finding is a false positive. Gates 1 and 4
grade the EVIDENCE — whether the stages above showed their work, and whether the
traced path has a gap in it — and neither says the bug is absent, so
`decideVerdict` returns NEEDS MORE INFO on them and names the gate. A refutation
wins where both kinds failed: "there is no reachable path" is an answer, and "the
stages asserted rather than showed" is a fact still to establish.

**Gate 2 is where most false positives die, and the wording is load-bearing.** A
proof of concept that calls the vulnerable function directly demonstrates attacker
control *of the sink*; that is not control of any reachable entry point. Measured:
on a case whose sink is genuinely injectable but unreachable, every no-plugin run
wrote exactly that PoC, exfiltrated seeded credentials, and reported a confirmed
SQL injection — while the guard at the entry point rejected the payload outright.
Six of six runs across both arms *named* the blocking guard; one of six reached the
right verdict. Naming the blocker is not the same as concluding.

## Verdicts

Three, not two. The workflow returns a finer-grained status; these are what to
report to a human. **SKILL.md's Verdicts table is the authoritative status →
verdict mapping** and is not repeated here — in particular Stage 3's
`DO_NOT_SUBMIT` covers two outcomes and only one of them is a FALSE POSITIVE.
What follows is the shape to report once you have the verdict.

| Verdict | Reached when | Report as |
|---|---|---|
| **TRUE POSITIVE** | all six gates pass, with a stated reason, **and** nothing was left unresolved or deferred — an `unresolvedUncertainty` or a carried `blockingProofs` entry returns NEEDS MORE INFO on six passes | `BUG #N TRUE POSITIVE — <description>`, with the severity |
| **FALSE POSITIVE** | a gate that grades the bug fails — Reachability, Real Impact, Math Bounds or Environment — a layer stops the payload, or it is by design | `BUG #N FALSE POSITIVE — <the reason, verbatim>` |
| **NEEDS MORE INFO** | the review ran and the evidence does not decide, which includes a Process or PoC Validation FAIL — those report the analysis incomplete, not the finding disproven | `BUG #N NEEDS MORE INFO — <the missing fact>` |

`ALREADY_FIXED` and `DUPLICATE` are reported as retractions with their reference,
and `OUT_OF_SCOPE` as an answer about scope rather than a judgement on the bug.

**NEEDS MORE INFO is not a hedge, and rounding it to FALSE POSITIVE is the most
expensive mistake available here.** "The claim as stated is unproven" is not "no
vulnerability exists". Conflating the two killed a real, demonstrable finding in
this plugin's own history: the impact agent performed exactly the severity
downgrade it had been asked for, then graded the *original claim* as unverified,
and the run reported a working bug as not exploitable — scoring the case below the
arm that had no plugin at all.

Relay the `reason` the workflow returned, verbatim. It names the layer, clause,
gate or commit that decided the outcome, and that specificity is the deliverable.

## Example

```
BUG #3 FALSE POSITIVE — Integer underflow in packet_handler.c:142
  Gate 5 (Math Bounds) FAIL: validation at line 98 ensures packet_size >= 16,
  making (packet_size - header_size) >= 8. Underflow is mathematically impossible.
```
