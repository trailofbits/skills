# fp-check

Verify whether a suspected security bug is real, and say why — with the gates
enforced in workflow code rather than self-reported by the agent applying them.

## Overview

Three stages in a fixed order, behind two questions asked once up front.

| Stage | When | What it does |
|---|---|---|
| **1 Static** | always | one agent per validation layer → recovery → already-fixed search → impact and severity → adversarial pass → the six gates |
| **2 Online** | on request | the project's published policy, how the bug is reached in the published project, bounty scope, and one agent per named venue searching for past reports and duplicates. Fails closed when offline |
| **3 PoC** | on request | build the exploit against the real code in an isolated worktree, execute it, then five agents that did not build it try to reject it |

More than one finding at a time goes through **Stage 0, `triage-batch`**, which
derives the shared context once, runs Stage 1 per finding with it, accounts for
every finding by id, and then checks the pairs that are only exploitable
together — the one place in the plugin that sees a second finding.

Every finding gets **TRUE POSITIVE**, **FALSE POSITIVE**, or **NEEDS MORE INFO**.
The third means the analysis could not settle the question — not that the finding
was refuted, which is what FALSE POSITIVE means.

A few terms used throughout:

- **layer** — a validation check that exists between the entry point and the
  vulnerable operation: an authorization check, an allowlist, a bounds check.
  Stage 1 spends one agent on each.
- **sink** — the vulnerable operation itself. **Entry point** — where attacker
  data gets in.
- **root cause** — where the bad value originates: `internal` (this code),
  `integration` (a component this code trusts), or `external` (outside the
  deployment). It decides the severity cap.

## The six gates

Stage 1 ends by putting the finding through six gates. **All six must pass before
anything is called a TRUE POSITIVE**, and the decision is arithmetic over their
values, not a judgement call:

| Gate | Passes when |
|---|---|
| **1 Process** | every stage produced concrete evidence rather than assertion |
| **2 Reachability** | attacker-controlled data reaches the sink by a path a real caller can drive |
| **3 Real Impact** | the harm is RCE, privilege escalation or information disclosure — not reduced robustness, and not a defence-in-depth gap behind intact primary controls |
| **4 PoC Validation** | the attack path is demonstrated end to end |
| **5 Math Bounds** | the arithmetic permits the vulnerable condition. `N/A` when it is not a bounds or arithmetic finding — the only gate that may be N/A |
| **6 Environment** | no compiler, runtime, OS or framework protection prevents exploitation **entirely**. Raising the bar is not preventing |

**Gate 2 is where most false positives die.** A proof of concept that calls the
vulnerable function directly proves attacker control *of the sink*, which is not
control of any entry point a real caller can reach — the single most common way a
reported bug turns out not to be one.

Six passes are necessary but not sufficient: anything left unresolved returns
NEEDS MORE INFO instead, so a payload showing six passes may still not be a
TRUE POSITIVE.

## Installation

```
/plugin install fp-check
```

## Triggers

- "Is this bug real?" / "Is this a true positive?" / "Is this a false positive?"
- "Verify this finding" / "Check if this is exploitable"
- "Is this already fixed?" / "Is this in scope for their bounty?"
- Filtering findings out of a scanner or an agentic discovery run

It does **not** activate for bug hunting ("find bugs", "audit this code").

## What is enforced in code

This is the point of the workflow port. Each rule below was once prose that an
agent was asked to honour; each is now a pure function whose answer the
orchestrator cannot argue with:

| Rule | Enforced by |
|---|---|
| At least one validation layer is inspected — an empty list dispatched zero agents and fell through to a verdict | `missingArgs`, `decideGate` |
| Recovery was *checked*, not assumed absent | `decideGate(!recovery)` |
| An integration or external root cause states the precondition it needs | `missingPrecondition` |
| A fix that exists upstream retracts the finding, and has to cite a commit | `upstreamFixStands`, `alreadyFixedStands` |
| An integration/external root cause, or a hardening gap, caps at Medium | `capSeverity`, `severityCapViolation` |
| All six gates pass before anything is called a TRUE POSITIVE | `decideVerdict` |
| Only a TRUE POSITIVE justifies building an exploit | `verification.status` in Stage 3 |
| A PoC is built, executed and lint-clean, then re-checked by someone else | `isAcceptableBuild`, `artifactProblem` |
| A challenge with no verdict counts *for* the challenge | `tallyChallenges`, `confidenceBand` |
| No scope or severity claim is made from memory when offline | `offlineProblem` |
| Out-of-scope needs a quoted policy clause; "probably" is `unclear` | `scopeHalt` |
| Destructive PoC operations only at safety levels 1–2 | `missingArgs` in Stage 3 |
| Every finding in a batch is accounted for by id — one whose Stage 1 returned nothing, or returned `BLOCKED` without reaching a verdict, is reported as unverified, never silently dropped | `accountFindings` |
| Two findings are only paired for a chain check when one's blocking reason could supply what the other lacks | `pairReason`, `isChainable` |
| A chain is only reported when the agent names both contributions and the mechanism connecting them | `chainProblem` |
| A confirmed chain is a verdict of its own, and neither finding it names is left reportable as a false positive | the chain row's `status`, `chainedInto` |

## Components

```
workflows/
  triage-batch.js      Stage 0, for more than one finding
  triage-static.js     Stage 1, always
  triage-online.js     Stage 2, on request
  triage-poc.js        Stage 3, on request
skills/fp-check/
  SKILL.md             routing, the two questions, the dispatch contract
  references/          the criteria, the dismissal grounds, the lookup tables
  scripts/poc-lint.sh  the PoC quality gate
tests/                 four layers; see tests/README.md
evals/                 9 cases in three tagged suites, each run with and without
                       the plugin. Only the 7 `static` cases have been measured
```

### Reference files

| File | Purpose |
|------|---------|
| [checkpoints.md](skills/fp-check/references/checkpoints.md) | The pass criteria for every checkpoint, and the crosswalk from stages to checkpoints to the six gates |
| [dismissal-grounds.md](skills/fp-check/references/dismissal-grounds.md) | Why a report may not be a finding, and the guards against wrongly dismissing a valid one |
| [gate-reviews.md](skills/fp-check/references/gate-reviews.md) | The six gates and the verdict format |
| [false-positive-patterns.md](skills/fp-check/references/false-positive-patterns.md) | The 13-item checklist and the four red-flag lists |
| [bug-class-verification.md](skills/fp-check/references/bug-class-verification.md) | What each bug class specifically has to establish |
| [recovery-mechanisms.md](skills/fp-check/references/recovery-mechanisms.md) | What each runtime does on a panic, and the checklist before claiming a crash |
| [validation-dimensions.md](skills/fp-check/references/validation-dimensions.md) | Scope, security model, and design-intent judgement calls |
| [evidence-templates.md](skills/fp-check/references/evidence-templates.md) | Data flow, algebraic bounds proofs, attacker control, devil's advocate |
| [poc-anti-patterns.md](skills/fp-check/references/poc-anti-patterns.md) | PoC construction rules, enforced by `scripts/poc-lint.sh` |
| [test-integration.md](skills/fp-check/references/test-integration.md) | Framework patterns for a test-integrated PoC |
| [safety-guidelines.md](skills/fp-check/references/safety-guidelines.md) | The five safety envelope levels, from read-only analysis up to running an exploit against a live target |

## Routing

Stage 1 picks its own route from the dispatch. **Standard is the default, and it
is doing real work** — the cheaper path matched the full one on every test case,
so do not reach for `deep` to feel thorough.

**Deep** adds three proofs — API contracts and environmental protections, the
algebraic bounds proof, and race feasibility — and runs the full 13
devil's-advocate questions instead of the 7-question spot check. It fires
automatically on 3+ validation layers, on a memory-safety, arithmetic,
concurrency or availability bug class (the Route column of
[bug-class-verification.md](skills/fp-check/references/bug-class-verification.md)
is the authoritative list, and the tests pin `selectRoute` against it), and on an
explicitly cross-component or ambiguous claim.

## Testing

```bash
make check                                       # what CI runs
bash plugins/fp-check/tests/mutation-gate.sh     # not in CI; run it by hand
```

The mutation gate breaks each covered behaviour in a sandbox copy and requires
the suite to go red. Anything that survives is testing the model, not the plugin.

`tests/README.md` is the file to read before changing anything here. It records
every dead end this plugin has been down — including four paid eval sweeps that
were invalid, each of which produced a plausible-looking number.
