# Detailed Checkpoint Reference

The pass criteria for every checkpoint. A failure is not advisory — but "halts
the pipeline" is only one of the three things the code does with one, and which
one is per checkpoint rather than a house rule:

- **Halts**, returning a status: a blocking layer, an UNCERTAIN layer, an
  out-of-scope or by-design threat model, a complete upstream fix, a missing
  external precondition.
- **Corrects**, and reports the correction: an over-rated severity at 1e.
- **Carries**, and blocks a TRUE POSITIVE at the verdict instead of ending the
  stage early: a deep-route proof that reports the finding impossible. A single
  auxiliary proof does not outrank the traced path, so it is answered by the six
  gates rather than allowed to end the stage.

## Which stage runs which checkpoint

Checkpoint numbers are the stable IDs the workflow scripts cite in their gate
code and their prompts, so they are kept rather than renumbered. This table is
the crosswalk between them, the stages in `SKILL.md`, and the six gates in
[gate-reviews.md](gate-reviews.md).

| Stage | Checkpoints | fp-check gate it feeds | Enforced in code by |
|---|---|---|---|
| 1a Intake | 1.1, 1.2, 1.3 | 1 Process | `missingArgs` |
| 1c Reachability | 2.1, 2.2 | 2 Reachability | `decideGate` |
| 1c Threat model | 3.1, 3.2, 3.3 | 2 Reachability, 3 Real Impact | `decideGate` (the `threat` verdict) |
| 1c Already-fixed | 5.1 challenge 4, on the cheap path | — | `upstreamFixStands`, `downgradeUnreferencedFix`, `decideGate` |
| 1c Deep route only | — | 5 Math Bounds, 6 Environment | the blocking-proof and dead-proof checks on `proofs` |
| 1d Recovery | 2.3 | 3 Real Impact | `decideGate(!recovery)` |
| 1e Impact + severity | 2.4, 2.4b, 2.5, 5.2 | 3 Real Impact | `missingPrecondition`, `capSeverity` |
| 1f Adversarial | the 13 questions | 6 Environment | — synthesis |
| 1g Verdict | all six gates | all | `decideVerdict` |
| 2 Online | 2.4b, 2.5, and see the online stage in `SKILL.md` | 2, 3 | `offlineProblem`, `scopeHalt`, `needsUserCensus`, `censusProblem`, `summaryProblem`, `capSeverity` |
| 3 PoC | 4.1, 4.2, 4.3, 5.1, 5.2, 6.1 | 4 PoC Validation | `isAcceptableBuild`, `artifactProblem`, `tallyChallenges`, `confidenceBand`, `alreadyFixedStands`, `reportProblem`, `severityCapViolation` |

`upstreamFixStands` and `alreadyFixedStands` are the same rule at two stages, and
they are two functions with two names: Stage 1 reads the history agent's
reference, Stage 3 reads challenge 4's verdict. Citing the Stage 3 name against
Stage 1 sends the reader looking for a function that is not in that script.

Stages 2 and 3 run only when the user asks for them. **Stage 1 alone must reach
a verdict**, which is why the already-fixed search sits in 1c as well as in
Stage 3's challenge 4: on the cheap path challenge 4 never runs.

This file is the **criteria**. The calibration material — the lookup tables, red
flags and worked examples used to reach a verdict — lives in its siblings and is
not duplicated here:

| For | Read |
|-----|------|
| 2.3 recovery behaviour by runtime | [recovery-mechanisms.md](recovery-mechanisms.md) |
| 2.4b, 2.5, 3.1, 3.3 judgment calls | [validation-dimensions.md](validation-dimensions.md) |
| Why a report may not be a finding, and the guards against wrongly dismissing | [dismissal-grounds.md](dismissal-grounds.md) |
| 1c, 1e, per bug class | [bug-class-verification.md](bug-class-verification.md) |
| 1f, the 13 questions and the red-flag list | [false-positive-patterns.md](false-positive-patterns.md) |
| 4.2 PoC construction rules | [poc-anti-patterns.md](poc-anti-patterns.md) |
| 4.1 test-integrated PoCs | [test-integration.md](test-integration.md) |

Placeholder, ellipsis, TODO and narration detection is `scripts/poc-lint.sh`'s
job, not a checklist item — but only for the **PoC file**. Nothing runs the linter
over the report, so checkpoint 6.1's "no placeholders, no TBD" is still yours to
check by reading it.

---

## Stage 1a: Intake (REQUIRED)

### Checkpoint 1.1: Evidence Collection

**DO NOT PROCEED without source code evidence.**

Record the exact file, line, function and commit/version, how the finding
arrived (source review, user report, scanner, or a hypothesis from
documentation), and the actual code.

**Pass criteria:**

- Exact `file:line` reference, or a publicly accessible code URL
- Actual code shown, not described or paraphrased
- Code accessible for analysis

**If it fails:** request source code access. Mark BLOCKED.

### Checkpoint 1.2: Classification

Name the primary category — input validation bypass, logic error, race
condition/TOCTOU, panic or exception leading to a crash, cryptographic flaw,
access control bypass, resource exhaustion/DoS, state inconsistency, memory
safety — and state in 2-3 sentences what the *code* does wrong.

**Pass criteria:**

- Clear root cause in code terms
- Category matches the root cause
- Not vague: "missing validation" is not a root cause until you say *of what*

**If it fails:** re-analyze until the root cause is clear.

### Checkpoint 1.3: Initial Impact Assessment

State the claimed impact — process crash, data theft, DoS, privilege escalation,
and so on. Checkpoint 2.4 verifies or downgrades it.

**Pass criteria:**

- The claim is specific, not "causes problems"

---

## Stages 1c-1e: Attack Path Verification (MANDATORY)

**THIS IS THE PRIMARY QUALITY GATE. DO NOT SKIP.**

**Historical failure rate:** 95% of false positives come from skipping this
phase.

### Checkpoint 2.1: Entry Point Identification

State how attacker-controlled data enters — the RPC/API call, transaction, P2P
message, HTTP endpoint, contract call, file upload — and name the exact entry
package, function and signature. Give a concrete example input, not "malicious
payload goes here".

**Pass criteria:**

- Specific entry point, not "user sends a transaction"
- The attacker can actually call it; it is not internal-only
- The example input is concrete

**If it fails:** find the actual entry point, or mark NOT_EXPLOITABLE.

### Checkpoint 2.2: Validation Layer Enumeration

#### ⚠️ THIS IS THE MOST CRITICAL CHECKPOINT

**Purpose:** verify the attack actually reaches the vulnerable code. Most false
positives fail here.

List **every** validation or check between the entry point and the vulnerable
code. For each, give its type (authorization, input sanitization, rate limiting,
type checking, bounds checking), its `file:line`, what it checks, and whether the
attacker payload passes — with the code as evidence. The three verdicts are the
layer schema's own, so use these words:

- **PAYLOAD_REACHES_SINK** — explain how the payload survives it
- **PAYLOAD_STOPPED_HERE** — this stops the attack; the finding is NOT_EXPLOITABLE
- **UNCERTAIN** — stop; the code must be traced before this can be answered

The verdict is about the **payload**, and the names say so because the short ones
did not. As `PASSES` / `BLOCKS` they read equally well as a property of the layer
and as a property of the finding, and a traced run returned `BLOCKS` with the
reason *"I labeled this BLOCKS meaning the payload is NOT blocked/validated"* —
the label inverted against its own evidence, the finding died before the impact
agent, and the severity cap never ran.

**Pass criteria:**

- At least 1 layer identified, **or none confirmed** — both halves are reachable.
  A layer must be a check that EXISTS, with a `file:line`. If nothing on the path
  validates the payload, that is `layers: []` plus `layersSearched` naming the
  files and functions read and what was not found; an empty list on its own is
  still rejected, because a forgotten field and a deliberate "nothing guards this
  path" are the same value. **Do not pass the absence of a check as a layer** — an
  agent asked whether a layer that does not exist stops the payload cannot answer
  coherently, and the contract used to demand exactly that
- For each layer, determined pass/fail with evidence
- ZERO "UNCERTAIN" layers — all verified
- If any blocks: mark NOT_EXPLOITABLE
- If all pass: document WHY, with code evidence

**What the code does with it:** a PAYLOAD_STOPPED_HERE verdict returns `NOT_EXPLOITABLE`, and
an UNCERTAIN one returns `NEEDS_MORE_INFO` — not the same thing, and not a bare
halt. BLOCKED is reserved for "this analysis could not be run": a contract
violation, or an agent that returned nothing. NEEDS_MORE_INFO means it ran and the
evidence does not decide, which is what an unresolved layer is: the code was read
and could not be traced. Reporting that as BLOCKED sends the reader to the harness
instead of to the code, and rounding it to FALSE POSITIVE loses real findings.

### Checkpoint 2.3: Recovery Mechanism Check

**⚠️ CRITICAL: many "crash" vulnerabilities are actually just errors.**

Determine whether a panic or exception at the vulnerable location is caught
anywhere in the call stack — language-level, framework middleware, or a server
built-in — and state the impact that actually survives.
[recovery-mechanisms.md](recovery-mechanisms.md) carries the per-runtime
defaults, the search primitive to grep for in each, and the checklist to clear
before claiming a process crash.

**Pass criteria:**

- Checked for recovery (not assumed absent)
- If recovery exists: impact updated from crash to error
- If claiming "process crash": proved recovery does not catch it

**If recovery exists and the claim was a process crash:** the claim is wrong as
stated, and the impact becomes whatever survives the recovery. That is usually
Low/Informational — error handling, not a crash. It is not always: a crash loop
under a restart policy, state that the restart does not restore, and a lost task
that was the only thing draining a queue all survive recovery as real findings.
[recovery-mechanisms.md](recovery-mechanisms.md) has the four shapes. Record the
surviving impact, not the fact that something caught it.

### Checkpoint 2.4: Impact Verification with Evidence

Verify each claimed impact against evidence, and grade it
**VERIFIED | NOT VERIFIED | DISPROVEN**.

**The grade is about whether an impact exists, not about whether the reported
one survived intact.** A real bug reported at inflated severity is **VERIFIED**,
carrying the impact the evidence actually supports — downgrading is the work
this checkpoint asks for, not a reason to fail it. Reserve NOT VERIFIED for
"no impact could be established either way", and DISPROVEN for "the evidence
shows there is no impact". Only VERIFIED continues to PoC development, so
grading a real-but-smaller impact as NOT VERIFIED throws away a genuine finding
— which is exactly what happened to a graded eval case before this paragraph
existed.

What counts as evidence depends on the class of impact claimed:

| Claimed impact | Evidence required |
|----------------|-------------------|
| Process/service crash | Panic or exception not caught by recovery; code on a critical execution path; no automatic restart; the crash reproduced |
| Denial of service | Resource exhaustion or infinite loop shown; the service becomes unresponsive; attack complexity is low; impact duration measured |
| Data theft / unauthorized access | The attacker gains access; the access-control bypass shown; sensitive data extracted; scope of exposure identified |
| Privilege escalation | A lower-privileged user gains higher privileges; the authorization check bypassed; elevated actions performed; persistence, where applicable |

**Pass criteria:**

- EVERY claimed impact has evidence
- No "would cause" or "might" — only "does cause", with proof
- If NOT VERIFIED, the claim is removed or marked hypothetical
- An impact smaller than the one claimed is still VERIFIED; record the smaller
  one and let checkpoint 5.2 apply the severity cap

**What the code does with it:** `DISPROVEN` returns `NOT_EXPLOITABLE` — positive
evidence of no impact, and the only grade that does. Everything else returns
`NEEDS_MORE_INFO`: `NOT_VERIFIED`, because the absence of evidence is not evidence
of absence, and treating the two alike is the conflation that killed a real finding;
and any answer outside the three, because a grade the code cannot read establishes
nothing in either direction. Neither branch "downgrades severity":
a smaller-but-real impact is `VERIFIED` carrying the smaller impact, and the cap
is applied afterwards by `capSeverity`.

### Checkpoint 2.4b: Root Cause Attribution

**Purpose:** distinguish a flaw in our code from a flaw we merely fail to defend
against. This changes both severity and remediation.

State the proximate cause (which line fails) and the root cause (why it fails),
then classify:

| Classification | Meaning | Severity consequence |
|----------------|---------|----------------------|
| **Internal** | Missing validation in our own code | Full exploitability, severity as claimed |
| **Integration** | Missing validation of data from an external source | Requires an external failure to trigger — **cap at Medium** |
| **External** | The flaw is in a dependency; our code lacks defense | Workaround only; report upstream and document — **cap at Medium**, as for Integration |

For Integration or External, answer: is defensive validation required by design
(with evidence), and should this be handled at the integration layer?

**Pass criteria:**

- Classification chosen with code evidence, not asserted
- If Integration/External, the required external precondition is stated
  explicitly

Only **Internal** exempts a finding from the cap, and it is the strong claim: the
trigger originates inside this repository. Anything else — including a
classification named in some other vocabulary — is priced as Integration/External
by `missingPrecondition` and `capSeverity`, which read one predicate between them
so the cap cannot be paid in the prompt and skipped in the arithmetic.

**If it fails:** trace the data to its origin before classifying.

### Checkpoint 2.5: Exploitability Classification

**Purpose:** separate an exploitable vulnerability from a missing hardening
feature. Both are valid findings; they are not the same finding and must not
carry the same severity.

**The test:**

1. Does the code DO something it should not? → **VULNERABILITY**
2. Does the code LACK something it should have? → **HARDENING GAP**

**Tie-breaker when unclear:** "can an external attacker exploit this without user
cooperation?" YES → vulnerability. NO → hardening gap.

**Severity consequence:** a vulnerability is high priority and directly
exploited; a hardening gap is medium priority, defense-in-depth.

**Pass criteria:**

- Classification is justified by the test above, not by how serious it feels
- A hardening gap is not written up as an exploited vulnerability

**If it fails:** reclassify and recalibrate severity before proceeding.

---

## Stage 1c: Threat Model Alignment

### Checkpoint 3.1: Scope Verification

Where a scope is defined — a security assessment, a disclosure program — decide
whether the vulnerability is in it: YES, NO (stop), or UNCERTAIN (clarify
first).

**Pass criteria:**

- Verified in-scope against an explicit statement
- Not in an excluded category
- Not already called out as known or accepted

### Checkpoint 3.2: Security Model Verification

Decide whether the finding violates a security property the target claims, or
sits within its stated trust assumptions. Three recurring shapes are usually out
of scope: "an admin can upgrade to malicious code" (centralization risk), an
exploit that requires governance compromise (trust assumption), and behaviour
the documentation states is trusted — cite where.

**Pass criteria:**

- This breaks a security property the target claims
- Not a feature working as intended

Where no documentation exists, proceed but note it.

### Checkpoint 3.3: Design Intent Classification

**Purpose:** privileged access is not a bug when it is intentional. Centralized
control is not by itself a vulnerability.

Check all three indicator classes and report how many fired:

1. **Explicit privilege indicators** — access control identifiers (`isAdmin`,
   `isSuperUser`, `requiresOwner`), function naming (`emergency*`, `override*`,
   `bypass*`, `force*`), or comments saying "intentional", "by design",
   "privileged"
2. **A symmetric pattern** — a guarded path and an unguarded sibling both exist,
   e.g. `withdraw()` requires approval and `emergencyWithdraw()` does not, which
   makes the unguarded sibling an intentional escape hatch rather than a bypass
3. **Documented as normal operation** — the README or architecture docs describe
   the behaviour, or tests cover it as expected

**If 2 or more fire:** search the codebase for usage patterns and check test
coverage. If confirmed intentional → mark NOT_VULNERABLE and STOP.

**Pass criteria:**

- All three indicator classes checked, not assumed absent
- If 2+ indicators fire, the confirmation search was actually performed
- The finding is not "an admin can do admin things"

**If it fails:** mark NOT_VULNERABLE. Do not write a PoC for intended behaviour.

---

## Stage 3: PoC Development (ONLY after Stage 1 returns TRUE_POSITIVE)

**A finding that did not clear all six gates does not get a PoC.** `triage-poc`
enforces it: `verification.status` must be `TRUE_POSITIVE`, and a failing Stage 1
return carries a populated `impact` and `severity` too, so forwarding one
verbatim would otherwise satisfy every other field.

### Checkpoint 4.1: PoC Type Selection

Choose the cheapest form that works, in this order:

1. **Test-integrated** — PREFERRED where a suite exists. Name the framework and
   the tests path. The test must fail while the vulnerability exists and pass
   once it is fixed. See [test-integration.md](test-integration.md).
2. **Standalone script** — name the language and whether it runs against local,
   testnet or a fork.
3. **Testnet demonstration** — record the testnet URL and the transaction hash.

**Pass criteria:**

- An appropriate type selected
- The necessary infrastructure is available

### Checkpoint 4.2: Code Implementation

[poc-anti-patterns.md](poc-anti-patterns.md) carries the construction rules and the
required-structure table. The one that invalidates everything else:

**Real code invocation.** The PoC imports and calls the actual code under test.
Never a copy-pasted or reimplemented vulnerable function. Mocks replace
dependencies only, NEVER the vulnerable component. If the PoC cannot call real
code, document why and get approval.

Beyond that, every PoC carries setup (dependencies and install/run commands), a
concrete payload with every parameter filled, an execution section that actually
calls the vulnerable path — not commented out, not a print statement describing
what would happen — a validation section that asserts on the outcome, and
cleanup where the run was destructive.

### Checkpoint 4.3: Execution and Validation

**REQUIRED: actually run the PoC.** Record the platform and architecture, the
target commit or version, the exact command, and the full output.

**Pass criteria:**

- The PoC actually executed
- The output demonstrates the vulnerability
- Reproducible

**If it fails:** debug until it works, or document why it cannot.

The second and third are graded by the artifact-check reviewer's `reRun`, not by
the builder, whose `executed` is a self-report in a script with no Bash. It has
three values because "debug until it works" and "document why it cannot" are two
different answers: `DID_NOT_REPRODUCE` is the first and ends the stage as
`BLOCKED`, `COULD_NOT_RUN_HERE` is the second and rides into the report's
`unproven`. As one boolean the two collapsed, so neither could be acted on and
neither was.

---

## Stage 3: Self-Critical Review (MANDATORY)

**THIS PHASE CANNOT BE SKIPPED.**

### Checkpoint 5.1: Devil's Advocate Analysis

**Assume you are a skeptical auditor reviewing this PoC. Your job is to REJECT
it if possible.** For each challenge below, state the strongest form of the
argument against the finding, then whether the evidence rebuts it. Uncertainty is
not a rebuttal.

| # | Challenge | The argument to make |
|---|-----------|----------------------|
| 1 | Reachable? | The attacker cannot reach the vulnerable code |
| 2 | Recoverable? | The impact is less than claimed, e.g. the panic is caught by defer/recover |
| 3 | By design? | This is intended behaviour, e.g. governance is trusted |
| 4 | Already fixed? | A fix already exists — search the issue tracker, `git log --grep`, and published advisories, and report what you searched |
| 5 | Real deployment? | It is not exploitable in practice — the path is unreachable in a default configuration, real deployments add protections in front of it, or the code path is never used |

**Challenge 4 is not scored like the others.** A fix that exists means the finding
is **RETRACTED** — `ALREADY_FIXED`, not a false positive and not a lowered
severity — and this outcome overrides the confidence band. It has to be cited,
and the citation has to be one: a challenge awarded with no commit, PR, issue or
advisory behind it — or with `n/a`, `see evidence`, a bare `file:line` — retracts
nothing and **ends the stage as `NEEDS_MORE_INFO`**, because a bug a reviewer
calls patched is not reported as live either. An incomplete or partial fix does
not retract at all: it is counted against the finding by the band like any other
challenge, and the report says the fix is partial.

**Confidence Level — this is the canonical scale for this skill.**

The ranges are disjoint, so every score carries exactly one label. Derived from
how many of the 5 challenges above were defeated by evidence; a challenge that
cannot be defeated with evidence counts as won by the challenge, not as a tie.

| Band | Range | Derivation | Action |
|------|-------|-----------|--------|
| HIGH | 90-100% | 5 of 5 challenges defeated | Proceed |
| MEDIUM | 50-89% | 3 or 4 defeated | Proceed only with uncertainties documented |
| LOW | 10-49% | 1 or 2 defeated | Do not submit; gather evidence or downgrade |
| NONE | 0-9% | 0 defeated | False positive, DO NOT SUBMIT |

The bands are the only gate. There is no separate percentage threshold: the
derivation is discrete (0-5 challenges), so 3 and 4 defeated both land in
MEDIUM and no run can produce a score that a 70% cut would separate. MEDIUM
means proceed **with the uncertainties documented**; LOW and NONE mean do not
submit.

Any other confidence scale appearing elsewhere in this skill's references is
superseded by this table.

**Pass criteria:**

- All 5 challenges completed honestly
- Evidence-based rebuttals, not speculation
- Confidence matches evidence quality

### Checkpoint 5.2: Severity Calibration

State the original severity and the severity after review, and where they differ,
why — "thought this was a process crash, but recovery makes it an error response
→ Medium, not High".

Justify it on both axes:

- **Impact** — direct loss (amount or TVL%), disruption (permanent, hours,
  minutes, none), who is affected (all, a subset, one) and how many, and the
  cost and time to recover
- **Exploitability** — complexity, privileges required, whether user interaction
  is needed, and attacker cost

**Pass criteria:**

- Severity matches industry standards (CVSS or equivalent)
- The rating is supported by evidence
- Not speculative or inflated

**The caps are arithmetic and are applied in code, not requested in a prompt** —
which is the difference the head-to-head measured: 3/3 against 0/3 on the case
built to test it. All three stages apply them, and the last one differently and
deliberately. Stage 1e `capSeverity` **corrects** an over-rated severity and
reports the correction, because there is no artifact to correct and the caller is
owed a verdict. Stage 2 carries its own copy of `capSeverity` for the same reason
and applies it to the severity the online summary returns — the census that feeds
that agent fires precisely on the capped root causes and its `severityEffect:
raise` invites the number back up. Stage 3 `severityCapViolation` **blocks**,
because by then the number has been written into a report file and correcting the
return value would leave that file wrong.

A rating that names no level, or names two, is **not capped at all** — there is no
number to bound, so none of the three guesses at one. Stage 1 stops at NEEDS MORE
INFO and names the fix, Stage 2 keeps the rating Stage 1 derived from the code, and
Stage 3 refuses the report. Reading a string nobody can parse as *below* the cap is
how an integration finding shipped as a true positive at `Sev-1` with 2.4b never
applied.

---

## Stage 3: Documentation

### Checkpoint 6.1: Report Completeness

Seven sections, all required:

| Section | Must contain |
|---------|--------------|
| Executive Summary | One paragraph, a clear impact statement, no hyperbole |
| Technical Details | Exact `file:line`, root cause, the attack path trace, the validation layers |
| Proof of Concept | Working executable code, setup instructions, execution output, the impact demonstrated |
| Attack Path Verification | Entry point, validation layers enumerated, recovery checked, impact evidenced |
| False Positive Analysis | The 5 challenges, the confidence assessment, the uncertainties |
| Remediation | A specific fix — NOT "add validation" — as a diff or pseudo-code, why it addresses the root cause, and any breaking changes |
| References | Program URL where applicable, target documentation, similar vulnerabilities, the source repository |

**Pass criteria:**

- All sections complete
- No placeholders (`$XXM`, `$XX`), no TODOs, no "TBD"

---

## Checkpoint Failure Protocol

The output form is in SKILL.md. The rule here is what counts as a failure, and
what the code returns for it:

| Failure | Response | Status returned |
|---------|----------|-----------------|
| Missing evidence — a contract violation, or an agent that returned nothing | Request the source, or fix the dispatch | `BLOCKED` |
| Uncertain validation layer | Code trace required before this can be answered | `NEEDS_MORE_INFO` |
| Recovery exists | The verified impact is the one that survives recovery, and it is what 1e records | continues on the surviving impact |
| A deep-route proof reports the finding impossible | Carried to the six gates, which answer it with the traced path in hand, and blocks a TRUE POSITIVE at the verdict | `NEEDS_MORE_INFO` at 1g |
| A Stage 3 challenge wins | Lowers the confidence band, and the band decides | `DO_NOT_SUBMIT` at LOW or NONE; MEDIUM proceeds with the challenge documented |
| A Stage 3 challenge agent returns no verdict | Still counts against the band as a win for the challenge, but a band nobody argued for is a missing fact, not a refutation | `NEEDS_MORE_INFO` naming the silent agents |
| Stage 3's challenge 4 wins on a **whole** fix, **with a citation** | Overrides the band outright: the bug was real and a fix landed | `ALREADY_FIXED`, a retraction carrying that citation |
| Stage 3's challenge 4 wins on a **whole** fix, **citing nothing** | A retraction has to point at something, and a bug a reviewer calls entirely patched is not reported as live either. Establish the reference | `NEEDS_MORE_INFO`, unless the artifact gate or a band of LOW/NONE has already answered the finding |
| Stage 3's challenge 4 wins on a **partial** fix, cited or not | The fix is incomplete, so the finding survives it either way, and only the retraction needed the citation — the same call Stage 1 makes, which downgrades an uncited fix claim and carries on | the band decides, and the report records the partial fix |
| Placeholder detected | Complete the code; `poc-lint.sh` must exit 0 | `BUILD_FAILED`, or `BLOCKED` at the reviewer's re-run |
| The reviewer's re-run runs and does not reproduce the impact | 4.3's "the output demonstrates the vulnerability", decided by the one reader who did not build it. Fix the PoC | `BLOCKED` at the artifact gate |
| The reviewer cannot run the PoC here at all — a missing service, a target that is not this host | A boundary rather than a result; it is recorded in the report's `unproven` section, and it must name what stopped it | the band decides, and the report records the boundary |

**`NOT_EXPLOITABLE` is a Stage 1 status only.** Stage 3 has no verdict of that
name: a challenge that stands there costs the finding one band step, and only a
band of LOW or NONE, with every challenge answered, returns `DO_NOT_SUBMIT` — the
status SKILL.md reads a refutation out of, which no agent that never ran has made.
A single standing challenge is not
terminal by itself — the same reason a single deep-route proof is carried rather
than allowed to end Stage 1, one row up.

Four rows above do not end the stage: "recovery exists", the blocking deep-route
proof, a standing Stage 3 challenge that leaves the band at MEDIUM, and a PoC the
reviewer had no environment to run. None of the four is a licence to proceed as
though the check had passed. The first replaces the claimed impact with the
surviving one; the second is carried in `blockingProofs` and denies a TRUE
POSITIVE in code; the third rides on `unrebutted` in the `REPORTED` return and the
report must address it; the fourth rides into the report prompt, which tells the
report agent that nobody but the builder has seen the PoC work and that this
belongs in `unproven`.

**There is no cheap pre-gate row any more.** Stage 1b dispatched four brocard
agents that could end the analysis on the shape of the claim alone; it was removed
before 2.0.0 after 65 measured runs, and its content is guidance in
[dismissal-grounds.md](dismissal-grounds.md) that the agents holding the traced
path apply. The reasoning is in that file.
