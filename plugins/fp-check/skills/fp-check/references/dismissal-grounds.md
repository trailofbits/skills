# Dismissal grounds: when a reported finding is not a finding

**Guidance, not gates.** Nothing in this file ends an analysis on its own. These
are the recurring reasons a report turns out not to be a vulnerability, written so
that whoever is holding the evidence — the impact agent, the six-gate review, or
you at Step 0 — can recognise the shape and say so with the trace in hand.

Adapted from William Woodruff,
["Brocards for vulnerability triage"](https://blog.yossarian.net/2026/04/11/Brocards-for-vulnerability-triage)
(2026). The plugin `vulnerability-triage-brocards` carries the full worked
examples and edge cases.

## Why these are guidance now, and were gates before 2.0.0

They used to be four agents dispatched before any data-flow work, each able to end
the stage. That was measured over 65 runs and it went wrong in three distinct ways,
which is why the fan-out is gone rather than merely reordered:

1. **Cheap and first beat correct and later.** A dismissal decided 12 of 63 runs,
   while `upstreamFixStands`, `capSeverity`, `missingPrecondition` and
   `decideVerdict` fired zero times between them. Three of the seven eval cases
   exist to exercise exactly those four. The pre-gate was not answering better than
   the specialised gates; it was answering *sooner*.
2. **A question the code cannot answer is not a neutral question.** Asked "is the
   upstream service inside the same trust boundary?" about a repository containing
   only the client, the test returned NEEDS_MORE_INFO — correctly — and that
   unresolved question then propagated into three failed gates and a FALSE
   POSITIVE. The finding was real, and the verdict was about the missing context
   rather than about the finding.
3. **Judging the shape of a claim is not judging the claim.** Every one of these
   grounds is better answered with the trace in hand. There is no version of "does
   the documentation warn about this?" that is more reliable when asked by an agent
   that has not read the code than by one that has.

The content was always right. Only its position was wrong.

## The grounds

### The attacker already holds what the exploit would give them

If the capabilities the attack *requires* equal or exceed the impact it *grants*,
the finding is redundant. An active MITM who can already inject arbitrary responses
does not need your parsing bug.

Two traps in the other direction:

- **A privilege-escalation chain does not fail this.** Limited access exploited
  into elevated access is valid — the post-exploit capability exceeds the
  pre-exploit one.
- **"The attacker can do X" is not "the attacker can do X in this context."** Code
  execution inside a sandbox is not code execution with the sandbox's privileges.

**Where this lands in practice:** usually not as a dismissal at all. "The attack
needs the upstream service to misbehave" is an *external precondition* — an
`integration` root cause, stated explicitly, severity capped at Medium. That is
checkpoint 2.4b, and it is a live finding reported accurately, not a dead one.

### It is a correct implementation of a specification

If the spec requires or permits the behaviour, the vulnerability is in the
standard, not this code. Say which standard.

**The nuance inverts the test, so check it first.** An implementation that
*voluntarily* claims a stricter posture than the spec requires is vulnerable when
that strictness fails. A library documented as TLS 1.3-only that silently falls
back to a 1.2 CBC suite has broken its own promise, and the spec permitting 1.2 is
no defence. Read what the code claims about itself.

### The project's own documentation describes and warns against it

Dismiss the report *against this project* when the documentation carries the
security implication or the usage caveat.

**This is a redirection, not a dismissal.** Downstream usage that violates
documented guidance is a valid finding **against the downstream project**. The
answer is "not a bug *here*", not "not a bug" — say which project it is a bug in,
or the report is quietly lost.

Where the target is a library, what settles it is whether real, popular consumers
exhibit the unsafe pattern. **Stage 2 answers that** in its downstream-consumer
census: it derives the client-side pattern from the public reachability findings,
searches the dependents graph and the code indexes, and keeps only confirmed
occurrences with a link to the exact line.

Two things to know about that answer. The census only runs when severity turns on
downstream usage — an `integration` or `external` root cause, a `hardening_gap`, or
a sink no in-repo caller drives — because for a bug exploitable in the target
itself it answers a question nobody asked; the skip is reported, not silent. And
**a census that confirmed nothing is not proof that no consumer is affected.** It
bounds what was searched, which is why its `coverage` is required.

**If the document that would settle this is not in the repository, that is not an
open question — it is out of reach.** A governing spec, an upstream service
contract and a downstream consumer's guidance all sit outside a question about what
*this* project documents. Note which document you would need and carry on; the
online stage exists for exactly that.

### The cure is worse than the disease

Weigh severity in practice, the cost and disruption of the fix, and the blast
radius of the remediation across the dependency graph.

Nothing else in this skill evaluates remediation cost, so this is the only place a
"technically real, not worth the ecosystem breakage" finding gets an honest
hearing. **It is more often a severity input than a dismissal:** a finding whose
only safe fix is a breaking API change is usually reported at a lower severity with
the trade-off stated.

### The report is neither necessary nor sufficient

A CVE ID or a formal report does not prove a vulnerability exists, and the absence
of one does not prove safety. Strip the CVE number and the CVSS score: does the
technical description alone justify action?

### The report cannot state a threat model

**This one is still enforced in code**, and it is the only one that is — because it
is a fact about the dispatch rather than a judgement about the finding. A report
that cannot say who the attacker is, what capability they already hold, how they
trigger it and what breaks is unanalysable, and `missingArgs` rejects it before an
agent is spent. Refusing an unusable input is not dismissing a finding.

---

## Rationalizations to reject, in both directions

Both adversarial lists in
[false-positive-patterns.md](false-positive-patterns.md) end with questions asked
*for* the finding — 5 against and 2 for on the standard route, 11 against and 2 for
on the deep one. A triage tool that guards one direction drifts toward it, so the
dismissal-side guards below carry equal weight.

### Wrongly dismissing a valid finding

- *"It's only reachable in debug mode."* Verify debug mode is truly never enabled
  in production. Plenty of deployments ship with debug flags on.
- *"The attacker would need local access."* Local access is a realistic threat
  model for most containerised services.
- *"Nobody uses that API."* Confirm with usage data, not assumption — integration
  tests, deployment configs, downstream dependents.
- *"The spec allows it."* Check whether the implementation claims stricter
  behaviour than the spec requires.
- *"The claim as stated is unproven."* That is a smaller verified impact, or a
  named missing fact. It is not "no impact exists".
- *"The trigger comes from outside this repository."* That is an external
  precondition to state and a severity to cap, not a reason the bug is imaginary.

### Wrongly accepting an invalid finding

- *"It has a CVE, so it must be real."* Necessary-nor-sufficient exists for this.
- *"The CVSS score is high."* CVSS is a formula, not a verdict.
- *"Better safe than sorry."* The fix cost is part of the judgement.
- *"We can't prove it's NOT exploitable."* The burden is on the report to
  establish a threat model.
- *"Other projects patched it."* Other projects have different usage patterns.
- *"We should include it to pad the report."* A dismissed finding with documented
  reasoning is worth more in a deliverable than a false positive.
