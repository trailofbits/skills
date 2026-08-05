---
name: spec-to-code-compliance
description: Check code against the documentation that specifies it - which requirements hold, which the code contradicts, which are absent, and what the code does that no document mentions. Use when comparing an implementation against a whitepaper, protocol spec, or design document.
allowed-tools: Workflow Task Read Grep Glob
---

# Spec-to-Code Compliance

Two artifacts disagree, and the job is to find where. The documentation says what the system does; the code
decides what it actually does. Every gap between them is either a bug or a documentation fix, and which one it
is is the finding.

## When to Use

You have both documentation describing intended behavior and the code that should implement it. A whitepaper
against a protocol, a design note against a service, a README's stated guarantees against the functions behind
them.

Most useful when the document is authoritative — something a client wrote, published, or is audited against —
because then a divergence is a defect rather than stale prose.

## When NOT to Use

Not for code with no documentation of intended behavior. There is nothing to check against, and a requirement
inferred from the code is checked against itself. Build the system model first with `audit-context-building`.

Not for finding bugs in general. This finds one class: where the code and the document disagree. A bug both
artifacts are silent about is out of scope, and a bug the document endorses is a finding against the document.

Not for writing or improving documentation, though it produces the list of what needs fixing.

## Do not check requirements in this context

Run `/spec-to-code-compliance:spec-compliance <path>`. The slash command takes a path; to name the
specification directly or widen the fan-out, ask for the run with those values — "run spec-compliance on
./contracts against SPEC.md, checking 20 requirements" — and they reach the script as `{path, spec, limit}`.
Typing the object literally after the slash command does not work; it arrives as a string and becomes the path.

It finds the documents, splits them into individually checkable requirements, gives each requirement its own
agent to hunt the code with, has independent agents try to refute every divergence before it is reported, and
writes `spec-compliance/REPORT.md` plus one file per requirement under `spec-compliance/requirements/`. Only
compact records come back here.

For a single requirement, dispatch the `spec-to-code-compliance:spec-compliance-checker` agent at it.

This is not a preference about where output lands. The check does not fit in one context window if it is done
honestly: judging one requirement means reading the enforcement, its callees, and its callers, and doing that
for thirty requirements means holding thirty call chains at once. Attempted inline, the first few get a real
check and the rest get a plausible one — and the transcript looks the same either way, because a verdict resting
on a promising function name reads exactly like one resting on having read the function. Per requirement, in its
own context, is what makes that difference visible.

Two properties come from the script rather than from instructions, and cannot be had here:

- **A refutation the finding's author did not perform.** Claude favors findings it produced when asked to check
  them. The workflow sends each divergence to agents that did not produce it — one reading the code again, one
  re-reading the document — and drops what either knocks down.
- **Records that cannot be prose.** A subagent bound to a return schema has to name the lines it read and the
  searches it ran. An `absent` verdict arrives with the patterns tried and their results attached, which is the
  only thing separating a real absence from a search that stopped early.

Measured on the `routes-not-inline` eval: with this plugin installed the work is dispatched every run, without
it never — Δ +1.00. Deleting this section while leaving the workflow in place changes nothing, because the
workflow is a real command that gets found and dispatched on its own. Read that as the mechanism carrying the
behavior rather than this text: the section is here so a human knows what runs and why, not because the routing
depends on it.

## What comes back, and how to read it

Every requirement gets one of six verdicts: `implemented`, `partial`, `contradicted`, `stronger-than-spec`,
`absent`, or `undecidable`. The interesting ones are the middle four.

- **`partial`** is usually the most serious thing in the report. The requirement holds on the paths anyone would
  test and fails on one nobody did, which is how it survived long enough to be found.
- **`absent`** rests entirely on its `searched` record. Read it. Enforcement often lives somewhere the search
  did not go — a modifier, a base class, a caller that checks first.
- **`undecidable`**, and any `documentProblem`, are findings about the documentation. A requirement too vague to
  check is one the client cannot hold anyone to.
- **`stronger-than-spec`** is an undocumented constraint. It works today, and nothing tells the next person
  changing that code that anything depended on it.

The report also carries the reverse direction — behavior the code has that no document mentions — which the
per-requirement pass cannot find by construction, since it is driven by the documents.

Read `notChecked`, `unverified`, and `unreadableDocuments` before treating the report as complete. Requirements
below the fan-out cut were never checked, and a divergence whose refutation agents both failed is unverified
rather than confirmed.

## Judgment the workflow does not make for you

Severity is consequence, not distance from the text: [DIVERGENCE_RUBRIC.md](resources/DIVERGENCE_RUBRIC.md). A
rounding step that bleeds a pool outranks a MUST satisfied by different means than the document describes, and
documentation drift with no behavioral consequence is a docs ticket.

The verdict is not the finding. `absent` on a mandatory requirement is a finding; `absent` on a sentence
describing a roadmap item is not. Deciding which is which is what this skill is for, and the workflow hands you
the evidence to decide it with.

## The target does not have to be a contract

The question is the same everywhere — what does this requirement demand, where would it be enforced, is it
enforced on every path — but what counts as a specification and where enforcement hides both change.
[DOMAIN_NOTES.md](resources/DOMAIN_NOTES.md) maps that across contracts, C and C++, services, and decompiled
firmware, and covers the case where the specification is an RFC or a standard rather than a project document.
Read it when the target is not a contract, and when scoping a check against a large standard.

## Reference

- [ANALYSIS_FORMAT.md](resources/ANALYSIS_FORMAT.md) — the on-disk format for a per-requirement analysis. Read
  when extending this plugin or judging whether a record is trustworthy.
- [WORKED_EXAMPLE.md](resources/WORKED_EXAMPLE.md) — three requirements chased to a verdict, one per verdict
  that is easy to get wrong: arithmetic that satisfies a requirement it does not resemble, an absence whose
  searches are the finding, and enforcement present on every path but the one nobody tested.
- [DOMAIN_NOTES.md](resources/DOMAIN_NOTES.md) — per-domain mapping of specifications and enforcement.
- [DIVERGENCE_RUBRIC.md](resources/DIVERGENCE_RUBRIC.md) — severity, and the two directions of a gap.
