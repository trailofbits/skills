---
name: specification-assurance
description: "Checks implementation conformance to specifications using Duvet requirements traceability and Trailmark code graphs, connecting requirements to enforcement, executable tests, and formal verification evidence. Use when setting up Duvet, auditing RFC or protocol compliance, finding unimplemented requirements, or checking whether proved models describe the shipped implementation."
allowed-tools: Read Grep Glob Bash Edit Write Workflow Task
---

# Specification Assurance

Build a reviewable chain from an authoritative requirement to production code and
evidence about its behavior. Install and run **Duvet** for traceability and
**Trailmark** for source relationships. A citation is a claim of coverage. Read the
enforcement and the assertions or proof obligations before treating it as evidence
of conformance.

## Quick Start

Identify the implementation root and the authoritative specification revisions
from the request or repository. If none can be identified, ask which specification
governs the implementation. Do not derive the requirements from the implementation
being assessed.

Use `/trailmark:specification-assurance-run` with a JSON object:

```json
{
  "target": ".",
  "specifications": ["spec/protocol.md"],
  "skill_dir": "{baseDir}"
}
```

The workflow prepares setup, assessments, annotations, and reporting. Pass
`skill_dir` from this loaded skill; direct invocations can resolve installed plugin
caches. It returns `pending_validation`, `validation_request`, its destination
`validation_request_path`, and `validation_command`. Use the calling session's file
writer to save that request verbatim, then execute the command and retain its exit
status and JSON output. Keep the request independent of the reporting worker.
The finalizer reads the artifacts and runs Duvet itself. A workflow agent's claimed
gate cannot establish an assurance result. Add the resulting gate and native-report
links to `report.md`, preserving any errors or gaps. Continue through this handoff
before reporting completion. On hosts without dynamic workflows, execute the same
work directly using the contracts here and the three references below.

Pass local specification paths. Download remote specifications first, retain their
original URLs/revisions and full text, and configure Duvet against those local copies.
The source snapshot then binds definitions and conditions outside extracted quotations.

Read [Duvet setup and annotation](references/duvet.md) before configuring the target.
Read [graph and formal evidence](references/formal-evidence.md) when building the
graph or using a proof/model. Read [records and reporting](references/reporting.md)
when writing the ledger.

## Required Tool Use

- Reuse working project tooling. Otherwise install Duvet with
  `cargo install duvet --locked` and Trailmark with `uv tool install trailmark`.
  A Rust toolchain is a Duvet build dependency even when the target uses another
  language. Record installation failures as setup failures, with the actual error.
- Python imports need their own environment: use
  `uv run --with trailmark python -` for graph queries. A CLI tool install does not
  make the package importable in arbitrary Python environments.
- Inspect `duvet init --help` and `duvet report --help`. Preserve existing
  `.duvet/config.toml`, requirement files, exceptions, and snapshots; merge missing
  entries. Configure both production and test roots, plus formal sources when
  present. Exclude generated reports, copied source evidence, and fixture strings
  that would create false citations.
- Use `requirements.py baseline --root <target> --run <run> --output <run>/baseline.json`
  before adding citations. It isolates all report/snapshot writes inside the run.
  Retain its JSON/logs and create the complete
  requirement inventory with the bundled helper. Run Duvet again after annotation.
  Use its HTML and snapshot artifacts for review. Do not claim that a successful
  `report` invocation or unchanged snapshot establishes complete coverage.
- Build and query a Trailmark graph of the actual implementation. Preserve source
  policy, inspected-file counts, parse diagnostics, unresolved edges, and source
  locations. Unsupported formal files remain explicit gaps; they must not disappear
  because `--language auto` omitted them.

## What Counts as Evidence

Keep applicability, semantic judgment, and evidence strength distinct. A MUST is
an obligation; SHOULD needs a justified deviation; MAY describes optional behavior
whose selected branch may carry further obligations. Conditional requirements
retain their antecedents. Split compound requirements into explicit obligations
in the assessment without dropping any part of Duvet's original quotation.

Use the graph to locate the enforcement, callers, alternative entrypoints, state
updates, tests, and specification/proof references. Then inspect the source at those
locations. Names, comments, graph reachability, and matching output types do not
establish the required behavior. Check rejection paths and observable side effects
as well as successful results.

Existing tests count when their assertions exercise the requirement on the assessed
revision. Record the command, actual result, property/assertion location, and log.
Use boundary and negative cases, known-answer vectors, integration tests, property
tests, fuzzing, or targeted mutation tests where they address an identified gap.
A round trip can let two wrong functions agree; independent known answers catch
different failures. A no-crash fuzz target does not test a protocol invariant.
A surviving mutant may be equivalent or outside the threat model; explain it rather
than optimizing a percentage. These techniques supply evidence, not universal proof.

Run existing relevant tests and proof commands. Add focused assurance tests when
needed within the requested scope. Preserve native failures, timeouts, unchecked
obligations, and unavailable tools. Do not change production behavior, weaken a
specification, or add a waiver to turn the report green. Report proposed fixes
separately unless implementation repair was requested.

A formal result needs a native verifier run and an explicit implementation binding.
An abstract protocol proof supports the design under its assumptions; it does not
establish that a separate implementation refines the model. The formal reference
describes language/version gates, native obligations, and this binding.

## Deliverables

Keep a unique run under `.trailmark/specification-assurance/runs/` with specification
revisions/hashes, target revision and dirty state, tool identities, graph evidence,
baseline/final Duvet JSON and logs, native test/proof logs, requirement records,
`ledger.json`, `gate.json`, and `report.md`. Keep durable Duvet configuration and
citations in `.duvet/assurance-citations/`. Existing source annotations stay in place.

The report lists requirements as `supported`, `partial`, `violated`, `missing`,
`unknown`, `not_applicable`, or `not_checked`, with severity for every divergence.
Show the full denominator and separate annotation coverage, executed checks, formal
results, model-to-code gaps, and exclusions. `supported` means supported by the
recorded evidence under stated assumptions, not certified correct.

The helper's `inventory` command extracts Duvet's requirements. Repeat
`--specification` for every requested document; omitted documents and documents
extracting zero obligations fail. Every assessment ends with the native finalizer:

```bash
uv run --no-project "{baseDir}/scripts/requirements.py" inventory \
  --root <target> --specification spec/protocol.md \
  --report <run>/duvet-before.json --output <run>/inventory.json

uv run --no-project "{baseDir}/scripts/requirements.py" finalize \
  --request <run>/validation-request.json --output <run>/gate.json
```

After graph/inventory setup, run `requirements.py freeze --root <target> --run <run>`
once. It records the full file list and contents in `source-snapshot.json`, including
untracked and ignored files. Keep generated build outputs outside the frozen tree;
put new assurance tests/logs inside the run. After native checks, seal each record with
`requirements.py seal --root <target> --run <run> --record <run>/requirements/<id>.json`.
Workers bind the shared snapshot digest and their own source/check/log contents.
Include additional dependency inputs in `inputs`. Use distinct logs and keep sealed
files unchanged; new citations go in the configured sidecars.

For workflow runs, save the returned request and execute `finalize`.
The request retains the original inventory, failures, setup limits, source
count, and worker digests without growing the shell command. The finalizer checks
the ledger against immutable workers and graph evidence before running Duvet. Parse
diagnostics force a gap. It checks evidence again afterward and retains each native
attempt, including a candidate snapshot, under `gate-native-*`; the project snapshot
stays unchanged. It writes `gate.json` even on failure. Link its JSON, HTML, log,
and snapshot artifacts. Use `--duvet /path/to/duvet` if needed.

Exit 0 means complete records supporting the scoped obligations, exit 1 means
recorded gaps, and exit 2 means invalid/missing artifacts or setup failure. The
checker validates records and local evidence artifacts; it cannot judge the
semantics of assertions, proof statements, or the analyst's reasoning.

## Rationalizations to Reject

| Rationalization | Why it fails |
| --- | --- |
| "Every MUST has a citation, so it is implemented" | Duvet matches text, including stale or misplaced comments. Inspect enforcement and assertions. |
| "The proof passed, so the service complies" | A proof about a model needs a refinement, extraction, or other justified binding to the deployed code. |
| "The parser found the theorem, so it is proved" | Trailmark extracts source structure; only the native tool checks obligations. |
| "Tests passed, so this requirement is tested" | Tests may skip, assert only a success code, or never execute the relevant path. Retain the exact assertion and execution evidence. |
| "That file was not detected, so it is out of scope" | Detection depends on installed parsers and source policy. Inventory formal files independently and retain omissions. |
| "An exception or implication fixes the gap" | Those annotations change accounting. Require a justified applicability decision or an actual construction-level guarantee. |
| "The report is green after narrowing the globs" | Changing the denominator hides obligations. Keep baseline identities and explain exclusions. |
