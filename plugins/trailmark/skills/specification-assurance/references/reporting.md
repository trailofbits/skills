# Records and reporting

## Run artifacts

Create a unique directory under `.trailmark/specification-assurance/runs/`. Record
the target revision and dirty state, effective source roots/exclusions, pinned
specifications with hashes, installed tool versions/origins, and the actual commands
and exit statuses. Preserve baseline and final Duvet JSON/HTML/logs and snapshot
diffs, graph source policy/diagnostics and focused queries, native test/proof logs,
and a record for every requirement from `requirements.py inventory`.

Keep external specifications and evidence in the target run or another deliberately
configured root. The checker resolves source/log paths within `--root` and rejects
missing files and paths escaping that root. Copy external logs into the run; do not
point evidence at an unrelated or stale file. Retain copied source evidence outside
Duvet and Trailmark source discovery.

The inventory's IDs hash the specification identifier, section, normative level,
and whitespace-normalized quotation, so adding citations does not change identity.
Changing or dropping an obligation between baseline and final reports invalidates
the run. Start a new explicitly scoped assessment when the specification changes.
Supply every requested document with repeated `--specification` arguments to
`inventory`, and retain the same list in the validation request. Each document must
extract at least one obligation. If extraction misses obligations, register them explicitly
before proceeding; another document's successful extraction cannot cover the gap.
`inventory` accepts `--root` so specification paths resolve against the target
even when the calling session runs from another directory. For `inventory`, omitting
`--root` preserves the current-directory default.

Retain the native Trailmark export as `graph.json`, its `source_policy()` result as
`source-policy.json`, and its `parse_diagnostics()` result as `diagnostics.json`.
Write `graph-scope.json` with a `production_files` array of target-relative or absolute
production paths, for example `{"production_files": ["src/packet.py"]}`. Tests and
models stay in the native graph's total inspected-file count; keep them out of this
production list. The workflow retains its length in the validation request.
The finalizer checks both counts against the inspected paths in the native source
policy and requires parsed source nodes or matching parse diagnostics for each
production file. It rejects missing artifacts, zero inspected files, duplicate paths,
and inconsistent scope.
Production enforcement locations for `supported` requirements must belong to this
validated scope; a graph of unrelated files cannot support the assessment.
Any retained parse diagnostics force a global gap, even when the listed production
locations have parsed nodes.

## Ledger contract

`ledger.json` has `requirements` and `limitations` arrays. Each requirement record
contains `id`, `verdict`, a nonempty `rationale`, `implementation` locations, `checks`,
and an `assumptions` array (empty when none). Copy IDs from the inventory. Preserve
all obligations, including optional, waived, unimplemented, and unchecked ones.

In workflow runs, `requirements/<id>.json` is the immutable assessment from that
worker. Copy the complete record into the ledger: preserve its verdict, rationale,
assumptions, findings, and all native checks, including failures. Reporting cannot
replace a failed check with another passing one or change the applicability decision.
If evidence needs reassessment, retain the gap and start a new assessment.

Prime Duvet's generated requirement files with an isolated `baseline` first. Run
`requirements.py begin --root <target> --run <run>` before collecting the assessed
baseline or building a fresh graph; reuse no earlier engine or graph. Repeat the
isolated baseline, retain its inventory, build/export the graph, then run
`requirements.py freeze --root <target> --run <run>`. Freeze rejects changes since
begin and binds the original inputs to the analysis artifacts. Start a new run when
inputs change during analysis. Both capture files refuse overwrites.

`source-snapshot.json` binds file names, SHA-256 hashes, link destinations, and the
permission modes and owner/group IDs of files and directories. It covers the target
tree, including ignored/untracked inputs, and the retained graph/inventory artifacts. It excludes
the run, `.trailmark/`, Duvet reports/citation sidecars, Git metadata, Python bytecode
caches, and pytest caches. Keep production/build inputs out of these artifact roots;
put generated build outputs elsewhere and new assurance tests/logs inside the run.
Every inspected graph file must have a source snapshot binding; freeze and finalization
reject graphs that rely on files omitted from the snapshot.
Internal file links bind their destinations and contents. Internal directory links
bind their destinations without repeating traversal. External links retain only the
link text already present in the checkout: their targets are not read or traversed.
They produce an explicit coverage gap; retain local copies of dependencies that need
assessment. Unreadable directories invalidate capture. Graph and worker evidence
still require files inside the target.
Duvet configuration must also resolve inside the target; external configuration
links are rejected before their contents can be read or copied into the run.
The finalizer rejects added, removed, or modified files before and after Duvet.

Immediately after executing checks, run:

```bash
uv run --no-project "{baseDir}/scripts/requirements.py" seal \
  --root <target> --run <run> --record <run>/requirements/<id>.json
```

The helper reads `source-snapshot.sha256`, a small digest file written by freeze,
and binds it as `snapshot_sha256`; each worker avoids reading the full manifest.
It adds a `files` map of SHA-256 hashes, permission modes, owner/group IDs, and link
destinations for enforcement/check locations, executed logs, and additional dependency inputs
listed in `inputs`. Shared project hashes stay
in one manifest instead of being copied into every record and ledger entry. Retain
distinct logs for each execution; overwriting a passing log invalidates its record.
Keep sealed source unchanged and add new citations only in configured sidecars.
If sources change, reassess affected requirements rather than updating their hashes.

The helper returns the exact record's SHA-256 digest. The workflow retains it in
`validation_request.assessments`; failed workers have no digest. Rewriting both the
worker and ledger fails this original binding. Changing referenced file contents
fails the file bindings. The ledger must match each completed worker exactly.

Example record before sealing for `spec.md#length`, quoting
"A packet MUST contain at most 16 bytes.":

```json
{
  "id": "106a9a86e59d9600eb8f",
  "verdict": "supported",
  "rationale": "accepted() accepts 16 bytes and rejects 17; the test asserts both sides of the specified bound.",
  "implementation": [
    {"file": "src/packet.py", "line": 3, "role": "production"}
  ],
  "checks": [
    {
      "kind": "test",
      "scope": "implementation",
      "property": "test_length_boundary: accepts 16 bytes and rejects 17",
      "location": {"file": "tests/test_packet.py", "line": 6},
      "command": "uv run --with pytest pytest -q tests/test_packet.py",
      "result": "pass",
      "exit_code": 0,
      "log": ".trailmark/specification-assurance/runs/length-test.log"
    }
  ],
  "assumptions": ["The production request path calls accepted() before changing state."]
}
```

That final assumption needs caller evidence before claiming request-level rejection
or state preservation. The length requirement does not establish the separate
rejection requirement. For a stateful receiver, assert the error **and** the unchanged
counter/root/storage after rejection. A success-status-only test is insufficient.

Implementation locations have role `production` or `model`. Checks have kind
`test` or `formal`, scope `implementation` or `model`, and result `pass`, `fail`,
`unknown`, or `not_run`. Every check names its exact property, command, and source
location. Executed checks retain a nonempty log; passing checks require exit code
0 and a genuinely successful native per-property result. Skipped tests, admitted
proofs, timeouts, and inconclusive queries cannot be `pass`.

A formal check with implementation scope also needs a nonempty `binding` describing
the concrete production definitions/build artifacts governed by that result. A
separate unbound protocol model stays scope `model`, even when its proof passes.
Record compiler, solver, attacker-model, extraction, and external-code assumptions.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `supported` | Source inspection supports every sub-obligation, with complete Duvet implementation traceability, production enforcement, and at least one executed passing implementation check. State the limits of the evidence. |
| `partial` | Some conditions, paths, or sub-obligations hold; others do not or lack adequate evidence. |
| `violated` | Observed behavior or source logic contradicts the requirement. Preserve a counterexample when available. |
| `missing` | No enforcement was found; record searched roots, symbols/patterns, and plausible alternate enforcement sites in the rationale or linked evidence. |
| `unknown` | Ambiguity, unsupported syntax, opaque dependencies, stale evidence, or unavailable tooling prevents judgment. |
| `not_applicable` | A specific profile/condition makes this obligation inapplicable; cite that condition or an existing authorized waiver. It stays in the denominator. |
| `not_checked` | The obligation was inventoried but not assessed, including worker failures or a resource limit. |

Every `partial`, `violated`, or `missing` record must include `severity` as
`critical`, `high`, `medium`, `low`, or `info`, and a nonempty `consequence` describing
the concrete effect. Map a project's rubric to these levels and retain its original
label in an optional `project_severity` field. Report all severities. For example:

```json
{"verdict": "violated", "severity": "medium", "consequence": "Rejected packets increment the counter, allowing invalid input to consume the receiver's sequence space."}
```

These fields extend a complete requirement record; they do not replace its rationale,
locations, checks, or assumptions. `unknown` and `not_checked` retain their reason
without inventing a confirmed divergence or severity.
Preserve unapproved deviations as findings, not `not_applicable` records. A recommended
behavior without a justified deviation remains a gap. Optional features still carry
their conditional requirements when enabled.

`limitations` holds global gaps such as unsupported formal sources, uninspected
dependencies, unbound models, incomplete source coverage, or a test suite that
could not execute. Requirement-specific assumptions belong in that record. Do not
hide unresolved enforcement behind an assumption to get a `supported` verdict.

## Report and gate

Write `report.md` with the scope/revisions, full requirement counts, per-requirement
matrix, severity-tagged divergences and counterexamples, native test/proof outcomes,
and the paths to artifacts and proposed fixes. Separate:

- Duvet citations, test annotations, implications, exceptions, and TODOs;
- semantic implementation judgments and executed behavioral evidence;
- native formal results, their assumptions, and implementation bindings;
- global limitations and obligations not assessed.

The workflow returns `pending_validation`, never an assurance verdict. The calling
session writes the returned `validation_request` verbatim to `validation_request_path`
using its file-writing tool, then executes `validation_command` and observes its exit
and JSON output. Do not ask the reporting worker to reconstruct this request or embed
the inventory in a shell argument. The `finalize` command reads the baseline, inventory, report, ledger,
and successful workers' records. It compares the original requirement IDs, enforces
each failed worker's own `not_checked` verdict, reconciles completed workers with
the ledger, validates graph artifacts and counts, and preserves setup limitations.
Both `baseline` and `finalize` copy Duvet configuration to isolate report writes.
Finalization rejects invalid ledgers before running Duvet. Report paths, including
the candidate snapshot, point into a fresh `gate-native-*` directory. After Duvet,
the helper checks the ledger and sealed contents again.
A failure cannot reuse an old report or alter the project's accepted snapshot.
The gate links JSON, HTML, log, snapshot, and graph artifacts and records the native
exit code and source counts. Add these links to the report. Review a candidate
snapshot before intentionally adopting it.
Failed native attempts also retain artifact paths, logs, and `execution.json`;
`duvet_exit_code` is null when the process could not start.

Without a workflow runtime, prepare the same validation request from the retained
setup and worker outputs: `schema_version` 1, absolute `root` and `run`, original
`specifications` and requirement IDs in `requirements`, `failed_requirements`,
`assessments` mapping completed IDs to their original record digests, setup
`limitations`, and `production_source_files`. Run `finalize` for every assessment;
existing reports alone cannot validate the current source tree.
Retain `gate.json` even on a nonzero exit.
Exit 1 (`gaps`) is a useful completed assessment with unresolved obligations; exit
2 (`invalid`) means the artifacts cannot support even that accounting. Do not
describe either as compliant. An entirely inapplicable inventory cannot establish
implementation assurance and is invalid. A `supported` gate only means the records satisfy
the stated evidence contract; the helper cannot validate their semantic truth.

Snapshot matching, line coverage, mutation score, and the number of proved lemmas
are separate measurements. None is a conformance percentage. Do not promise that
`duvet report --ci` will fail on old gaps already accepted into its snapshot.
