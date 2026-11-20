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
Supply every requested document with repeated `--specification` arguments to the
inventory and gate commands. Each configured document must extract at least one
obligation. If extraction misses a document's obligations, register them explicitly
before proceeding; another document's successful extraction cannot cover the gap.

## Ledger contract

`ledger.json` has `requirements` and `limitations` arrays. Each requirement record
contains `id`, `verdict`, a nonempty `rationale`, `implementation` locations, `checks`,
and an `assumptions` array (empty when none). Copy IDs from the inventory. Preserve
all obligations, including optional, waived, unimplemented, and unchecked ones.

Example record for `spec.md#length`, quoting
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
session executes its `validation_command` and observes the process exit and JSON
output. The `finalize` command reads the actual baseline, inventory, report, ledger,
and successful workers' records. It compares the original requirement IDs, enforces
each failed worker's own `not_checked` verdict, and preserves setup limitations.
It runs Duvet itself, retaining a fresh `gate-native-*` directory with JSON, HTML,
log, and `execution.json`. A failed or no-op command cannot reuse an older report.
The gate names the final native report/log and records the observed Duvet exit code.
Update the report's artifact links and retain any snapshot diff after this command.

For direct assessments, the helper's `check` command gates existing baseline/final
reports; capture the Duvet process exit separately. Retain `gate.json` even on a nonzero exit.
Exit 1 (`gaps`) is a useful completed assessment with unresolved obligations; exit
2 (`invalid`) means the artifacts cannot support even that accounting. Do not
describe either as compliant. An entirely inapplicable inventory cannot establish
implementation assurance and is invalid. A `supported` gate only means the records satisfy
the stated evidence contract; the helper cannot validate their semantic truth.

Snapshot matching, line coverage, mutation score, and the number of proved lemmas
are separate measurements. None is a conformance percentage. Do not promise that
`duvet report --ci` will fail on old gaps already accepted into its snapshot.
