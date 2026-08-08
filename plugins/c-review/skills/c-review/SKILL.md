---
name: c-review
description: Performs comprehensive C/C++ security review for memory corruption, integer overflows, race conditions, and platform-specific vulnerabilities. Use when auditing native C/C++ applications, reviewing daemons or services for memory safety, or hunting integer overflow / use-after-free / race conditions in userspace code.
allowed-tools: Workflow AskUserQuestion Bash Read
---

# C/C++ Security Review

Collects four parameters, then hands the whole review to a workflow script. The
workflow owns concurrency, retries and result collection; this skill only resolves
inputs and returns the report.

## When to Use

Native C/C++ application security review: memory safety, integer overflow, races,
type confusion, Linux/macOS daemons, Windows userspace services.

## When NOT to Use

- Kernel drivers or modules (Linux, Windows, macOS).
- Managed languages (Java, C#, Python, Go, Rust).
- Embedded or bare-metal code with no libc.

---

## Phase 0 — Parameters

Parse any free text on the invocation line (`flamenco only`, `high severity only`,
`use haiku`) and pre-fill what it implies. Then make **one** `AskUserQuestion` call for
whatever is still unresolved. Never silently default a required parameter.

| Parameter | Values | Inferring it from the invocation |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | "remote", "network", "attacker" → `REMOTE`; "local", "unprivileged" → `LOCAL_UNPRIVILEGED`; otherwise ask |
| `worker_model` | `haiku` / `sonnet` / `opus` / `inherit` | An explicit model name. Otherwise ask. `inherit` uses the session model |
| `severity_filter` | `all` / `medium` / `high` | "all", "every", "noisy" → `all`; "medium and above" → `medium`; "high only" → `high`; otherwise ask |
| `scope_subpath` | repo-relative directory, optional | "X only", "just audit X/" → the matching subdirectory, fuzzy-matched against top-level dirs. Absent → `.`. Ambiguous → ask |

Two scopes stay separate for the whole run:

- **`finding_scope_root`** = `scope_subpath` (default `.`) — a finding must live inside it,
  and it is the tree the unit list is generated from.
- **`context_roots`** = `.` by default — read freely to establish callers, build flags and
  reachability. Set it to `finding_scope_root` only if the user explicitly forbids wider
  reading, and say that reachability confidence drops when you do.

## Phase 1 — Resolve paths

```bash
# Plugin root. Abort if it does not resolve rather than running with an empty path.
root="${CLAUDE_PLUGIN_ROOT:-}"
[ -n "$root" ] && [ -f "$root/workflows/c-review.js" ] && echo "$root"
# Fallback for a local checkout or a cache layout that does not set the variable:
find ~/.claude . -path '*/c-review/workflows/c-review.js' -print -quit 2>/dev/null
```

```bash
# Output directory. The workflow cannot call Date.now(), so the timestamp is made here.
output_dir="$(pwd)/.c-review-results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$output_dir"
echo "$output_dir"
```

`uv` must be on PATH: three of the phases run Python scripts through it, and the first
one — the unit enumerator — is what the whole review is partitioned from. If `uv` is
missing, say so and stop rather than running a review with no unit list.

## Phase 2 — Run the workflow

Invoking this skill **is** the opt-in to multi-agent orchestration — call `Workflow`
without asking again. A review of a real codebase also runs past any default workflow
size guideline; that guideline is advisory and this is the case it exempts. Do not shrink
the fan-out to fit it, and do not substitute hand-spawned `Agent` calls.

One `Workflow` call. `scriptPath` takes the absolute path resolved in Phase 1; `args`
must be a real JSON object, not a JSON-encoded string.

```
Workflow({
  scriptPath: "<plugin_root>/workflows/c-review.js",
  args: {
    outputDir:        "<output_dir>",
    pluginRoot:       "<plugin_root>",
    threatModel:      "REMOTE",
    severityFilter:   "all",
    findingScopeRoot: "expat/lib",
    contextRoots:     ".",
    workerModel:      "sonnet"
  }
})
```

Five further arguments are optional and default correctly; pass them only when the user
asks or when running an evaluation:

| Argument | Default | What it is for |
|---|---|---|
| `maxUnitLines` | `150` | Cap on a review unit. A larger function is split at syntactic seams. Raising it reintroduces the saturation the cap exists to prevent |
| `linesPerAgent` | `1500` | Source lines per review agent. Lower it to fan out wider at proportionally higher cost |
| `reviewAgents` | derived | Pins the review fan-out outright instead of deriving it from the line total (clamped 4–14) |
| `injectFindings` | absent | **Eval-only.** An array of finding objects appended before dedup. Anything passed here is reported as though a reviewer found it, so it must never be used in a real review |

The workflow validates its own arguments and throws with a named field if one is
missing. It runs five phases:

| Phase | Agents | What it does |
|---|---|---|
| Detect | 1 | Runs `enumerate_units.py` to generate the unit list; platform flags **from actual API usage**; the shared state structs; and, per bug class, whether the source has any candidate site at all |
| Review | 4–14 (7 on 9 KLOC) | One agent per contiguous slice of the unit list. Each returns findings **with severity** and a ledger row per (unit × question) |
| Sweep | 2 | The class axis. One agent over every bug class with no entry anywhere and a cited candidate site; one agent auditing the shared-state struct fields |
| Dedup | 0–1 | Only for collisions the assembler cannot merge deterministically. Usually skipped |
| Assemble | 1 | Runs `assemble_findings.py`: the ledger gate, the deterministic merges, `findings.json`, `REPORT.md` and `REPORT.sarif` |

**Around 11–12 agents on a mid-size target.** An earlier class-partitioned pipeline cost
three times that for no more recall.

**There is no false-positive review.** Severity is assigned by the reviewer that found the
bug and nothing rejects anything. The judge that used to do it rejected most of what it
rejected on threat-model scope; that is now handled by scoping the review prompt, and the
rest ships. Say so when you report — see Phase 3.

**Location is the partition, not bug class.** An undirected fan-out over contiguous line
ranges equalled the class-partitioned pipeline at a fraction of the cost, and the two axes
find *different* bugs. So the class catalogue survives as a bounded completeness sweep over
ground nothing covered, and location does the dividing. Do not restore a class-per-agent
fan-out; it was measured and it lost.

## Phase 3 — Return the report

`Read <output_dir>/REPORT.md` and return it. Then surface, prominently and separately
from the findings, anything in the workflow result that means the run was partial:

- `artifactsWritten: false` — `REPORT.md` and `REPORT.sarif` are missing. **The part
  files under `<output_dir>/parts/` are intact**, so re-run the assembler by hand rather
  than reconstructing anything: the exact command is in `artifactError`'s context, and
  the script is `<plugin_root>/scripts/assemble_findings.py --run-dir <output_dir>
  --threat-model ... --severity-filter ...`.
- `coverage` — `checksCompleted` / `checksRequired`. Report this number, not "functions
  reviewed": the previous design would have shown a 628-line function as fully covered
  in all four runs that found two or three of its four bugs. A non-zero `violations`
  means some reviewer claimed a verdict its own evidence did not support; that is a
  coverage-integrity failure and belongs next to the findings.
- `groupsFailed` / `agentFailures` — that ground was **not covered**. Do not let a clean
  report imply it was.
- **No false-positive review ran.** State this once, plainly, next to the findings:
  every severity is the reviewer's own and nothing independent rejected anything.
  `judgeRan` is always `false` in this configuration. On measured runs an FP judge
  rejected about a third of candidates, so expect some of what you are shown to be
  out of scope or wrong, and say so rather than presenting the list as adjudicated.
- `silentClasses` — classes with no finding anywhere. Say which of them were swept
  (`sweptGroups`) and which were capped out.
- `notes` — a reviewer's own note about what it could not finish.

List the artifacts: `findings.json`, `REPORT.md`, `REPORT.sarif`, `units.json`,
`ledger-gate.json`.

---

## Rationalizations to Reject

- **"The run mostly worked, so I'll just present the report."** A failed agent is
  uncovered ground, not a rounding error. Report it next to the findings, not in a
  footnote.
- **"Coverage is 80%, that's basically complete."** The missing 20% is a list of exact
  (unit, question) pairs in `ledger-gate.json`. Name them.
- **"I'll write the findings myself instead of running the workflow."** Hand-orchestrating
  this is what the rewrite removed. It cost nine times a single prompt for worse recall.
- **"The artifacts failed, so I'll reconstruct the report from the tool result."** The
  part files are on disk and the assembler is deterministic. Re-run it. A reconstruction
  is exactly the hand-transcription this design exists to eliminate.
- **"Zero findings, so there is nothing to report."** A zero-finding run still produces
  `REPORT.md` and `REPORT.sarif`, and a zero-finding run on real C code is itself worth
  saying out loud.
- **"The workflow returned findings, so I can skip reading REPORT.md."** The tool result
  is capped and carries counts, not findings. The report is the artifact.
- **"No judge ran, so I should filter the findings myself before showing them."** No.
  Report what the pipeline produced and label it unadjudicated. Silently dropping
  findings in the chat response reproduces the judge's cost with none of its rigour and
  leaves the artifact disagreeing with what you said.
- **"No judge ran, so I'll present severities as authoritative."** Also no. They are one
  reviewer's opinion, recorded as `severity_source: "reviewer"` in `findings.json`.

## Design notes

Every load-bearing rule below is from a measured failure. Do not undo one by "improving"
a prompt.

- **The judge was removed deliberately and the cost is known.** Most of what it rejected
  was threat-model scope, now handled in the review prompt for nothing. Do not reinstate a
  judge without re-measuring: its cost scales with finding count, which is exactly where
  this pipeline's cost ran away.
- **Persist is code, never an agent.** The previous last phase handed one agent the whole
  findings payload and asked it to retype it. Faithful at 15 and 25 findings, destroyed
  at 75 and 86 — every evidence field stripped from 22–23 of 23 — and one run shipped an
  empty findings array while its own stats block said 14 findings, 2 CRITICAL. The
  failure scaled with the pipeline's own success. Now each agent writes only its own
  output and `assemble_findings.py` builds the document, cross-checking each part file's
  length against what its agent returned so a summarised part fails loudly.
- **Coverage is measured against the parse, never against the reviewer's own account.**
  `sites_accounted` is diffed against line numbers tree-sitter counted. The previous
  validator certified 40/40 clean rows while one worker had fabricated thirteen, because
  it validated the rows that were present rather than the rows that were owed.
- **A finding raises the prior; it never closes the unit.** Any unit with a finding gets
  a second reader whose only brief is "what else is wrong here?" The densest function in
  the corpus was also the one with the most misses.
- **No reviewer may clear anything from recalled knowledge.** Every negative conclusion
  rests on the code, and any claimed mitigation cites a `path:line`. A worker previously
  cleared thirteen passes by asserting upstream CVE fixes were present when they were
  not, suppressing two real bugs inside its own remit.
- **Platform gating is on usage, not includes.** A portability shim that includes
  `<windows.h>` is not a Windows codebase; treating it as one previously burned 27% of
  the fan-out on a portable XML parser.
- **Every reviewer may report anything.** There is no stay-in-lane rule, and `logic-flaw`
  — the least specific class in the catalogue — produced more credited findings than any
  other, 28 of 102.
- **The banned-API rule demands a flow.** The old brief said of a bare `strcpy` that "the
  presence is the bug, no data-flow trace needed", wired to a judge forbidden from
  rejecting it. That is an unrejectable-finding pump. It never fired on the measured
  corpora because neither uses `strcpy`; it would fire on the first legacy target.
- **Cold error paths are read deliberately.** Three of the four bugs only a class sweep
  found live in them, which is exactly what an attacker-reachability prior deprioritises.
  Reachability weights depth, never coverage: every unit has an owner.
- **External sources are declared, not forbidden.** Consulting upstream is legitimate in
  a real audit; it only invalidates a benchmark run against a public corpus. Reviewers
  declare it, the benchmark harness excludes any arm that used an oracle, and nothing in
  the review path penalises the declaration.

The plugin is measured, not argued: `tools/c-review-bench/` holds corpora whose bugs this
repository injected itself (so no CVE database contains the answers), a grader that
reports recall by bug class and difficulty tier alongside false positives and token cost,
an oracle detector that invalidates rather than annotates, and a judge benchmark with
seeded false positives. tools/c-review-bench/MEASUREMENTS.md records what each number was.
