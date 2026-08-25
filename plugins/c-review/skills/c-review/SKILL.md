---
name: c-review
description: Performs comprehensive C/C++ security review for memory corruption, integer overflows, race conditions, and platform-specific vulnerabilities. Use when auditing native C/C++ applications, reviewing daemons or services for memory safety, or hunting integer overflow / use-after-free / race conditions in userspace code.
allowed-tools: Workflow AskUserQuestion Bash Read
---

# C/C++ Security Review

Resolve four parameters, make one `Workflow` call, return the report. The workflow owns
concurrency, retries and result collection.

**Use for:** native C/C++ userspace — memory safety, integer overflow, races, type
confusion, Linux/macOS daemons, Windows services.

**Not for:** kernel drivers or modules; managed languages (Java, C#, Python, Go, Rust);
embedded or bare-metal code with no libc.

## Phase 0 — Parameters

Parse any free text on the invocation line (`flamenco only`, `high severity only`, `use
haiku`) and pre-fill what it implies. Then make **one** `AskUserQuestion` call for
whatever is still unresolved. Never silently default a required parameter.

| Parameter | Values | Inferring it from the invocation |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | "remote", "network", "attacker" → `REMOTE`; "local", "unprivileged" → `LOCAL_UNPRIVILEGED`; otherwise ask |
| `worker_model` | `haiku` / `sonnet` / `opus` / `inherit` | An explicit model name. Otherwise ask. `inherit` uses the session model |
| `severity_filter` | `all` / `medium` / `high` | "all", "every", "noisy" → `all`; "medium and above" → `medium`; "high only" → `high`; otherwise ask |
| `scope_subpath` | repo-relative directory, optional | "X only", "just audit X/" → the matching subdirectory, fuzzy-matched against top-level dirs. Absent → `.`. Ambiguous → ask |

Two scopes stay separate for the whole run:

- **`finding_scope_root`** = `scope_subpath` (default `.`) — a finding must live inside
  it, and it is the tree the unit list is generated from.
- **`context_roots`** = `.` — read freely to establish callers, build flags and
  reachability. Narrow it to `finding_scope_root` only if the user explicitly forbids
  wider reading, and say that reachability confidence drops when you do.

## Phase 1 — Resolve paths

```bash
root="${CLAUDE_PLUGIN_ROOT:-}"
if [ -z "$root" ] || [ ! -f "$root/workflows/c-review.js" ]; then
  # Fallback for a cache layout that does not set the variable. ~/.claude ONLY — never `.`:
  # `.` is the AUDITED repository, and a tree that vendors or mirrors this marketplace would
  # win the traversal and run its copy of the scripts, with a different question set and
  # nothing saying which copy ran. Let find's stderr through; a missing ~/.claude is a real
  # failure to report, not noise to hide.
  hit="$(find "$HOME/.claude" -path '*/c-review/workflows/c-review.js' -print -quit)"
  root="${hit%/workflows/c-review.js}"
fi
[ -n "$root" ] && [ -f "$root/workflows/c-review.js" ] && echo "PLUGIN ROOT: $root"
```

Stop if neither resolves, rather than running with an empty path — and say which path you
resolved, so a copy other than the installed plugin is visible before eight agents run
against it.

```bash
# The workflow cannot call Date.now(), so the timestamp is made here.
output_dir="$(pwd)/.c-review-results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$output_dir"; echo "$output_dir"

# A Workflow script has no filesystem APIs, and `assemble_findings.py` resolves `--scope`
# against ITS OWN cwd. Resolve it once here and pass BOTH spellings, or the workflow strips
# `src/` from a finding's path while the assembler strips `/repo/src/`, and the two disagree
# about which findings are duplicates of each other.
scope_abs="$(cd "${scope_subpath:-.}" && pwd)" || echo "scope_subpath does not exist"
echo "$scope_abs"
```

`uv` must be on PATH: Detect runs the unit enumerator and Assemble runs
`assemble_findings.py`. If `uv` is missing, say so and stop — the whole review is
partitioned from that unit list.

## Phase 2 — Run the workflow

Invoking this skill **is** the opt-in to multi-agent orchestration — call `Workflow`
without asking again. A review of a real codebase also runs past any default workflow
size guideline; that guideline is advisory and this is the case it exempts. Do not
shrink the fan-out to fit it, and do not substitute hand-spawned `Agent` calls.

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
    findingScopeRootAbs: "/abs/path/to/repo/expat/lib",
    contextRoots:     ".",
    workerModel:      "sonnet"
  }
})
```

`findingScopeRootAbs` is the `scope_abs` from Phase 1 and is not optional in practice:
omitted, the workflow tells the assembler no absolute root is known and a finding filed as
`/repo/expat/lib/xmlparse.c` stops merging with the same bug filed as `xmlparse.c`.

Six further arguments are optional. Omitted, each takes its default; passed with the
wrong TYPE, the workflow throws with the field name rather than defaulting. Pass them
only when the user asks or when running an evaluation:

| Argument | Default | What it is for |
|---|---|---|
| `maxUnitLines` | `150` | Cap on a review unit; a larger function is split at syntactic seams. Raising it reintroduces the saturation the cap prevents |
| `linesPerAgent` | `1500` | Source lines per review agent. **A no-op on a small tree** — `--agent-min` (default 4) floors the derived count, so two very different values can produce identical assignments. Use `reviewAgents` to pin the fan-out |
| `reviewAgents` | derived | Pins the review fan-out, subject to the same floor as the derived count: both are clamped to 4–14, and an explicit value above 14 raises the cap to itself. A value below 4 is raised to 4, and a trailing slice too small to be worth an agent is folded into its neighbour, so the final count can come out one lower than asked |
| `invariantAudit` | `false` | Adds the shared-state invariant audit to the sweep. A whole extra agent; turn it on for state-machine-heavy targets |
| `exclude` | `[]` | Array of globs or substrings the unit enumerator skips (each becomes a repeated `--exclude`). Use when enumeration aborts naming a path it cannot own — a symlink resolving outside the scope root, an unreadable directory — and the excluded paths land in the enumerator's totals as a visible coverage hole, not silence |
| `benchmarkMode` | `false` | **Eval-only.** Adds an external-source declaration to reviewer prompts and two schema fields. Changes no finding; leave it off for a real audit |

The workflow validates its own arguments and throws with a named field if one is
missing. It runs five phases:

| Phase | Agents | What it does |
|---|---|---|
| Detect | 1 | Runs `enumerate_units.py` for the unit list; platform flags **from actual API usage**; shared-state structs; per bug class, whether any candidate site exists |
| Review | 4–14 | One agent per contiguous slice of the unit list. Each returns findings **with severity** and a ledger row per (unit × question) |
| Sweep | 0–2 | The class axis: one agent over every bug class with no entry anywhere that Detect did not rule out. None, and the phase is skipped. Plus the struct-field audit when `invariantAudit: true` |
| Dedup | 0–1 | Only for collisions the assembler cannot merge deterministically. Usually skipped |
| Assemble | 1 | Runs `assemble_findings.py`: ledger gate, deterministic merges, `findings.json`, `REPORT.md`, `REPORT.sarif` |

**Around 8–10 agents on a mid-size target.**

## Phase 3 — Return the report

`Read <output_dir>/REPORT.md` and return it.

**Say once, plainly, next to the findings: no false-positive review ran.** Every
severity is the reviewer's own (`severity_source: "reviewer"`), `judgeRan` is always
`false`, and nothing rejected anything. Expect some of what you are shown to be wrong or
out of scope — say so rather than presenting the list as adjudicated, and do not filter
it yourself.

Then surface, prominently and separately from the findings, anything in the workflow
result that means the run was partial:

| Field | Meaning and what to do |
|---|---|
| `artifactsWritten: false` | `REPORT.md` and `REPORT.sarif` are missing; the part files under `parts/` are intact. Re-assemble by hand (below) — never reconstruct from the tool result |
| `artifactsWritten: null` | The assemble agent returned nothing, so whether the artifacts exist is **unknown** — the command may have completed and only its structured answer failed. List the output directory before doing anything else |
| `gateAccepted: false` with artifacts written | The failure that looks like success. Artifacts are complete; the **coverage gate** could not run or rejected the ledger, so the review is assembled and unverified. Do **not** re-run the assembler — read `ledger-gate.json` and report the gap. `artifactError` always carries the reason |
| `coverage: null` | Coverage is **unmeasured**, not complete. Never report such a run as fully covered; point at `ledger-gate.json` |
| `coverage` | Report `checksSatisfied` / `checksRequired`, and `checksCompleted` only as "answered" — never "functions reviewed". `checksSatisfied` below `checksCompleted` means the gate threw rows out: a coverage-*integrity* failure. Name the `violations` |
| `groupsFailed`, `agentFailures`, `notes` | That ground was **not covered**. Do not let a clean report imply it was |
| `unrecognisedParts` | Whole agents' output in no artifact. `null` means **unchecked, not none** |
| `silentClasses` / `ruledOutClasses` / `platformDroppedClasses` | "Swept and found nothing" / "nothing looked" / "out of scope by configuration". Report separately — only the middle one means a human should look |

Hand re-assembly, when `artifactsWritten` is false:

```
uv run --no-project <plugin_root>/scripts/assemble_findings.py --run-dir <output_dir> \
  --threat-model <MODEL> --severity-filter <FILTER> --no-judge \
  --scope <finding_scope_root> --context-roots <context_roots> \
  --worker-model <worker_model> \
  --expect <part-stem>=<finding-count>   # one per part the workflow log names
```

- **`--expect` is not optional.** Without it the allowlist admits every file under
  `parts/`, including one nobody dispatched, and the run exits **1** for that reason
  alone. If you cannot recover the counts from the workflow log, exit 1 is correct and
  the run is assembled-but-unverified.
- **Never drop `--no-judge`.** Dropping it overwrites every reviewer severity with MEDIUM
  and records `judge_ran: true` for a run no judge ever saw.
- Six flags cannot be reconstructed at all (`--expect-complete`, `--benchmark-mode`,
  `--groups-attempted`, `--groups-failed`, `--agent-failure`, `--external-source`), so
  the document will say `agent_failures: []` on a run that may have lost a slice. Report
  that. Without a `units.json` the assembler also exits **1**: no gate ran.

Finally list the artifacts: `findings.json`, `REPORT.md`, `REPORT.sarif`, `units.json`,
`ledger-gate.json`, `detect.json`, and the `parts/` and `assignments/` directories.

## Rationalizations to Reject

- **"The run mostly worked, so I'll just present the report."** A failed agent is
  uncovered ground, not a rounding error. Report it next to the findings.
- **"Coverage is 80%, that's basically complete."** The missing 20% is a list of exact
  (unit, question) pairs in `ledger-gate.json`. Name them.
- **"I'll write the findings myself instead of running the workflow."** Hand-orchestrating
  costs far more for worse recall. Always call `Workflow`.
- **"The artifacts failed, so I'll reconstruct the report from the tool result."** The
  part files are on disk and the assembler is deterministic. Re-run it.
- **"Zero findings, so there is nothing to report."** A zero-finding run still produces
  both artifacts, and zero findings on real C code is itself worth saying out loud.
- **"The workflow returned findings, so I can skip reading REPORT.md."** The tool result
  is capped and carries counts, not findings. The report is the artifact.
- **"No judge ran, so I should filter the findings myself."** No — silently dropping
  findings reproduces a judge's cost with none of its rigour and leaves the artifact
  disagreeing with what you said. Report what the pipeline produced, labelled unadjudicated.
- **"No judge ran, so I'll present severities as authoritative."** Also no. They are one
  reviewer's opinion.
- **"A class-per-agent fan-out would find more."** Location is the partition on purpose;
  the class catalogue is a bounded completeness sweep on top. Do not add one.

Design rationale, the coverage gate's threat model and its known limitations are in
[AGENTS.md](../../AGENTS.md). Read it before changing a prompt or a gate rule.
