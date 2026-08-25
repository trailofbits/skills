---
name: semgrep
description: >-
  Runs a Semgrep security scan over a codebase: detects languages, selects
  rulesets, presents the plan for explicit approval, then runs every approved
  ruleset through scripts/run-scans.sh, which batches the semgrep processes and
  writes scans.json, and merges the output to SARIF. Supports two scan modes,
  "run all" for full ruleset coverage and "important only" for security
  findings at medium-to-high confidence and impact. Uses Semgrep Pro for
  cross-file taint analysis when it is available. Use when asked to scan code
  for vulnerabilities, run a security audit with Semgrep, find bugs, or perform
  static analysis. For the same scan without the approval gate, use the
  /static-analysis:semgrep-scan workflow.
allowed-tools: Bash Read Glob AskUserQuestion TaskCreate TaskList TaskUpdate
---

# Semgrep Security Scan

Run a Semgrep scan with automatic language detection, parallel execution, and merged SARIF output.

## Essential Principles

1. **Always use `--metrics=off`** — Semgrep sends telemetry by default; `--config auto` also phones home. Every `semgrep` command must include `--metrics=off` to prevent data leakage during security audits.
2. **User must approve the scan plan (Step 3 is a hard gate)** — The original "scan this codebase" request is NOT approval. Present exact rulesets, target, engine, and mode; wait for explicit "yes"/"proceed" before spawning scanners.
3. **Third-party rulesets are required, not optional** — Trail of Bits, 0xdea, and Decurity rules catch vulnerabilities absent from the official registry. Include them whenever the detected language matches.
4. **`scripts/run-scans.sh` generates the commands; do not write them yourself** — it builds every `semgrep` line from the approved list. That is what makes `--metrics=off`, the `--include` scoping rule, and the parallel dispatch properties of the code rather than instructions. Give it the approved rulesets and let it run.
5. **Always check for Semgrep Pro before scanning** — Pro enables cross-file taint tracking and catches ~250% more true positives. Skipping the check means silently missing critical inter-file vulnerabilities.
6. **Report what did not run** — `scans.json` carries `failed` and `skipped` alongside `scans`. A ruleset whose repo would not clone, or whose scan exited non-zero, must appear in the report. A partial scan presented as a complete one is worse than no scan.

## When to Use

- Security audit of a codebase
- Finding vulnerabilities before code review
- Scanning for known bug patterns
- First-pass static analysis

## When NOT to Use

- Binary analysis → Use binary analysis tools
- Already have Semgrep CI configured → Use existing pipeline
- Need cross-file analysis but no Pro license → Consider CodeQL as alternative
- Creating custom Semgrep rules → Use `semgrep-rule-creator` skill
- Porting existing rules to other languages → Use `semgrep-rule-variant-creator` skill

## Output Directory

All scan results, SARIF files, and temporary data are stored in a single output directory.

- **If the user specifies an output directory** in their prompt, use it as `OUTPUT_DIR`.
- **If not specified**, default to `./static_analysis_semgrep_1`. If that already exists, increment to `_2`, `_3`, etc.

In both cases, **always create the directory** with `mkdir -p` before writing any files.

```bash
# Resolve output directory
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  BASE="static_analysis_semgrep"
  N=1
  while [ -e "${BASE}_${N}" ]; do
    N=$((N + 1))
  done
  OUTPUT_DIR="${BASE}_${N}"
fi
mkdir -p "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results"
```

The output directory is resolved **once** at the start of Step 1 and used throughout all subsequent steps.

```
$OUTPUT_DIR/
├── rulesets.json                # The approved plan (Step 3), read by run-scans.sh (Step 4)
├── scans.json                   # What ran, failed, skipped, and covered nothing (Step 4)
├── raw/                         # Per-scan raw output (unfiltered)
│   ├── python-python.json        # <language>-<ruleset> for language-scoped rules
│   ├── python-python.sarif
│   ├── python-django.json
│   ├── python-django.sarif
│   ├── all-security-audit.json   # all-<ruleset> for cross-language rules, run once
│   ├── all-security-audit.sarif
│   └── ...
└── results/                     # Final merged output
    └── results.sarif
```

## Prerequisites

**Required:** Semgrep CLI (`semgrep --version`). If not installed, see [Semgrep installation docs](https://semgrep.dev/docs/getting-started/).

**Optional:** Semgrep Pro — enables cross-file taint tracking, inter-procedural analysis, and additional languages (Apex, C#, Elixir). Check with:

```bash
# --metrics=off because Principle 1 has no exceptions, and this is the first semgrep command
# of a run. stderr is kept because "OSS only" has several causes (logged out, no subscription,
# registry blocked) and the run downgrades silently for all of them.
if PRO_ERR=$(semgrep --pro --validate --metrics=off --config p/default 2>&1); then
  echo "Pro available"
else
  echo "OSS only"
  echo "  reason: $(printf '%s' "$PRO_ERR" | tail -n 3)"
fi
```

**Limitations:** OSS mode cannot track data flow across files. Pro mode uses `-j 1` for cross-file analysis (slower per ruleset, but parallel rulesets compensate).

## Scan Modes

Select mode in Step 2. Mode affects both the scan flags and post-processing.

| Mode | Coverage | Findings Reported |
|------|----------|-------------------|
| **Run all** | All rulesets, all severity levels | Everything |
| **Important only** | All rulesets, pre- and post-filtered | Security vulns only, medium-high confidence/impact |

**Important only** applies two filter layers:
1. **Pre-filter**: `--severity WARNING --severity ERROR` (CLI flag)
2. **Post-filter**: JSON metadata — keeps only `category=security`, `confidence∈{MEDIUM,HIGH}`, `impact∈{MEDIUM,HIGH}`

See [scan-modes.md](references/scan-modes.md) for metadata criteria and jq filter commands.

## Orchestration Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ MAIN SESSION (this skill)                                        │
│ Step 1: Detect languages + check Pro availability                │
│ Step 2: Select scan mode + rulesets (ref: rulesets.md)           │
│ Step 3: Present plan + rulesets, get approval [⛔ HARD GATE]     │
│ Step 4: Run scripts/run-scans.sh with the approved rulesets      │
│ Step 5: Post-filter, merge, report, delete repos/                │
└──────────────────────────────────────────────────────────────────┘
         │ Step 4: Bash
         ▼
┌──────────────────────────────────────────────────────────────────┐
│ scripts/run-scans.sh                                             │
│   clone       each third-party repo once, into repos/            │
│   generate    one semgrep command per ruleset                    │
│                ├── python     p/python, p/django   --include=*.py│
│                ├── javascript p/javascript         --include=*.js│
│                ├── docker     p/dockerfile                       │
│                └── cross-language  p/security-audit, p/secrets,  │
│                                    the cloned repos  (no filter) │
│   run         in batches of --jobs, exit code read per process   │
│   write       scans.json — scans, failed, skipped                │
└──────────────────────────────────────────────────────────────────┘
```

The approval gate stays in the session; the script is execution only and asks nothing. The
approved list reaches it as a JSON file, so the scan cannot reach a ruleset the user declined.

Cross-language rulesets go in one shared unit rather than being repeated per language.
`p/security-audit`, `p/secrets`, and the third-party repos scan the whole target unscoped,
so running them once per language ran the identical command N times and left the SARIF
merge to dedup the copies.

## Running it as a Workflow

This plugin ships `/static-analysis:semgrep-scan`, which runs the whole scan end to end:
detect languages and Pro, select rulesets from [rulesets.md](references/rulesets.md), run
`scripts/run-scans.sh`, merge and report. Pass it a JSON object, not prose:

```
/static-analysis:semgrep-scan {"target": "/abs/path", "mode": "run-all"}
```

**It does not stop for ruleset approval.** Invoking it with a target is the opt-in, the same
way `/variant-analysis:variants` works. That is safe to do because the scan is read-only over
the target — no `--autofix`, every write inside the output directory — so the approval gate
below is a scope confirmation rather than a safety one. What ran is recorded in
`rulesets.json` and `scans.json` either way.

Use the workflow when you want the scan run; work the five steps below when the ruleset
selection itself matters and you want to see and edit the list first.

## Workflow

**Follow the detailed workflow in [scan-workflow.md](workflows/scan-workflow.md).** Summary:

| Step | Action | Gate | Key Reference |
|------|--------|------|---------------|
| 1 | Resolve output dir, detect languages + Pro availability | — | Use Glob, not Bash |
| 2 | Select scan mode + rulesets | — | [rulesets.md](references/rulesets.md) |
| 3 | Present plan, get explicit approval | ⛔ HARD | AskUserQuestion |
| 4 | Run the scans | — | `scripts/run-scans.sh` |
| 5 | Post-filter, merge, report, clean up | — | Merge script (below) |

**Task enforcement:** On invocation, create 5 tasks with blockedBy dependencies (each step blocks the previous). Step 3 is a HARD GATE — mark complete ONLY after user explicitly approves.

**Merge command (Step 5):**

```bash
# run-all
uv run --no-project {baseDir}/scripts/merge_sarif.py "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results/results.sarif" \
  --scans "$OUTPUT_DIR/scans.json"

# important-only, once the JSON post-filter has run over every file in raw/
uv run --no-project {baseDir}/scripts/merge_sarif.py "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results/results.sarif" \
  --important --scans "$OUTPUT_DIR/scans.json"
```

`--scans` drops the output of scans listed under `.failed`. A scan that died part-way may still
have written a `.sarif`, and under `--important` that file has no post-filter beside it, which is
an error rather than an empty filter. Without the flag one dead scan denies every healthy scan a
merged result. The excluded files are named on stdout, so they can go in the report.

The post-filter reads metadata SARIF does not carry, so it cannot be re-run against the merged
file; `--important` instead keeps the findings the JSON filter kept, matched on
`(rule, file, line)`. Without it `results.sarif` is unfiltered while the JSON side is not.

## Workflow and agents

| Component | Purpose |
|-----------|---------|
| `scripts/run-scans.sh` | Builds every scan command from the approved rulesets, runs them in batches, and writes `scans.json` |

Step 4 is a Bash call. No subagent runs any part of the scan: exit codes and finding counts are
read from the processes and the JSON they wrote.

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "User asked for scan, that's approval" | Original request ≠ plan approval. Present plan, use AskUserQuestion, await explicit "yes" |
| "Step 3 task is blocking, just mark complete" | Lying about task status defeats enforcement. Only mark complete after real approval |
| "I already know what they want" | Assumptions cause scanning wrong directories/rulesets. Present plan for verification |
| "Just use default rulesets" | User must see and approve exact rulesets before scan |
| "Add extra rulesets without asking" | Modifying approved list without consent breaks trust |
| "Third-party rulesets are optional" | Trail of Bits, 0xdea, Decurity catch vulnerabilities not in official registry — REQUIRED |
| "Use --config auto" | Sends metrics; less control over rulesets |
| "I'll just run the semgrep commands myself" | `run-scans.sh` is what enforces `--metrics=off`, the `--include` rule and the output-directory `--exclude`. Hand-written commands drop them silently |
| "The script failed, I'll run semgrep directly to get something" | A non-zero exit means no scan succeeded. Report that and stop; a hand-run subset reads as a full scan |
| "Some scans failed, the run still finished" | `failed` and `skipped` are part of `scans.json`. Report them or the user reads a partial scan as a clean one |
| "Pro is too slow, skip --pro" | Cross-file analysis catches 250% more true positives; worth the time |
| "Semgrep handles GitHub URLs natively" | URL handling fails on repos with non-standard YAML; always clone first |
| "Cleanup is optional" | Cloned repos pollute the user's workspace and accumulate across runs |
| "Use `.` or relative path as target" | Subagents need absolute paths to avoid ambiguity |
| "Let the user pick an output dir later" | Output directory must be resolved at Step 1, before any files are created |

## Reference Index

| File | Content |
|------|---------|
| [rulesets.md](references/rulesets.md) | Complete ruleset catalog and selection algorithm |
| [scan-modes.md](references/scan-modes.md) | Pre/post-filter criteria and jq commands |

| Workflow | Purpose |
|----------|---------|
| [scan-workflow.md](workflows/scan-workflow.md) | Complete 5-step scan execution process |
| `scripts/run-scans.sh` | The scan runner Step 4 calls |

## Success Criteria

- [ ] Output directory resolved (user-specified or auto-incremented default)
- [ ] All generated files stored inside `$OUTPUT_DIR`
- [ ] Languages detected with file counts; Pro status checked
- [ ] Scan mode selected by user (run all / important only)
- [ ] Rulesets include third-party rules for all detected languages
- [ ] User explicitly approved the scan plan (Step 3 gate passed)
- [ ] `run-scans.sh` exited 0 and wrote `$OUTPUT_DIR/scans.json`
- [ ] `failed` and `skipped` from `scans.json` are empty, or listed in the report
- [ ] Every `semgrep` command used `--metrics=off`
- [ ] Approved plan written to `$OUTPUT_DIR/rulesets.json` at the Step 3 gate, and passed to
      the scanner unchanged
- [ ] `coveredNothing` from `scans.json` is empty, or listed in the report
- [ ] Raw per-scan outputs stored in `$OUTPUT_DIR/raw/`
- [ ] `results.sarif` exists in `$OUTPUT_DIR/results/` and is valid JSON
- [ ] Important-only mode: post-filter applied before merge, merge run with `--important`, unfiltered results preserved in `raw/`
- [ ] Results summary reported with severity and category breakdown
- [ ] Cloned repos (if any) cleaned up from `$OUTPUT_DIR/repos/`
