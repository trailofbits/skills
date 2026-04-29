# c-review

Comprehensive C/C++ security code review plugin. Runs assigned parallel workers over clusters of related bug classes and produces a deduplicated, severity-graded report plus SARIF.

## Features

- **Clustered worker pool** — 7–11 parallel workers, each assigned one cluster of related bug classes. Sites are inventoried once per cluster (Phase A) and reused across all of the cluster's passes.
- **File-based findings** — each finding is a markdown file with YAML frontmatter in a shared output directory; judges edit frontmatter in place (no separate handoff format).
- **Up to 64 bug-class passes across 7 always-on + 4 conditional clusters** — 47 always-on plus up to 17 conditional (`cpp-semantics` under `is_cpp`; three Windows clusters under `is_windows`).
- **Manifest-driven pass order** — `prompts/clusters/manifest.json` is the single source of truth for cluster gates, pass ordering, prefixes, and per-class prompt paths.
- **Platform-aware** — auto-selects clusters from detected `is_cpp` / `is_posix` / `is_windows` flags.
- **Threat-model-aware** — `REMOTE`, `LOCAL_UNPRIVILEGED`, or `BOTH`; out-of-scope passes (e.g. `privilege-drop` under `REMOTE`) are skipped.
- **Judge pipeline** — dedup → FP+severity, sequentially.
- **Severity filter** — report only Medium+ or High+ findings.
- **SARIF 2.1.0 export** — `scripts/generate_sarif.py` deterministically writes `REPORT.sarif` for CI / IDE consumption.

## Usage

```
/c-review:c-review [optional free-text args]
```

The skill self-collects parameters via a single `AskUserQuestion`. It pre-fills answers from any free text on the slash-command line and asks for unresolved required parameters:

- Threat model — `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH`
- Worker model — `haiku` / `sonnet` / `opus`
- Severity filter — `all` / `medium` / `high`
- Scope subpath is optional. It defaults to repo root unless the user asks for a narrower scope; ambiguous scope requests are clarified.

Examples:
- `/c-review:c-review` — asks for threat model, worker model, and severity filter
- `/c-review:c-review flamenco only high severity sonnet` — fills scope + severity + worker model; asks only for threat model
- `/c-review:c-review remote audit of src/net` — fills threat model + scope; asks for worker model and severity filter

## Architecture

```
/c-review:c-review  (skill entry point — no command wrapper)
└── Main conversation coordinates:
    ├── Phase 0: AskUserQuestion — collects required params, plus scope_subpath only when ambiguous
    ├── Phase 1: Detect is_cpp / is_posix / is_windows (scope-scoped)
    ├── Phase 2-3: Output directory + context.md
    ├── Phase 4: Select clusters from prompts/clusters/manifest.json
    ├── Phase 5: TaskCreate M cluster tasks (orchestrator-internal bookkeeping; workers
    │           have no Task tools and never read or write the ledger)
    ├── Phase 6: (optional) Phase 6a cache primer + Phase 6b stagger when
    │           plan.run.cache_primer=true; Phase 6c spawns M workers in a single
    │           message (parallel Agent calls, subagent_type="c-review:c-review-worker")
    │           └── Each worker: validate spawn prompt (self-check) →
    │                            run assigned cluster prompt
    │                                   (Phase A inventory + focused passes) →
    │                                   write finding files + per-worker shard
    │                                   under findings-index.d/ → exit
    ├── Phase 7: Wait until all workers complete; concatenate findings-index.d/ shards
    │           into findings-index.txt
    ├── Phase 8: Judges sequentially — Dedup → FP+Severity
    │           ├── Dedup-judge:    reads ALL findings, merges duplicates (Tier 1 exact loc,
    │           │                   Tier 2 same-function snippet-confirmed), writes dedup-summary.md
    │           └── FP+Severity:    reads primaries only, assigns fp_verdict + (for survivors)
    │                               severity / attack_vector / exploitability, writes
    │                               fp-summary.md + REPORT.md, then runs generate_sarif.py
    └── Phase 9: Return REPORT.md + artifact list
```

### Output directory layout

```
${output_dir}/
├── context.md             # threat model, scope, codebase summary
├── plan.json              # build_run_plan.py output: cluster selection, worker assignments
├── worker-prompts/        # build_run_plan.py output: one .txt per worker plus optional cache-primer.txt
│   ├── worker-1.txt
│   ├── worker-2.txt
│   └── cache-primer.txt   # only when plan.run.cache_primer=true
├── findings/
│   ├── BOF-001.md         # worker-written; judges add merged_into / fp_verdict / severity
│   ├── UAF-001.md
│   └── …
├── findings-index.d/      # per-worker shards (each worker writes its own paths here)
│   ├── worker-1.txt
│   └── …
├── findings-index.txt     # deterministic newline-separated manifest (concat of shards)
├── dedup-summary.md       # dedup-judge (stage 1; absent on zero-findings runs)
├── fp-summary.md          # fp+severity-judge (stage 2)
├── REPORT.md              # severity-filtered human-facing report
└── REPORT.sarif           # SARIF 2.1.0, generated from finding frontmatter
```

Default `output_dir`: `$(pwd)/.c-review-results/<iso-timestamp>/`.

## Communication format

Markdown-with-YAML-frontmatter everywhere except the SARIF export:

- **Finding files** — worker writes prose + code + data flow; judges add `merged_into` / `fp_verdict` / `severity` fields to the frontmatter via `Edit`.
- **Summary files** (`dedup-summary.md`, `fp-summary.md`) — markdown tables of counts and per-finding annotations.
- **Final report** (`REPORT.md`) — severity-grouped markdown, filtered per `severity_filter`.
- **SARIF export** (`REPORT.sarif`) — SARIF 2.1.0 JSON, covering the same reported findings as `REPORT.md`.

## Clusters

The authoritative list of clusters, pass ordering, gates, prefixes, and per-class prompt paths is `prompts/clusters/manifest.json`. Always-on coverage is 47 passes across 7 clusters. Conditional clusters add up to 17 more passes.

## Not for

- Windows or Linux/macOS kernel drivers / modules
- Managed languages (Java, C#, Python)
- Embedded / bare-metal code without libc

## Requirements

- Claude Code with `Task*` and `Agent` tools available to the main conversation.
- Named plugin subagents enabled so workers and judges get their tool sets eagerly (no `ToolSearch` bootstrap needed).
- `Write` + `Edit` for finding-file creation and in-place frontmatter updates.
- `python3` available on `PATH` for `scripts/build_run_plan.py` and `scripts/generate_sarif.py`.
