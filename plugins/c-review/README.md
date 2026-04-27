# c-review

Comprehensive C/C++ security code review plugin. Runs assigned parallel workers over clusters of related bug classes and produces a deduplicated, severity-graded report plus SARIF.

## Features

- **Clustered worker pool** — 7–11 parallel workers, each assigned one cluster of related bug classes. Sites are inventoried once per cluster (Phase A) and reused across all of the cluster's passes.
- **File-based findings** — each finding is a markdown file with YAML frontmatter in a shared output directory; judges edit frontmatter in place (no separate handoff format).
- **Up to 64 bug-class passes across 7 always-on + 4 conditional clusters** — 47 always-on plus up to 17 conditional (`cpp-semantics` under `is_cpp`; three Windows clusters under `is_windows`).
- **Platform-aware** — auto-selects clusters from detected `is_cpp` / `is_posix` / `is_windows` flags.
- **Threat-model-aware** — `REMOTE`, `LOCAL_UNPRIVILEGED`, or `BOTH`; out-of-scope passes (e.g. `privilege-drop` under `REMOTE`) are skipped.
- **Judge pipeline** — dedup → FP+severity, sequentially.
- **Severity filter** — report only Medium+ or High+ findings.
- **SARIF 2.1.0 export** — `REPORT.sarif` always produced for CI / IDE consumption.

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
    ├── Phase 4: Select clusters from prompts/clusters/*.md
    ├── Phase 5: TaskCreate one context task + M cluster tasks (M = 7..11)
    ├── Phase 6: Spawn M workers in a single message (parallel Agent calls,
    │           subagent_type="c-review:c-review-worker")
    │           └── Each worker: TaskList (self-check) →
    │                            run assigned cluster prompt
    │                                   (Phase A inventory + focused passes) →
    │                                   Write finding files → TaskUpdate(completed)
    ├── Phase 7: Wait until all cluster tasks are completed; write findings-index.txt manifest
    ├── Phase 8: Judges sequentially — Dedup → FP+Severity
    │           ├── Dedup-judge:    reads ALL findings, merges duplicates (Tier 1 exact loc,
    │           │                   Tier 2 same-function snippet-confirmed), writes dedup-summary.md
    │           └── FP+Severity:    reads primaries only, assigns fp_verdict + (for survivors)
    │                               severity / attack_vector / exploitability, writes
    │                               fp-summary.md + REPORT.md + REPORT.sarif
    └── Phase 9: Return REPORT.md + artifact list
```

### Output directory layout

```
${output_dir}/
├── context.md             # threat model, scope, codebase summary
├── findings/
│   ├── BOF-001.md         # worker-written; judges add merged_into / fp_verdict / severity
│   ├── UAF-001.md
│   └── …
├── findings-index.txt     # deterministic newline-separated manifest of finding files
├── dedup-summary.md       # dedup-judge (stage 1; absent on zero-findings runs)
├── fp-summary.md          # fp+severity-judge (stage 2)
├── REPORT.md              # severity-filtered human-facing report
└── REPORT.sarif           # SARIF 2.1.0, always produced
```

Default `output_dir`: `$(pwd)/.c-review-results/<iso-timestamp>/`.

## Communication format

Markdown-with-YAML-frontmatter everywhere except the SARIF export:

- **Finding files** — worker writes prose + code + data flow; judges add `merged_into` / `fp_verdict` / `severity` fields to the frontmatter via `Edit`.
- **Summary files** (`dedup-summary.md`, `fp-summary.md`) — markdown tables of counts and per-finding annotations.
- **Final report** (`REPORT.md`) — severity-grouped markdown, filtered per `severity_filter`.
- **SARIF export** (`REPORT.sarif`) — SARIF 2.1.0 JSON, covering the same reported findings as `REPORT.md`.

## Clusters and the bug classes they cover

| Cluster | Passes | Gate | Bug classes |
|---------|--------|------|-------------|
| `buffer-write-sinks` | 13 | Always | buffer-overflow, memcpy-size, overlapping-buffers, strlen-strcpy, strncat-misuse, strncpy-termination, snprintf-retval, scanf-uninit, format-string, banned-functions, flexible-array, unsafe-stdlib, string-issues |
| `object-lifecycle` | 4 | Always | use-after-free, memory-leak, uninitialized-data, null-deref |
| `arithmetic-type` | 7 | Always | integer-overflow, type-confusion, operator-precedence, oob-comparison, null-zero, undefined-behavior, compiler-bugs |
| `syscall-retval` | 7 | Always | errno-handling, negative-retval, error-handling, eintr-handling, socket-disconnect, half-closed-socket, open-issues |
| `concurrency` | 4 | Always | race-condition, thread-safety, spinlock-init, signal-handler |
| `ambient-state` | 6 (4 under REMOTE) | Always | access-control, envvar, privilege-drop, filesystem-issues, time-issues, dos |
| `static-hygiene` | 6 | Always | exploit-mitigations, printf-attr, va-start-end, regex-issues, inet-aton, qsort |
| `cpp-semantics` | 7 | `is_cpp` | init-order, iterator-invalidation, exception-safety, move-semantics, smart-pointer, virtual-function, lambda-capture |
| `windows-process` | 4 | `is_windows` | createprocess, cross-process, token-privilege, service-security |
| `windows-fs-path` | 3 | `is_windows` | dll-planting, windows-path, installer-race |
| `windows-ipc-crypto` | 3 | `is_windows` | named-pipe, windows-crypto, windows-alloc |

Always-on coverage: 47 passes across 7 clusters. Conditional clusters add up to 17 more passes.

## Not for

- Windows or Linux/macOS kernel drivers / modules
- Managed languages (Java, C#, Python)
- Embedded / bare-metal code without libc

## Requirements

- Claude Code with `Task*` and `Agent` tools available to the main conversation.
- Named plugin subagents enabled so workers and judges get their tool sets eagerly (no `ToolSearch` bootstrap needed).
- `Write` + `Edit` for finding-file creation and in-place frontmatter updates.
- Optional but recommended: `clangd` and `compile_commands.json` for LSP-backed verification (call graphs, types, references).
