# c-review

C/C++ security code review plugin. Based on [Trail of Bits Testing Handbook](https://appsec.guide/docs/languages/c-cpp/)

## Overview

The skill takes the following inputs (collected via `AskUserQuestion`):

- **Threat model** — `REMOTE`, `LOCAL_UNPRIVILEGED`, or `BOTH`. Drives which passes are in scope (e.g. `privilege-drop` is skipped under `REMOTE`).
- **Scope subpath** — optional path under the repo root; defaults to the whole repo. Ambiguous scope requests are clarified.
- **Worker model** — `haiku` / `sonnet` / `opus` for the parallel worker agents.
- **Severity filter** — `all` / `medium` / `high`; controls what lands in `REPORT.md` and `REPORT.sarif`.

From these inputs the orchestrator detects platform/language flags (`is_cpp`, `is_posix`, `is_windows`) over the scope and selects clusters from `prompts/clusters/manifest.json`. Each cluster groups related bug classes — based on C/C++ chapters of [appsec.guide](https://appsec.guide/) — and runs as one parallel worker.

Always-on clusters:

- **buffer-write-sinks** — banned/unsafe stdlib calls, format strings, `snprintf` retval, overlapping buffers, `memcpy`/`strncpy`/`strncat` size and termination, scanf-uninit, flexible arrays, buffer overflows.
- **object-lifecycle** — uninitialized data, NULL deref, use-after-free, memory leaks.
- **arithmetic-type** — operator precedence, integer overflow, OOB comparisons, NULL/zero conflation, type confusion, undefined behavior, compiler bugs.
- **syscall-retval** — error / `errno` / `EINTR` handling, negative retval, `open()` issues, socket disconnect, half-closed sockets.
- **concurrency** — spinlock init, thread safety, race conditions, signal-handler safety.
- **ambient-state** — filesystem issues, access control, privilege drop, env vars, time-of-check, DoS.
- **static-hygiene** — exploit mitigations, `printf` attribute, `va_start`/`va_end`, regex, `inet_aton`, `qsort`.

Conditional clusters:

- **cpp-semantics** (`is_cpp`) — init order, virtual functions, smart pointers, move semantics, iterator invalidation, lambda captures, exception safety.
- **windows-process** (`is_windows`) — `CreateProcess`, cross-process access, token privileges, service security.
- **windows-fs-path** (`is_windows`) — DLL planting, Windows path handling, installer races.
- **windows-ipc-crypto** (`is_windows`) — named pipes, Windows crypto, Windows allocators.

Each worker inventories candidate sites once for its cluster (Phase A), then runs that cluster's focused passes and writes one markdown-with-YAML-frontmatter finding file per issue into a shared `findings/` directory. After workers exit, two judges run sequentially: a **dedup judge** merges duplicates, then an **FP + severity judge** assigns `fp_verdict` / `severity` / `attack_vector` / `exploitability` and writes `REPORT.md`. `scripts/generate_sarif.py` emits `REPORT.sarif` (SARIF 2.1.0) from the same frontmatter.

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
