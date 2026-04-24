# c-review

Comprehensive C/C++ security code review plugin using a task-queue worker pool with file-based finding storage.

## Features

- **Clustered worker pool** — 7–11 parallel workers, each owning one cluster of related bug classes (e.g. 13 buffer-write-sink finders run on one worker sharing a single Phase-A inventory)
- **File-based findings** — each finding is a markdown file with YAML frontmatter in a shared output directory; judges edit frontmatter in place
- **47 bug classes across 7 always-on + 4 conditional clusters** — buffer-write-sinks, object-lifecycle, arithmetic-type, syscall-retval, concurrency, ambient-state, static-hygiene, plus cpp-semantics (is_cpp), windows-process / windows-fs-path / windows-ipc-crypto (is_windows)
- **API-cache-friendly** — the worker agent system prompt is large and stable, so Anthropic prompt caching shares it across all parallel worker spawns; the cluster prompts themselves amortize per-file reads across 3–13 passes
- **Platform-aware** — auto-selects clusters for Linux/macOS/BSD or Windows
- **Threat-model-aware** — REMOTE, LOCAL_UNPRIVILEGED, or BOTH; filters out-of-scope sub-passes (e.g. privilege-drop under REMOTE)
- **Judge pipeline** — FP filtering, deduplication, severity assignment
- **Severity filter** — optionally report only Medium+ or High+ findings

## Usage

```
/c-review
```

The command prompts for:
- Threat model (REMOTE, LOCAL_UNPRIVILEGED, or BOTH)
- Worker model (haiku for speed, sonnet for depth, opus for maximum capability)
- Severity filter (all, medium, or high)

Arguments passed on the slash-command line (e.g. `only medium,high,and critical issues`) pre-fill the questions.

## Architecture

```
/c-review command (thin)
└── Invokes c-review skill via the Skill tool (runs in the MAIN conversation)
    └── Main conversation coordinates:
        ├── Detects code characteristics (is_cpp, is_posix, is_windows)
        ├── Creates output directory + context.md
        ├── TaskCreate one context task + M cluster tasks (M = 7..11 depending on gates)
        ├── Spawns M workers in a single message (parallel Agent calls,
        │   subagent_type="c-review:c-review-worker")
        │   └── Each worker: TaskList (self-check) →
        │                    loop { claim cluster → run cluster prompt (shared Phase-A
        │                           inventory + 3..13 focused passes) →
        │                           Write finding files → TaskUpdate(completed) }
        ├── Waits until all cluster tasks are completed
        └── Spawns judges sequentially (FP → Dedup → Severity)
            └── Judges read finding files, Edit frontmatter in place,
                write summary files, and severity-agent writes REPORT.md
```

### Why clustering (vs one task per prompt)

A previous design created ~45 tasks (one per bug-class prompt) and spawned 8 workers. Workers pulled tasks in rough round-robin from a shared queue, so unrelated prompts ran back-to-back on the same worker, blowing context and re-running the same Greps. The cluster design instead:

- Groups related bug classes (e.g. all 13 "buffer-write" finders) into a single cluster task.
- The cluster prompt begins with a **Phase A inventory** (one unified Grep for all sinks/syscalls/locks the cluster cares about), reused across all passes.
- `buffer-write-sinks.md` is fully consolidated — 13 sub-prompts merged into one, with a mandatory deconfliction rule so the same site doesn't get filed under multiple prefixes.
- Other clusters are thin — they Read the per-class sub-prompts in order, but share the Phase-A context across them.
- Worker count = cluster count, so no worker is idle and no cluster is serialized.

### API prompt caching

The `c-review-worker` agent system prompt (~5–6K tokens) contains the entire worker protocol and finding-file schema inline — nothing is read from a separate `worker.md` or `common.md` at runtime. Because all M workers share that exact system prompt within a 5-minute window, Anthropic's prompt cache writes it once on the first worker and serves it at ~10% base cost to workers 2..M. To preserve the cache hit, the orchestrator's spawn-time user prompt is intentionally tiny (just `worker-N`, `context_task_id`, `output_dir`).

### Output directory layout

```
${output_dir}/
├── context.md             # threat model, codebase summary
├── findings/
│   ├── BOF-001.md         # worker-written; judges add fp_verdict, merged_into, severity fields
│   ├── UAF-001.md
│   └── …
├── fp-summary.md          # fp-judge summary
├── dedup-summary.md       # dedup-judge summary
└── REPORT.md              # severity-agent final report (severity-filtered)
```

Default `output_dir`: `$(pwd)/.c-review-results/<iso-timestamp>/`.

### Why we use named plugin subagents

Workers and judges are declared as plugin subagents in `plugins/c-review/agents/*.md` with explicit `tools:` frontmatter. The `Task*` tools they need are listed there, so they're loaded into the subagent's tool set at spawn time — no `ToolSearch` bootstrap, no pseudo-code for a worker to misread as a `Skill()` invocation. A previous `general-purpose`-based design required each worker to run `ToolSearch(query="select:TaskList,...")` at startup; a Haiku worker misread that as `Skill("compound-engineering:triage")`, never loaded `TaskList`, and returned "no tasks found" — which the orchestrator misdiagnosed as a broken queue. The named-subagent design eliminates that class of failure.

## Communication Format

Everything is markdown with YAML frontmatter:
- **Finding files** — worker writes prose + code + data flow; judges add `fp_verdict`, `merged_into`, `severity` fields to the frontmatter via `Edit`.
- **Summary files** (`fp-summary.md`, `dedup-summary.md`) — markdown tables of counts and per-finding annotations.
- **Final report** (`REPORT.md`) — severity-grouped markdown, filtered per `severity_filter`.

No JSON/TOON serialization anywhere. The frontmatter gives structured lookup; the body holds the prose.

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

## Requirements

- Claude Code with the `Task*` tools and `Agent` tool available to the main conversation (the skill's `allowed-tools` declare them).
- Named plugin subagents (`plugins/c-review/agents/*.md`) enabled so workers and judges get their tool sets eagerly.
- `Write` + `Edit` for finding-file creation and in-place frontmatter updates.
- LSP server for the target codebase (recommended for deeper analysis).

## Version History

- **1.4.0** — Introduced clustered task model: 7 always-on + up to 4 conditional clusters replace the 45-ish flat finder-task list. One worker claims one cluster and runs all of its 3–13 sub-passes sequentially against a shared Phase-A inventory. `buffer-write-sinks.md` is fully consolidated (13 sub-prompts merged); other clusters remain thin indices of per-class sub-prompts. Worker agent system prompt inlined the previously-external `worker.md` + `common.md` (~5–6K stable tokens) so Anthropic prompt caching shares it across all parallel worker spawns.
- **1.3.0** — Moved workers and judges to named plugin subagents (`c-review:c-review-worker`, `c-review:c-review-fp-judge`, `c-review:c-review-dedup-judge`, `c-review:c-review-severity-agent`) with explicit `tools:` frontmatter. The `ToolSearch` bootstrap is gone. Dedup-judge rewritten for deterministic Tier-1 exact-location merges plus a narrow Tier-2 snippet check, with "default is keep separate" as the prime directive.
- **1.2.0** — Reverted to task-queue worker pool (from v1.1.0's direct-assignment model); subagents loaded the deferred queue-tool schemas via `ToolSearch` at startup. Findings exchanged as markdown files with YAML frontmatter in a shared output directory — no TOON, no JSON, no task-metadata handoff. Judges edit frontmatter in place to annotate verdicts, merges, and severity.
- **1.1.0** — Switched to direct-assignment workers after the v1.0 queue design failed because subagents couldn't call the deferred task tools. Kept the `Skill`-tool entrypoint so orchestration runs in the main conversation.
- **1.0.0** — Initial release with worker-pool pattern, 64 prompts, TOON format.
