---
name: c-review
description: >
  Performs comprehensive C/C++ security review using assigned parallel workers to scan for
  memory corruption, integer overflows, race conditions, and platform-specific vulnerabilities.
  Use when asked to "audit C code", "C security audit", "find buffer overflows",
  "review C++ for security", "check for use-after-free", "C++ vulnerability scan",
  "audit Windows service", "review Linux daemon", "check signal handlers",
  "review setuid program", or "native code security review".
  NOT for kernel modules, managed languages, or embedded/bare-metal code.
allowed-tools:
  - Agent
  - AskUserQuestion
  - TaskCreate
  - TaskUpdate
  - TaskList
  - TaskGet
  - ToolSearch
  - Grep
  - Glob
  - Read
  - Write
  - Edit
  - LSP
  - Bash
---

# C/C++ Security Review

Comprehensive security review of C/C++ codebases. **This skill runs in the main conversation** (invoke via `/c-review:c-review` — no command wrapper, the skill self-collects parameters). It uses `TaskCreate`/`TaskUpdate`/`TaskList`/`TaskGet` as a shared task ledger, then assigns exactly one cluster task to each worker. Workers and judges are spawned as **named plugin subagents** (`c-review:c-review-worker`, `c-review:c-review-dedup-judge`, `c-review:c-review-fp-judge`) whose tool sets are declared in `plugins/c-review/agents/*.md`; findings are exchanged via **markdown files with YAML frontmatter** in a shared output directory.

## When to Use

- Auditing C/C++ applications for security vulnerabilities
- Pre-release security review of native code
- Finding memory-safety issues (buffer overflow, use-after-free)
- Integer overflow and type-confusion bugs
- Race conditions and concurrency issues
- Linux/macOS daemons, setuid programs, signal handlers
- Windows services, DLL loading, named pipes, CreateProcess

## When NOT to Use

- Windows kernel driver review (different checklist)
- Linux/macOS kernel modules (different checklist)
- Managed languages (Java, C#, Python)
- Embedded/bare-metal code without libc

## Parameters

| Parameter | Values | Required |
|-----------|--------|----------|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | yes — never silently default |
| `worker_model` | `haiku` / `sonnet` / `opus` | yes — never silently default |
| `severity_filter` | `all` / `medium` (≥ Medium) / `high` (≥ High) | yes — never silently default |
| `scope_subpath` | repo-relative directory (optional) | no — defaults to repo root |
| `output_dir` | absolute path | no — defaults to `${CWD}/.c-review-results/<iso-timestamp>/` |

---

## Subagents

Workers and judges run as **named plugin subagents** declared in `plugins/c-review/agents/*.md`:

| Subagent type | Purpose | Tool set |
|---|---|---|
| `c-review:c-review-worker` | Run assigned cluster task, write findings | Read, Write, Edit, Grep, Glob, Bash, LSP, TaskList, TaskGet, TaskUpdate |
| `c-review:c-review-dedup-judge` | Merge duplicates (runs **first**) | Read, Write, Edit, Glob |
| `c-review:c-review-fp-judge` | FP + severity + final reports (runs **second**) | Read, Write, Edit, Grep, Glob, Bash, LSP |

Tools are loaded into the subagent's tool set at spawn time from each agent's frontmatter; no `ToolSearch` bootstrap is required. The orchestrator's own `Task*` and `Agent` tools come from this skill's `allowed-tools`.

---

## Architecture: Assigned Workers + File-Based Handoff

```
Main conversation (coordinator)
├── Creates output directory and writes context.md
├── Creates TaskCreate entries:
│   ├── 1 context task  (metadata: threat_model, severity_filter, output_dir, codebase_summary)
│   └── N cluster tasks (metadata.kind="cluster", prompt_path → prompts/clusters/*.md)
├── Spawns M workers in ONE message (parallel Agent calls, subagent_type=c-review:c-review-worker)
│   ├── M = number of cluster tasks (typically 7 for POSIX-only, +1 for C++, +3 for Windows)
│   └── Each worker: TaskList (self-check) → run assigned cluster prompt (multiple passes) → write findings → TaskUpdate(completed)
├── Waits until all cluster tasks are completed (poll TaskList)
├── Spawns judges sequentially:
│   ├── Dedup-judge   → reads findings/*.md (ALL of them), edits frontmatter with merged_into /
│   │                   also_known_as / locations, writes dedup-summary.md
│   └── FP+Severity-judge → reads primaries only (merged_into absent), assigns fp_verdict AND
│                         severity/attack_vector/exploitability, writes fp-summary.md + REPORT.md + REPORT.sarif
└── Reads REPORT.md and returns it to the caller (REPORT.sarif is also always produced)
```

**Cluster model:** each cluster groups related bug classes so one worker shares a Phase-A inventory (sink/syscall/lock greps) across multiple passes. Worker count = cluster count, and the coordinator passes a distinct `assigned_cluster_task_id` to each worker to avoid concurrent queue-claim races. The worker agent's system prompt is kept stable across spawns so the API caches it.

**Output directory layout:**
```
${output_dir}/
├── context.md             # coordinator writes (threat model, codebase summary)
├── findings/              # workers write one markdown file per finding
│   ├── BOF-001.md
│   ├── UAF-001.md
│   └── …
├── findings-index.txt     # coordinator writes (Phase 7) — newline-separated finding paths
├── dedup-summary.md       # dedup-judge writes (stage 1; absent on zero-findings runs)
├── fp-summary.md          # fp+severity-judge writes (stage 2)
├── REPORT.md              # fp+severity-judge writes (final human-readable report)
└── REPORT.sarif           # fp+severity-judge writes (SARIF 2.1.0, always produced)
```

**Path convention:** file paths below use `${CLAUDE_PLUGIN_ROOT}` for skill-internal files. Verify it's resolvable at the start of Phase 0:
```
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/clusters/buffer-write-sinks.md
```
If empty, fall back to `Glob: **/plugins/c-review/prompts/clusters/*.md` and use the discovered directory as the cluster root.

---

## Orchestration Workflow

Run these phases **in the main conversation**.

### Phase 0: Parameter Collection

The skill is invoked directly (no command wrapper). Parse any free-text arguments the user passed on the `/c-review:c-review` line (e.g. `flamenco only`, `high severity only`, `use haiku`) and pre-fill the answers they imply — then ask for any missing required parameters with **one** `AskUserQuestion` call. Never silently default the required parameters.

Required parameters:

| Parameter | Values | How to infer from args |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | Words like "remote", "network", "attacker" → `REMOTE`; "local", "unprivileged" → `LOCAL_UNPRIVILEGED`; otherwise ask. |
| `worker_model` | `haiku` / `sonnet` / `opus` | Explicit model name in args. Otherwise ask (no silent default). |
| `severity_filter` | `all` / `medium` / `high` | "all", "every", "noisy" → `all`; "medium and above" → `medium`; "high only", "criticals only" → `high`. Otherwise ask — **no silent default**. |
| `scope_subpath` | repo-relative directory (optional) | Phrases like "X only", "just audit X/", "review subdirectory X" → `src/X/` or the matching subdir. Apply fuzzy matching against top-level subdirectories of the repo. If absent, set `"."`; if ambiguous, ask. |

Call `AskUserQuestion` exactly once with only unresolved required parameters (`threat_model`, `worker_model`, `severity_filter`) plus `scope_subpath` only when the user explicitly requested a narrowed scope but it is ambiguous. If the required parameters were all pre-filled and scope is absent or resolved, skip the question.

### Phase 1: Prerequisites

```bash
command -v clangd
```
If not found, warn that LSP features will be limited.

```
Glob: pattern="**/compile_commands.json"  path="${scope_subpath:-.}"
```
If empty, suggest CMake (`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`), Bear, or compiledb. Continue without it.

Detect language/OS characteristics (scope-scoped when `scope_subpath` was set). Use the built-in `Glob` tool (always available) — do **not** depend on `fd`/`find` being installed:
```
Glob: pattern="**/*.{cpp,cxx,cc,hpp,hh}"  path="${scope_subpath:-.}"
```
→ `is_cpp = true` if any matches.

```
Grep: pattern="#include\\s*<(pthread|signal|sys/(socket|stat|types|wait)|unistd|errno)\\.h>"  path="${scope_subpath:-.}"
```
→ `is_posix = true` if matches.

```
Grep: pattern="#include\\s*<(windows|winbase|winnt|winuser|winsock|ntdef|ntstatus)\\.h>"  path="${scope_subpath:-.}"
```
→ `is_windows = true` if matches.

### Phase 2: Output Directory

Resolve an absolute path for `output_dir` (default: `$(pwd)/.c-review-results/$(date -u +%Y%m%dT%H%M%SZ)/`):

```bash
mkdir -p "${output_dir}/findings"
```

### Phase 3: Codebase Context

Gather a short summary:
```bash
head -50 README.md 2>/dev/null || head -50 README.rst 2>/dev/null
ls -la Makefile CMakeLists.txt meson.build configure.ac 2>/dev/null | head -5
```

Write `${output_dir}/context.md` with this structure:

```markdown
---
threat_model: REMOTE | LOCAL_UNPRIVILEGED | BOTH
severity_filter: all | medium | high
scope_subpath: <repo-relative directory, or "." for repo root>
is_cpp: true|false
is_posix: true|false
is_windows: true|false
output_dir: /absolute/path/to/output
---

# Codebase Context

## Purpose
<what the software does — 1-3 sentences>

## Scope
<scope_subpath and what's in it — e.g. "src/flamenco/ only; contains gossip parsing, runtime, capture, types, features">

## Entry points
- <where untrusted data enters: network ports, file formats, CLI args, IPC…>

## Trust boundaries
- <what's sandboxed, what talks to trusted peers vs arbitrary remote attackers>

## Existing hardening
- <fuzzing corpora, sanitizers, privilege separation, etc.>
```

### Phase 4: Select Clusters

Instead of 45+ individual finder prompts, the coordinator now creates **one task per cluster**. Each cluster prompt lives in `prompts/clusters/*.md` and groups related bug classes so the worker can share a Phase-A inventory (sinks / syscall sites / lock model / …) across 4–13 passes.

**Always-on clusters (7):**

| cluster_id | prompt file | Covers (bug classes) |
|---|---|---|
| `buffer-write-sinks` | `prompts/clusters/buffer-write-sinks.md` | buffer-overflow, memcpy-size, overlapping-buffers, strlen-strcpy, strncat-misuse, strncpy-termination, snprintf-retval, scanf-uninit, format-string, banned-functions, flexible-array, unsafe-stdlib, string-issues |
| `object-lifecycle` | `prompts/clusters/object-lifecycle.md` | use-after-free, memory-leak, uninitialized-data, null-deref |
| `arithmetic-type` | `prompts/clusters/arithmetic-type.md` | integer-overflow, type-confusion, operator-precedence, oob-comparison, null-zero, undefined-behavior, compiler-bugs |
| `syscall-retval` | `prompts/clusters/syscall-retval.md` | errno-handling, negative-retval, error-handling, eintr-handling, socket-disconnect, half-closed-socket, open-issues |
| `concurrency` | `prompts/clusters/concurrency.md` | race-condition, thread-safety, spinlock-init, signal-handler |
| `ambient-state` | `prompts/clusters/ambient-state.md` | access-control, envvar, privilege-drop, filesystem-issues, time-issues, dos |
| `static-hygiene` | `prompts/clusters/static-hygiene.md` | exploit-mitigations, printf-attr, va-start-end, regex-issues, inet-aton, qsort |

**Conditional clusters:**

| Gate | cluster_id | prompt file |
|---|---|---|
| `is_cpp` | `cpp-semantics` | `prompts/clusters/cpp-semantics.md` (init-order, iterator-invalidation, exception-safety, move-semantics, smart-pointer, virtual-function, lambda-capture) |
| `is_windows` | `windows-process` | `prompts/clusters/windows-process.md` (createprocess, cross-process, token-privilege, service-security) |
| `is_windows` | `windows-fs-path` | `prompts/clusters/windows-fs-path.md` (dll-planting, windows-path, installer-race) |
| `is_windows` | `windows-ipc-crypto` | `prompts/clusters/windows-ipc-crypto.md` (named-pipe, windows-crypto, windows-alloc) |

**Threat-model filter:** if `threat_model == REMOTE`, record on the `ambient-state` task's metadata `skip_subclasses: ["privilege-drop", "envvar"]` so the worker drops those passes. Do NOT drop the whole cluster — the other passes in `ambient-state` still apply under `REMOTE`.

Result is `selected_clusters[]` — a list of `(cluster_id, prompt_path)` pairs with 7 (POSIX/always) + optionally cpp-semantics + optionally 3 Windows sub-clusters. Typical counts: 7 (pure C POSIX), 8 (C++ POSIX), 10 (C POSIX + Windows), 11 (C++ POSIX + Windows).

### Phase 5: Create Context Task and Cluster Tasks

```
context_task_id = TaskCreate(
  subject="Review Context",
  description="Shared parameters for all bug finders",
  activeForm="Storing review context",
  metadata={
    "threat_model": "<REMOTE|LOCAL_UNPRIVILEGED|BOTH>",
    "severity_filter": "<all|medium|high>",
    "scope_subpath": "<repo-relative dir or '.'>",
    "output_dir": "<absolute path>",
    "codebase_summary_path": "<output_dir>/context.md",
    "is_cpp": <bool>,
    "is_posix": <bool>,
    "is_windows": <bool>
  }
)
```

For each `cluster` in `selected_clusters[]`:
```
TaskCreate(
  subject="cluster-<cluster.cluster_id>",
  description="<cluster_id>: run all passes (<N> bug classes)",
  activeForm="Running cluster <cluster_id>",
  metadata={
    "kind": "cluster",
    "cluster_id": "<cluster_id>",
    "prompt_path": "<absolute path to prompts/clusters/<cluster_id>.md>",
    "sub_prompt_paths": [
      # Pre-resolved absolute paths, aligned 1:1 with the Pass order in the
      # cluster's prompt file. Empty list for consolidated clusters
      # (buffer-write-sinks — the cluster file is self-sufficient).
      "<abs path to per-class prompt 1>",
      "<abs path to per-class prompt 2>",
      ...
    ],
    "context_task_id": "<id>",
    "skip_subclasses": []      # e.g. ["privilege-drop","envvar"] for REMOTE ambient-state
  }
)
```

Track `cluster_task_ids[]` in the same order as `selected_clusters[]`. Tasks start as `pending`.

**Pass order for each cluster** (must match the cluster prompt file exactly — workers depend on the 1:1 index alignment):

| Cluster | Pass order (sub_prompt_paths[0..N-1]) |
|---|---|
| `buffer-write-sinks` | `[]` (consolidated) |
| `object-lifecycle` | uninitialized-data, null-deref, use-after-free, memory-leak |
| `arithmetic-type` | operator-precedence, integer-overflow, oob-comparison, null-zero, type-confusion, undefined-behavior, compiler-bugs |
| `syscall-retval` | error-handling, negative-retval, errno-handling, eintr-handling, open-issues, socket-disconnect, half-closed-socket |
| `concurrency` | spinlock-init, thread-safety, race-condition, signal-handler |
| `ambient-state` | filesystem-issues, access-control, privilege-drop, envvar, time-issues, dos |
| `static-hygiene` | exploit-mitigations, printf-attr, va-start-end, regex-issues, inet-aton, qsort |
| `cpp-semantics` | init-order, virtual-function, smart-pointer, move-semantics, iterator-invalidation, lambda-capture, exception-safety |
| `windows-process` | createprocess, cross-process, token-privilege, service-security |
| `windows-fs-path` | dll-planting, windows-path, installer-race |
| `windows-ipc-crypto` | named-pipe, windows-crypto, windows-alloc |

Per-class prompt files live in `prompts/general/<name>-finder.md`, `prompts/linux-userspace/<name>-finder.md`, or `prompts/windows-userspace/<name>-finder.md` — resolve each path with `Glob` before populating `sub_prompt_paths`.

### Phase 6: Spawn M Workers in ONE Message

**CRITICAL:** emit a single assistant message containing M `Agent` tool invocations (where M = `len(selected_clusters)`) so they run in parallel. Sequential spawning serializes the review.

Worker count must equal cluster count: each worker receives one `assigned_cluster_task_id` and runs that cluster end-to-end. Do not make workers compete for the first pending task; simultaneous queue claims can race.

For each worker `N ∈ [1..M]`:

| Parameter | Value |
|-----------|-------|
| `subagent_type` | `c-review:c-review-worker` |
| `model` | `${worker_model}` (haiku / sonnet / opus) |
| `description` | `C review worker N` |
| `prompt` | see template below |

Worker prompt template (keep stable across workers — only `worker-N` varies — so the shared system prompt caches efficiently):
```
worker-N

Context task id: <context_task_id>
Assigned cluster task id: <cluster_task_ids[N-1]>
Output directory: <absolute output_dir>
Scope root: <scope_subpath or "."> — all Grep/Glob queries MUST be rooted here; findings outside this subtree are out-of-scope.

(Follow your system-prompt protocol. Your first tool call must be TaskList.)
```

That's it. The worker's full protocol and finding-file schema live in its system prompt (`plugins/c-review/agents/c-review-worker.md`), which is ~5–6K tokens of stable content that the API caches across all M parallel spawns — workers 2..M read that cache at ~10% of its base cost. Keep the spawn-time user prompt short to preserve that prefix.

**Do not pass raw `${CLAUDE_PLUGIN_ROOT}` into the subagent prompt** — the worker doesn't need it; the assigned cluster prompt path is in the task metadata and the worker reads it via `TaskGet` + `Read`.

### Phase 7: Wait for Workers

Poll with `TaskList` until every cluster task is `completed`. If a task is `in_progress` but its owner has returned without completing, reset it to `pending` via `TaskUpdate` and spawn a replacement worker with that same `assigned_cluster_task_id`.

**Write a deterministic manifest** of finding files before spawning judges. This gives judges a `Glob`-independent fallback path (the dedup-judge has only `Read/Write/Edit/Glob` — no `Bash` or `ls`):

```bash
ls -1 "${output_dir}/findings/"*.md 2>/dev/null | sort > "${output_dir}/findings-index.txt"
```

The file is one repo-relative-or-absolute path per line, sorted lexicographically for reproducibility. An empty file is fine and signals "zero findings" unambiguously.

**Even if zero findings**, still run Phase 8 — the fp-judge protocol writes empty-results `REPORT.md` and `REPORT.sarif` so callers always get the same artifact set. Skipping Phase 8 here would silently break SARIF-consuming CI. The only adjustment for zero findings: dedup-judge can be skipped when `findings-index.txt` is empty; fp-judge tolerates a missing `dedup-summary.md` only for an empty finding set.

### Phase 8: Judge Pipeline (sequential, dedup → fp+severity)

Each judge runs as a named plugin subagent with its tool set declared in the agent frontmatter. **Always pass the absolute path to the judge's protocol file** — resolve `${CLAUDE_PLUGIN_ROOT}` before spawning. Judges open the protocol file with `Read`; they do not invoke `Skill(...)`.

Dedup runs first on the raw worker output so the FP judge only ever sees merged primaries — one analysis per underlying bug.

**Dedup-judge** (runs first):
```
Agent(
  subagent_type="c-review:c-review-dedup-judge",
  description="Dedup judge",
  prompt=f"""
Read the protocol at:
  <absolute path to prompts/internal/judges/dedup-judge.md>
and follow it exactly. Open it with the `Read` tool. Do NOT invoke `Skill(...)`.

Output directory: {output_dir}

Process ALL findings (no fp_verdict filter — fp_verdict doesn't exist yet).
Merge duplicates per the protocol: Tier 1 exact-location (deterministic), Tier 2 same-function snippet-confirmed.
Write {output_dir}/dedup-summary.md with merge rationale.
Return a one-line completion summary.
"""
)
```

**FP + Severity judge** (after Dedup completes):
```
Agent(
  subagent_type="c-review:c-review-fp-judge",
  description="FP + severity judge",
  prompt=f"""
Read the protocol at:
  <absolute path to prompts/internal/judges/fp-judge.md>
and follow it exactly. Open it with the `Read` tool. Do NOT invoke `Skill(...)`.

Context task id: {context_task_id}
Output directory: {output_dir}

Read {output_dir}/context.md for threat model and severity_filter.
If {output_dir}/dedup-summary.md does not exist, check {output_dir}/findings-index.txt.
If the manifest is empty, this is a zero-findings run: produce empty REPORT.md / REPORT.sarif.
If the manifest is non-empty, continue by treating every non-merged finding as a primary and add a prominent note to fp-summary.md and REPORT.md that dedup did not run.
Process only PRIMARIES — findings whose frontmatter has no 'merged_into' field.
For each primary: add fp_verdict + fp_rationale. For survivors (TRUE_POSITIVE / LIKELY_TP) also add
  severity, attack_vector, exploitability, severity_rationale.
Write {output_dir}/fp-summary.md with verdict counts.
Write {output_dir}/REPORT.md — severity-filtered markdown report.
Write {output_dir}/REPORT.sarif — SARIF 2.1.0, mandatory (always produced).
Return a one-line completion summary.
"""
)
```

### Phase 9: Return Report

```
Read ${output_dir}/REPORT.md → return to caller.
```

Include an "Artifacts" section in your reply:
- `${output_dir}/findings/` — individual finding files (frontmatter carries fp_verdict, severity, merged_into, also_known_as)
- `${output_dir}/dedup-summary.md` — dedup summary (stage 1)
- `${output_dir}/fp-summary.md` — FP+severity summary (stage 2)
- `${output_dir}/REPORT.md` — severity-filtered final report
- `${output_dir}/REPORT.sarif` — SARIF 2.1.0 machine-readable export (always produced)

---

## Finding File Format

Every file in `${output_dir}/findings/` is a markdown file with YAML frontmatter. Workers write the initial file; judges add fields to the frontmatter. File name is `<id>.md` (e.g. `BOF-001.md`).

**Minimum schema written by worker:**
```markdown
---
id: BOF-001
bug_class: buffer-overflow
title: Missing bounds check in parse_header
location: src/net/parse.c:142
function: parse_header
confidence: High
worker: worker-3
---

## Description
<prose — why this is a vulnerability>

## Code
```c
<actual vulnerable snippet>
```

## Data flow
- **Source:** <where attacker-controlled data enters>
- **Sink:** <where the vulnerability manifests>
- **Validation:** <what checks exist / are missing>

## Impact
<what an attacker could achieve>

## Recommendation
<how to fix>
```

**Fields added by judges** (via `Edit` on frontmatter). Pipeline order: dedup → fp+severity.
- Dedup-judge (on duplicates): `merged_into: <primary-id>`; (on primaries with merges): `also_known_as: [<id1>, <id2>]`, `locations: [<path:line>, …]`
- FP+Severity judge (on every primary): `fp_verdict: TRUE_POSITIVE | LIKELY_TP | LIKELY_FP | FALSE_POSITIVE | OUT_OF_SCOPE`, `fp_rationale: <one-line>`
- FP+Severity judge (on survivors — TRUE_POSITIVE / LIKELY_TP only): `severity: CRITICAL | HIGH | MEDIUM | LOW`, `attack_vector: Remote | Local | Both`, `exploitability: Reliable | Difficult | Theoretical`, `severity_rationale: <one-line>`

---

## Bug Classes → Clusters

| Cluster | Passes | Loaded When |
|---------|-------|-------------|
| `buffer-write-sinks` | 13 | Always |
| `object-lifecycle` | 4 | Always |
| `arithmetic-type` | 7 | Always |
| `syscall-retval` | 7 | Always |
| `concurrency` | 4 | Always |
| `ambient-state` | 6 (4 under `REMOTE`) | Always |
| `static-hygiene` | 6 | Always |
| `cpp-semantics` | 7 | `is_cpp` |
| `windows-process` | 4 | `is_windows` |
| `windows-fs-path` | 3 | `is_windows` |
| `windows-ipc-crypto` | 3 | `is_windows` |

Bug classes covered: 47 always-on, up to 64 with all conditional clusters enabled. Per-class prompt files live under `prompts/general/`, `prompts/linux-userspace/`, `prompts/windows-userspace/` and are referenced by the non-consolidated clusters; `buffer-write-sinks.md` is fully consolidated (its 13 sub-prompts are not re-read at runtime).

---

## Rationalizations to Reject (forwarded to workers via the `c-review-worker` agent system prompt)

- "Code path is unreachable" → Prove it with caller trace
- "ASLR/DEP prevents exploitation" → Mitigations are bypass targets
- "Too complex to exploit" → Report it anyway
- "Input validated elsewhere" → Verify the validation exists
- "Only crashes, not exploitable" → Memory corruption may be controllable
- "Signal handler is simple enough" → Even simple handlers can call non-async-signal-safe functions
- "Only called from one thread" → Thread usage patterns change
- "Environment is trusted" → Environment variables are attacker-controlled
