---
name: c-review
description: >
  Performs comprehensive C/C++ security review using a task-queue worker pool to scan for
  memory corruption, integer overflows, race conditions, and platform-specific vulnerabilities.
  Triggers on "audit C code", "C security audit", "find buffer overflows", "review C++ for security",
  "check for use-after-free", "C++ vulnerability scan", "audit Windows service", "review Linux daemon",
  "check signal handlers", "review setuid program", "native code security review".
  NOT for kernel modules, managed languages, or embedded/bare-metal code.
allowed-tools:
  - Agent
  - Task
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

Comprehensive security review of C/C++ codebases. **This skill MUST run in the main conversation** — it uses `TaskCreate`/`TaskUpdate`/`TaskList`/`TaskGet` for a shared work queue. Workers and judges are spawned as **named plugin subagents** (`c-review:c-review-worker`, `c-review:c-review-fp-judge`, `c-review:c-review-dedup-judge`, `c-review:c-review-severity-agent`) whose tool sets are declared in `plugins/c-review/agents/*.md`; findings are exchanged via **markdown files with YAML frontmatter** in a shared output directory.

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
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | yes |
| `worker_model` | `haiku` / `sonnet` / `opus` | yes |
| `severity_filter` | `all` / `medium` (≥ Medium) / `high` (≥ High) | default: `all` |
| `output_dir` | absolute path | default: `${CWD}/.c-review-results/<iso-timestamp>/` |

---

## Why We Use Named Plugin Subagents (Not `general-purpose`)

Workers and judges run as **named plugin subagents** declared in `plugins/c-review/agents/*.md`:

| Subagent type | Purpose | Tool set |
|---|---|---|
| `c-review:c-review-worker` | Claim cluster tasks, write findings | Read, Write, Edit, Grep, Glob, Bash, LSP, TaskList, TaskGet, TaskUpdate |
| `c-review:c-review-fp-judge` | FP triage | Read, Write, Edit, Grep, Glob, Bash, LSP |
| `c-review:c-review-dedup-judge` | Dedup | Read, Write, Edit, Glob (no Bash/Grep/LSP by design) |
| `c-review:c-review-severity-agent` | Severity + report | Read, Write, Edit, Grep, Glob, Bash, LSP |

Because these tools are enumerated in the agent's frontmatter, they are loaded into the subagent's tool set at spawn time — **no `ToolSearch` bootstrap is required**. Previous runs of this skill used `general-purpose` subagents, which kept `Task*` deferred; a Haiku worker once misread the `ToolSearch(...)` pseudo-code as a `Skill()` invocation, called an unrelated triage skill, never loaded `TaskList`, and returned "no tasks found" — which the orchestrator misdiagnosed as a broken queue. Named subagents with explicit tool lists remove that failure mode.

**Orchestrator (main conversation) still uses the deferred-tool mechanism** implicitly through the skill's `allowed-tools` — `TaskCreate`, `TaskUpdate`, `TaskList`, `TaskGet`, and `Agent` are available without ceremony.

---

## Architecture: Queue + File-Based Handoff

```
Main conversation (coordinator)
├── Creates output directory and writes context.md
├── Creates TaskCreate entries:
│   ├── 1 context task  (metadata: threat_model, severity_filter, output_dir, codebase_summary)
│   └── N cluster tasks (metadata.kind="cluster", prompt_path → prompts/clusters/*.md)
├── Spawns M workers in ONE message (parallel Agent calls, subagent_type=c-review:c-review-worker)
│   ├── M = number of cluster tasks (typically 7 for POSIX-only, +1 for C++, +3 for Windows)
│   └── Each worker: TaskList (self-check) → loop { claim cluster → run cluster prompt (multiple passes) → write findings → TaskUpdate(completed) }
├── Waits until all cluster tasks are completed (poll TaskList)
├── Spawns judges sequentially:
│   ├── FP-judge      → reads findings/*.md, edits frontmatter with fp_verdict, writes fp-summary.md
│   ├── Dedup-judge   → reads findings/*.md with passing verdicts, edits frontmatter with merged_into,
│   │                   writes dedup-summary.md
│   └── Severity-agent→ reads surviving findings, edits frontmatter with severity, writes REPORT.md
└── Reads REPORT.md and returns it to the caller
```

**Why clusters (not one task per prompt):** running 13 buffer-write finders in one worker shares Grep results and codebase reads across all 13 passes — Phase-A in each cluster prompt builds a sink/syscall/lock inventory once and the passes consume it. The worker agent system prompt is large and stable, so the API caches it across all M worker spawns (workers 2..M pay ~10% of its token cost). See `prompts/clusters/buffer-write-sinks.md` for the consolidated example.

**Output directory layout:**
```
${output_dir}/
├── context.md             # coordinator writes (threat model, codebase summary)
├── findings/              # workers write one markdown file per finding
│   ├── BOF-001.md
│   ├── UAF-001.md
│   └── …
├── fp-summary.md          # fp-judge writes
├── dedup-summary.md       # dedup-judge writes
└── REPORT.md              # severity-agent writes (final human-readable report)
```

**Path convention:** file paths below use `${CLAUDE_PLUGIN_ROOT}` for skill-internal files. Verify it's resolvable at the start of Phase 0:
```
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/clusters/buffer-write-sinks.md
```
If empty, fall back to `Glob: **/plugins/c-review/prompts/clusters/*.md` and use the discovered directory as the cluster root.

---

## Orchestration Workflow

Run these phases **in the main conversation**.

### Phase 0: Prerequisites

```bash
which clangd
```
If not found, warn that LSP features will be limited.

```bash
fd compile_commands.json . --type f 2>/dev/null | head -5
```
If not found, suggest CMake (`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`), Bear, or compiledb. Continue without it.

Detect language/OS characteristics:
```bash
fd -e cpp -e cxx -e cc -e hpp . | head -5
```
→ `is_cpp = true` if any found.

```
Grep: pattern="#include.*<(pthread|signal|sys/(socket|stat|types|wait)|unistd|errno)\.h>"
```
→ `is_posix = true` if matches.

```
Grep: pattern="#include.*<(windows|winbase|winnt|winuser|winsock|ntdef|ntstatus)\.h>"
```
→ `is_windows = true` if matches.

### Phase 1: Output Directory

Resolve an absolute path for `output_dir` (default: `$(pwd)/.c-review-results/$(date -u +%Y%m%dT%H%M%SZ)/`):

```bash
mkdir -p "${output_dir}/findings"
```

### Phase 2: Codebase Context

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
is_cpp: true|false
is_posix: true|false
is_windows: true|false
output_dir: /absolute/path/to/output
---

# Codebase Context

## Purpose
<what the software does — 1-3 sentences>

## Entry points
- <where untrusted data enters: network ports, file formats, CLI args, IPC…>

## Trust boundaries
- <what's sandboxed, what talks to trusted peers vs arbitrary remote attackers>

## Existing hardening
- <fuzzing corpora, sanitizers, privilege separation, etc.>
```

### Phase 3: Select Clusters

Instead of 45+ individual finder prompts, the coordinator now creates **one task per cluster**. Each cluster prompt lives in `prompts/clusters/*.md` and groups related bug classes so the worker can share a Phase-A inventory (sinks / syscall sites / lock model / …) across 4–13 passes.

**Always-on clusters (6):**

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

### Phase 4: Create Context Task and Cluster Tasks

```
context_task_id = TaskCreate(
  subject="Review Context",
  description="Shared parameters for all bug finders",
  activeForm="Storing review context",
  metadata={
    "threat_model": "<REMOTE|LOCAL_UNPRIVILEGED|BOTH>",
    "severity_filter": "<all|medium|high>",
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

Track the set of cluster task IDs → `cluster_task_ids[]`. Tasks start as `pending`.

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

### Phase 5: Spawn M Workers in ONE Message

**CRITICAL:** emit a single assistant message containing M `Agent` tool invocations (where M = `len(selected_clusters)`) so they run in parallel. Sequential spawning serializes the review.

**Why M = cluster count, not 8:** each cluster is claimed by exactly one worker and runs end-to-end there. A pool of 8 workers for 7 clusters would leave one idle; 8 clusters on 6 workers would serialize two. Match worker count to cluster count.

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
Output directory: <absolute output_dir>

(Follow your system-prompt protocol. Your first tool call must be TaskList.)
```

That's it. The worker's full protocol and finding-file schema live in its system prompt (`plugins/c-review/agents/c-review-worker.md`), which is ~5–6K tokens of stable content that the API caches across all M parallel spawns — workers 2..M read that cache at ~10% of its base cost. Keep the spawn-time user prompt short to preserve that prefix.

**Do not pass raw `${CLAUDE_PLUGIN_ROOT}` into the subagent prompt** — the worker doesn't need it; cluster prompt paths are in the task metadata and the worker reads them via `TaskGet` + `Read`.

### Phase 6: Wait for Workers

Poll with `TaskList` until every cluster task is `completed`. If a task is `in_progress` but its owner has returned without completing, reset it to `pending` via `TaskUpdate` and spawn a replacement worker.

List the finding files:
```bash
ls "${output_dir}/findings/"*.md 2>/dev/null | wc -l
```

If zero findings, skip Phase 7 and report "No findings — workers completed M cluster tasks with zero bugs above noise threshold".

### Phase 7: Judge Pipeline (sequential)

Each judge runs as a named plugin subagent with its tool set declared in the agent frontmatter. **Always pass the absolute path to the judge's protocol file** — resolve `${CLAUDE_PLUGIN_ROOT}` before spawning. Judges open the protocol file with `Read`; they do not invoke `Skill(...)`.

**FP-judge:**
```
Agent(
  subagent_type="c-review:c-review-fp-judge",
  description="FP judge",
  prompt=f"""
Read the protocol at:
  <absolute path to prompts/internal/judges/fp-judge.md>
and follow it exactly. Open it with the `Read` tool. Do NOT invoke `Skill(...)`.

Context task id: {context_task_id}
Output directory: {output_dir}

Read {output_dir}/context.md for threat model and codebase context.
Read every file in {output_dir}/findings/.
For each finding file, add 'fp_verdict' and 'fp_rationale' to its YAML frontmatter.
Write {output_dir}/fp-summary.md with counts and FP-pattern notes.
Return a one-line completion summary.
"""
)
```

**Dedup-judge** (after FP-judge completes):
```
Agent(
  subagent_type="c-review:c-review-dedup-judge",
  description="Dedup judge",
  prompt=f"""
Read the protocol at:
  <absolute path to prompts/internal/judges/dedup-judge.md>
and follow it exactly. Open it with the `Read` tool. Do NOT invoke `Skill(...)`.

Output directory: {output_dir}

Consider only findings whose frontmatter has fp_verdict ∈ {{TRUE_POSITIVE, LIKELY_TP}}.
Merge duplicates per the dedup-judge protocol (deterministic Tier 1 + narrow Tier 2).
Write {output_dir}/dedup-summary.md with merge rationale.
Return a one-line completion summary.
"""
)
```

**Severity-agent** (after Dedup-judge completes):
```
Agent(
  subagent_type="c-review:c-review-severity-agent",
  description="Severity agent",
  prompt=f"""
Read the protocol at:
  <absolute path to prompts/internal/judges/severity-agent.md>
and follow it exactly. Open it with the `Read` tool. Do NOT invoke `Skill(...)`.

Output directory: {output_dir}

Read {output_dir}/context.md for threat_model and severity_filter.
Consider only findings where fp_verdict ∈ {{TRUE_POSITIVE, LIKELY_TP}} AND
  'merged_into' is absent (primaries only).
For each such finding, add 'severity: CRITICAL|HIGH|MEDIUM|LOW' to its frontmatter.
Drop findings below severity_filter when writing the report.
Write {output_dir}/REPORT.md — final markdown report grouped by severity.
Return a one-line completion summary.
"""
)
```

### Phase 8: Return Report

```
Read ${output_dir}/REPORT.md → return to caller.
```

Also include a short "Artifacts" section in your reply so the user knows where to find the raw files:
- `${output_dir}/findings/` — individual finding files (updated in-place by judges)
- `${output_dir}/fp-summary.md` — FP-judge summary
- `${output_dir}/dedup-summary.md` — dedup summary
- `${output_dir}/REPORT.md` — severity-filtered final report

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

**Fields added by judges** (via `Edit` on frontmatter):
- FP-judge: `fp_verdict: TRUE_POSITIVE | LIKELY_TP | LIKELY_FP | FALSE_POSITIVE | OUT_OF_SCOPE`, `fp_rationale: <one-line>`
- Dedup-judge (on duplicates): `merged_into: <primary-id>`; (on primaries with merges): `also_known_as: [<id1>, <id2>]`
- Severity-agent: `severity: CRITICAL | HIGH | MEDIUM | LOW`, `attack_vector: Remote | Local`, `exploitability: Reliable | Difficult | Theoretical`

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

Total bug classes covered: ~47 across 7–11 cluster tasks. The individual per-class prompt files remain under `prompts/general/`, `prompts/linux-userspace/`, `prompts/windows-userspace/` and are referenced by the non-consolidated clusters; `buffer-write-sinks.md` is the one fully consolidated cluster and its 13 sub-prompts are not re-read at runtime.

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
