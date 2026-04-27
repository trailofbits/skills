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
│   └── N cluster tasks (metadata.kind="cluster", prompt_path/pass order from prompts/clusters/manifest.json)
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
└── REPORT.sarif           # generated by scripts/generate_sarif.py (SARIF 2.1.0, always produced)
```

**Path convention:** file paths below use `${CLAUDE_PLUGIN_ROOT}` for skill-internal files. Verify it's resolvable at the start of Phase 0:
```
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/clusters/buffer-write-sinks.md
```
If empty, fall back to `Glob: **/plugins/c-review/prompts/clusters/*.md` and use the discovered plugin root as `${C_REVIEW_PLUGIN_ROOT}`. Otherwise set `${C_REVIEW_PLUGIN_ROOT}=${CLAUDE_PLUGIN_ROOT}`.

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

Instead of 45+ individual finder prompts, the coordinator creates **one task per cluster**. The authoritative cluster/pass ordering lives in:

```
Read: ${C_REVIEW_PLUGIN_ROOT}/prompts/clusters/manifest.json
```

Use the manifest for cluster order, prompt paths, gate conditions, pass ordering, per-class prompt paths, prefixes, and `skip_threat_models`. Do not hand-maintain a separate pass-order table in the skill.

Selection rules:
- Include clusters with `"gate": "always"`.
- Include `"gate": "is_cpp"` only when `is_cpp == true`.
- Include `"gate": "is_windows"` only when `is_windows == true`.
- For each selected cluster, build the active pass list by **dropping** every pass for which:
  - `requires` is present and any flag in `requires` (e.g. `is_posix`) is `false` in the codebase context, **or**
  - `skip_threat_models` is present and contains the active `threat_model` (e.g. `privilege-drop`/`envvar` under `REMOTE`).
- After filtering, if a non-consolidated cluster has zero remaining passes, drop the cluster entirely (don't spawn a worker for an empty cluster).

The orchestrator hard-skips dropped passes — they never appear in the cluster task's `sub_prompt_paths`. This is authoritative: the worker does not re-derive applicability from `is_posix`/`is_windows` for these passes.

Result is `selected_clusters[]` in manifest order — 7 always-on clusters (some passes may be filtered) plus optional C++ and Windows clusters. Typical counts: 7 (pure C POSIX), 8 (C++ POSIX), 10 (C POSIX + Windows), 11 (C++ POSIX + Windows). On a Windows-only codebase (`is_posix=false`), the always-on `concurrency`, `syscall-retval`, and `static-hygiene` clusters keep only their portable passes.

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
    "prompt_path": "<absolute path resolved from manifest cluster.prompt>",
    "sub_prompt_paths": [
      # Pre-resolved absolute paths, aligned 1:1 with the Pass order in the
      # manifest. Empty list for consolidated clusters
      # (buffer-write-sinks — the cluster file is self-sufficient).
      "<abs path from passes[0].prompt>",
      "<abs path from passes[1].prompt>",
      ...
    ],
    "pass_bug_classes": ["<passes[0].bug_class>", "<passes[1].bug_class>", ...],
    "pass_prefixes": ["<passes[0].prefix>", "<passes[1].prefix>", ...],
    "context_task_id": "<id>",
    "skip_subclasses": []      # derived from pass.skip_threat_models for the active threat_model
  }
)
```

Track `cluster_task_ids[]` in the same order as `selected_clusters[]`. Tasks start as `pending`.

Before creating tasks, verify every manifest-referenced `cluster.prompt` and non-consolidated pass `prompt` exists. If any path is missing, stop and surface the missing path instead of starting a partial review.

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

Worker prompt template — **the user prompt is structured as a long stable prefix shared by every worker, followed by a short variable suffix**, so prompt caching covers both the system prompt AND most of the user prompt:

```
You are a c-review worker on a parallel C/C++ security review.
Follow the protocol in your system prompt verbatim. Your first tool call must be TaskList.

Context task id: <context_task_id>
Output directory: <absolute output_dir>
Scope root: <scope_subpath or "."> — all Grep/Glob queries MUST be rooted here; findings outside this subtree are out-of-scope.

— assignment —
Worker id: worker-N
Assigned cluster task id: <cluster_task_ids[N-1]>
```

The first block (greeting + context_task_id + output_dir + scope_root) is **byte-identical across all M workers** in the same run, so the API caches it and workers 2..M read that cache at a fraction of base cost. Only the trailing two lines after `— assignment —` vary per worker. The worker's full protocol and finding-file schema live in its system prompt (`plugins/c-review/agents/c-review-worker.md`), which is ~5–6K tokens of stable content that the API also caches across all M parallel spawns. Keep the variable suffix short to preserve the cacheable prefix.

**Do not pass raw `${CLAUDE_PLUGIN_ROOT}` into the subagent prompt** — the worker doesn't need it; the assigned cluster prompt path is in the task metadata and the worker reads it via `TaskGet` + `Read`.

### Phase 7: Wait for Workers

The Phase-6 `Agent` invocations block until each worker returns, so by the time control returns to the coordinator every spawned worker has already exited. Once they have all returned, call `TaskList` **once** and verify each cluster task is `completed`. If any cluster task is still `in_progress` (worker exited without `TaskUpdate(status=completed)`), the worker died mid-run — reset the task to `pending` via `TaskUpdate` and spawn a single replacement worker bound to the same `assigned_cluster_task_id`. The replacement may overwrite finding files the dead worker partially wrote; that is acceptable because IDs are deterministic per cluster prefix and writes are idempotent in content.

**Write a deterministic manifest** of finding files before spawning judges. This gives judges a `Glob`-independent fallback path (the dedup-judge has only `Read/Write/Edit/Glob` — no `Bash`):

```bash
find "${output_dir}/findings" -maxdepth 1 -type f -name '*.md' 2>/dev/null \
  | sort > "${output_dir}/findings-index.txt"
```

`find` returns an empty stream (not an error) when the directory has no matches, so the resulting file is empty — which is the unambiguous "zero findings" signal. One absolute path per line, sorted lexicographically for reproducibility.

**Even if zero findings**, still run Phase 8 — the fp-judge protocol writes empty-results `REPORT.md` and `REPORT.sarif` so callers always get the same artifact set. Skipping Phase 8 here would silently break SARIF-consuming CI. The only adjustment for zero findings: dedup-judge can be skipped when `findings-index.txt` is empty; fp-judge tolerates a missing `dedup-summary.md` only for an empty finding set.

### Phase 8: Judge Pipeline (sequential, dedup → fp+severity)

Each judge runs as a named plugin subagent with its tool set declared in the agent frontmatter. **Always pass absolute paths to judge protocol files and `scripts/generate_sarif.py`** — resolve them from `${C_REVIEW_PLUGIN_ROOT}` before spawning. Judges open protocol files with `Read`; they do not invoke `Skill(...)`.

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
SARIF generator path: <absolute path to scripts/generate_sarif.py>

Read {output_dir}/context.md for threat model and severity_filter.
If {output_dir}/dedup-summary.md does not exist, check {output_dir}/findings-index.txt.
If the manifest is empty, this is a zero-findings run: produce empty REPORT.md / REPORT.sarif.
If the manifest is non-empty, continue by treating every non-merged finding as a primary and add a prominent note to fp-summary.md and REPORT.md that dedup did not run.
Process only PRIMARIES — findings whose frontmatter has no 'merged_into' field.
For each primary: add fp_verdict + fp_rationale. For survivors (TRUE_POSITIVE / LIKELY_TP) also add
  severity, attack_vector, exploitability, severity_rationale.
Write {output_dir}/fp-summary.md with verdict counts.
Write {output_dir}/REPORT.md — severity-filtered markdown report.
Run python3 <absolute path to scripts/generate_sarif.py> {output_dir} after REPORT.md is written.
This writes {output_dir}/REPORT.sarif from finding frontmatter; do not hand-write SARIF JSON.
Return a one-line completion summary.
"""
)
```

### Phase 8b: SARIF safety net

After the fp-judge agent returns, verify `${output_dir}/REPORT.sarif` exists. If it is missing — because the fp-judge errored before invoking the generator — run it from the orchestrator yourself so CI consumers always get the file:

```bash
test -f "${output_dir}/REPORT.sarif" || \
  python3 "<absolute path to scripts/generate_sarif.py>" "${output_dir}"
```

The generator is idempotent and reads only finding frontmatter + `context.md`; it produces `results: []` for zero-survivor runs.

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

## Reachability trace
<short call chain from entry point to sink>

## Impact
<what an attacker could achieve>

## Mitigations checked
<canary / ASLR / FORTIFY_SOURCE / sanitizer / type bound — present/absent, bypassable?>

## Recommendation
<how to fix>
```

The worker's system prompt is authoritative for the body schema (`plugins/c-review/agents/c-review-worker.md` — "Body structure"); keep this template in sync with it.

**Fields added by judges** (via `Edit` on frontmatter). Pipeline order: dedup → fp+severity.
- Dedup-judge (on duplicates): `merged_into: <primary-id>`; (on primaries with merges): `also_known_as: [<id1>, <id2>]`, `locations: [<path:line>, …]`
- FP+Severity judge (on every primary): `fp_verdict: TRUE_POSITIVE | LIKELY_TP | LIKELY_FP | FALSE_POSITIVE | OUT_OF_SCOPE`, `fp_rationale: <one-line>`
- FP+Severity judge (on survivors — TRUE_POSITIVE / LIKELY_TP only): `severity: CRITICAL | HIGH | MEDIUM | LOW`, `attack_vector: Remote | Local | Both`, `exploitability: Reliable | Difficult | Theoretical`, `severity_rationale: <one-line>`

---

## Bug Classes → Clusters

The authoritative list of clusters, gates, pass order, bug classes, prefixes, and per-class prompt paths is `prompts/clusters/manifest.json`. Bug classes covered: 47 always-on, up to 64 with all conditional clusters enabled. `buffer-write-sinks.md` is fully consolidated (its 13 sub-prompts are not re-read at runtime).

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
