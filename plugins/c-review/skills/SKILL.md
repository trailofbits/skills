---
name: c-review
description: >
  Performs comprehensive C/C++ security review for memory corruption, integer overflows,
  race conditions, and platform-specific vulnerabilities.
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
  - Grep
  - Glob
  - Read
  - Write
  - Bash
---

# C/C++ Security Review

Comprehensive security review of C/C++ codebases. **This skill runs in the main conversation** (invoke via `/c-review:c-review` — no command wrapper, the skill self-collects parameters). The orchestrator uses `TaskCreate`/`TaskUpdate`/`TaskList`/`TaskGet` as **its own** bookkeeping ledger to track which clusters need retry; workers do **not** read or write the ledger and have no Task tools in their tool set. Each worker receives a fully self-contained spawn prompt. Workers and judges are spawned as **named plugin subagents** (`c-review:c-review-worker`, `c-review:c-review-dedup-judge`, `c-review:c-review-fp-judge`) whose tool sets are declared in `plugins/c-review/agents/*.md`; findings are exchanged via **markdown files with YAML frontmatter** in a shared output directory.

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

## Subagents

Workers and judges run as **named plugin subagents** declared in `plugins/c-review/agents/*.md`:

| Subagent type | Purpose | Tool set |
|---|---|---|
| `c-review:c-review-worker` | Run assigned cluster task, write findings | Read, Write, Edit, Grep, Glob, Bash |
| `c-review:c-review-dedup-judge` | Merge duplicates (runs **first**) | Read, Write, Edit, Glob |
| `c-review:c-review-fp-judge` | FP + severity + final reports (runs **second**) | Read, Write, Edit, Grep, Glob, Bash, LSP |

Tools are loaded into the subagent's tool set at spawn time from each agent's frontmatter; no `ToolSearch` bootstrap is required. The orchestrator's own `Task*` and `Agent` tools come from this skill's `allowed-tools`.

---

## Layout Deviation

This skill intentionally does not use the conventional `references/` and `workflows/` subdirectories. Detailed protocols live where the harness already loads them:

- **Subagent system prompts** (`agents/*.md`) are authoritative for the full worker, dedup-judge, and fp-judge protocols (including finding-file schema, FP taxonomy, severity rules, and report templates). They are loaded by the harness when each subagent spawns. The orchestrator's spawn prompt passes only per-run variables, never the protocol body.
- **Cluster prompts** (`prompts/clusters/*.md`, `prompts/{general,linux-userspace,windows-userspace}/*.md`) are read by workers via paths the orchestrator pre-resolves into task metadata. They are not read by the orchestrator.

None of these files chain further references — every link is one hop from its consumer.

---

## Architecture: Assigned Workers + File-Based Handoff

```
Main conversation (coordinator)
├── Writes context.md
├── Runs scripts/build_run_plan.py → emits plan.json + worker-prompts/worker-N.txt
├── Creates one bookkeeping task per worker (orchestrator-internal, for retry tracking)
├── Spawns M workers in ONE message (parallel Agent, subagent_type=c-review:c-review-worker)
│   └── Each worker is given the verbatim contents of worker-prompts/worker-N.txt
│   └── Worker: read context.md → run assigned cluster prompt (multi-pass) → write findings → return one-line summary
├── Classifies each worker reply (Phase 7); retries retryable failures up to 2 attempts; writes findings-index.txt
├── Spawns judges sequentially:
│   ├── Dedup-judge → edits finding frontmatter (merged_into / also_known_as) + dedup-summary.md
│   └── FP+Severity-judge → adds fp_verdict + severity to primaries; writes fp-summary.md, REPORT.md, REPORT.sarif
└── Returns REPORT.md to caller (REPORT.sarif always produced)
```

**Output directory layout:**
```
${output_dir}/
├── context.md             # coordinator writes (threat model, codebase summary)
├── plan.json              # build_run_plan.py writes (Phase 4) — selected clusters, paths
├── worker-prompts/        # build_run_plan.py writes (Phase 4) — one .txt per worker
│   ├── worker-1.txt
│   └── …
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

**Path convention:** skill-internal paths use `${CLAUDE_PLUGIN_ROOT}` (resolved by the harness at spawn time, so the conventional `{baseDir}` placeholder doesn't apply here). At the start of Phase 0, verify it's resolvable via `Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/clusters/buffer-write-sinks.md`. If empty, fall back to `Glob: **/plugins/c-review/prompts/clusters/*.md` and use the discovered plugin root as `${C_REVIEW_PLUGIN_ROOT}`; otherwise set `${C_REVIEW_PLUGIN_ROOT}=${CLAUDE_PLUGIN_ROOT}`.

---

## Orchestration Workflow

Run these phases **in the main conversation**.

### Phase 0: Parameter Collection

**Entry:** skill invoked. **Exit:** `threat_model`, `worker_model`, `severity_filter` resolved; `scope_subpath` resolved or set to `"."`.

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

**Entry:** Phase 0 complete. **Exit:** `is_cpp`, `is_posix`, `is_windows` flags determined.

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

**Entry:** Phase 1 flags set. **Exit:** absolute `output_dir` resolved; `${output_dir}/findings/` exists.

Resolve an absolute path for `output_dir` (default: `$(pwd)/.c-review-results/$(date -u +%Y%m%dT%H%M%SZ)/`):

```bash
mkdir -p "${output_dir}/findings"
```

### Phase 3: Codebase Context

**Entry:** `${output_dir}` exists. **Exit:** `${output_dir}/context.md` written with frontmatter parameters and codebase summary.

Gather a short summary using dedicated tools (do not shell out for file inspection):

```
Glob: pattern="README.{md,rst,txt}"
Read: <first match, limit=50>     # skip Read entirely if Glob returned no matches
Glob: pattern="{Makefile,CMakeLists.txt,meson.build,configure.ac}"
```

`Read` on a missing file aborts the turn — always preflight with `Glob`. The presence of a build file is informational only — it tells you what the build system is, not whether to continue.

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

### Phase 4: Build Run Plan (deterministic)

**Entry:** language flags + `threat_model` known; `${output_dir}/findings/` exists. **Exit:** `${output_dir}/plan.json` and `${output_dir}/worker-prompts/worker-N.txt` files written; `M = worker_count` known.

Cluster selection, pass filtering, prompt-path resolution, and spawn-prompt rendering are **delegated to a script** rather than reconstructed by the orchestrator. This is the change that prevents the "orchestrator paraphrases the spawn template and drops fields" failure mode.

```bash
python3 "${C_REVIEW_PLUGIN_ROOT}/scripts/build_run_plan.py" \
  --plugin-root "${C_REVIEW_PLUGIN_ROOT}" \
  --output-dir  "${output_dir}" \
  --threat-model "${threat_model}" \
  --severity-filter "${severity_filter}" \
  --scope-subpath "${scope_subpath:-.}" \
  --is-cpp "${is_cpp}" --is-posix "${is_posix}" --is-windows "${is_windows}"
```

The script:
- reads `prompts/clusters/manifest.json` and applies the selection rules (gate `always`/`is_cpp`/`is_windows`; per-pass `requires`; per-pass `skip_threat_models`),
- resolves every cluster prompt and per-pass prompt to an absolute path and verifies it exists (exits non-zero if any are missing — surface the message and stop the review),
- writes `${output_dir}/plan.json` (machine-readable selection),
- writes `${output_dir}/worker-prompts/worker-1.txt` … `worker-M.txt` (ready-to-paste spawn prompts),
- prints a JSON summary (`worker_count`, `cluster_ids`, `plan_path`, `worker_prompts_dir`) on stdout.

Selection rules (applied by the script — listed here only so reviewers can audit the script's behavior, not for the orchestrator to re-implement):

- Cluster `gate`: `always` always selected; `is_cpp` selected iff `is_cpp == true`; `is_windows` selected iff `is_windows == true`.
- Per-pass: hard-drop if any flag in `requires` is `false`, or if active `threat_model` is in `skip_threat_models`.
- If a non-consolidated cluster has zero remaining passes after filtering, drop the cluster entirely.
- If zero clusters remain after filtering, the script exits non-zero — refusing to start an empty review.

Typical counts: 7 (pure C POSIX), 8 (C++ POSIX), 10 (C POSIX + Windows), 11 (C++ POSIX + Windows).

After the script returns, `Read: ${output_dir}/plan.json` to access the structured selection. The orchestrator should never re-implement filtering or path resolution — `plan.json` and the per-worker prompt files are the single source of truth for the rest of the run.

### Phase 5: Create Bookkeeping Tasks (orchestrator-internal)

**Entry:** `${output_dir}/plan.json` exists; `M = plan.workers.length`. **Exit:** `cluster_task_ids[]` created (1:1 with `plan.workers`), all `pending`.

The task ledger is **orchestrator bookkeeping only** — workers never read or write it. Its sole purposes are TUI visibility and Phase-7 retry tracking. One task per worker:

```
TaskCreate(
  subject="cluster-<plan.workers[i].cluster_id>",
  description="<cluster_id>: <len(pass_bug_classes)> bug classes",
  activeForm="Running cluster <cluster_id>",
  metadata={
    "kind": "cluster",
    "worker_n": <plan.workers[i].worker_n>,
    "cluster_id": "<plan.workers[i].cluster_id>",
    "spawn_prompt_path": "<plan.workers[i].spawn_prompt_path>",
    "pass_prefixes": <plan.workers[i].pass_prefixes>,
    "attempt": 1
  }
)
```

Read all values from `plan.json` — do not paraphrase or recompute them. Track `cluster_task_ids[]` in `plan.workers` order.

### Phase 6: Spawn M Workers in ONE Message

**Entry:** `cluster_task_ids[]` populated; per-worker spawn prompt files exist at `${output_dir}/worker-prompts/worker-N.txt`. **Exit:** all M `Agent` calls have returned (the parallel spawn block completed).

**CRITICAL:** emit a single assistant message containing M `Agent` tool invocations so they run in parallel. Sequential spawning serializes the review.

For each worker `N ∈ [1..M]`:

1. `Read: ${output_dir}/worker-prompts/worker-N.txt`
2. Pass the file contents **verbatim** as the `Agent` tool's `prompt` argument:

| Parameter | Value |
|-----------|-------|
| `subagent_type` | `c-review:c-review-worker` |
| `model` | `${worker_model}` (haiku / sonnet / opus) |
| `description` | `C review worker N` |
| `prompt` | the full text of `worker-N.txt` (no edits) |

The spawn prompt was rendered by `build_run_plan.py` in Phase 4 — it is the single authority. Do not paraphrase it, do not "simplify" it, do not insert additional instructions, do not strip "redundant"-looking fields. Every field is required by the worker's self-check; any deviation triggers `worker-N abort: spawn prompt malformed`.

**Anti-patterns to reject** (these are the failures the script-driven design exists to prevent):

- ❌ Hand-typing the spawn prompt instead of reading `worker-N.txt`. The orchestrator has drifted toward a TaskList-driven shape before; the file is the antidote.
- ❌ Inserting "Your first tool call must be TaskList" or "Assigned cluster task id: <N>". Workers have no Task tools.
- ❌ Editing the rendered prompt before passing it to `Agent` (e.g. trimming the codebase line, collapsing pass lists). Pass it verbatim.

The block before `— assignment —` is byte-identical across all M workers — the API caches it, so workers 2..M pay a fraction of the base cost. The worker's full protocol and finding-file schema live in its system prompt (`plugins/c-review/agents/c-review-worker.md`), which is also cached across spawns.

### Phase 7: Wait for Workers and Classify Outcomes

**Entry:** all M Phase-6 `Agent` calls have returned. **Exit:** every cluster has either succeeded or been retried up to the cap; `${output_dir}/findings-index.txt` written.

The Phase-6 `Agent` invocations block until each worker returns. Inspect each worker's return text and apply this classifier in order — first match wins:

| # | Match (in return text) | Outcome | Action |
|---|---|---|---|
| 1 | contains `worker-N complete:` | **success** | `TaskUpdate` cluster task to `completed`. |
| 2 | contains `abort: spawn prompt malformed` | **non-retryable orchestrator bug** | Stop the run, surface the abort text, do **not** retry. The script-rendered prompt is malformed or the orchestrator paraphrased it — re-running with the same prompt repeats the failure. |
| 3 | contains `abort: TaskList unavailable` (legacy) | **non-retryable orchestrator bug** | Same as #2. This means the orchestrator regressed to a pre-script spawn shape; fix the orchestrator, not the worker. |
| 4 | contains `worker-N abort:` (any other reason) | **retryable failure** | Mark task `pending`, set `metadata.abort_reason`, `metadata.needs_respawn=true`, increment `metadata.attempt`. |
| 5 | the `Agent` call errored, or no `complete:` / `abort:` token present | **retryable failure** | Same as #4 (treat as a transient worker crash). |

After classifying all M outcomes:

- If any task is in **non-retryable** state (#2 or #3), stop the review and surface the abort text plus the spawn prompt path (`${output_dir}/worker-prompts/worker-N.txt`) so the user can inspect what the script produced. Do not run Phase 8.
- Otherwise, for each `pending` (retryable) task with `attempt < 2`, spawn a replacement in **one parallel `Agent` block** (same Phase-6 mechanic: `Read worker-N.txt`, pass verbatim). Cap retries at **2 attempts per cluster** — after the second failure, leave the task `pending` and continue. Replacement workers may overwrite finding files the failed worker partially wrote; that's acceptable because IDs are deterministic per cluster prefix and writes are idempotent in content.

#### Sanity-check finding output before judges

For every cluster that returned `complete:`, confirm the on-disk output is consistent with the return text using the cluster's `pass_prefixes` (from `plan.json`):

```bash
for prefix in "${pass_prefixes[@]}"; do
  ls "${output_dir}/findings/${prefix}"-*.md 2>/dev/null
done
```

- "complete: wrote 0 finding files" + zero matching files → **fine** (a clean zero-finding cluster).
- "complete: wrote N finding files" with N>0 + zero matching files → **suspicious**: the worker invented a return string. Treat as a retryable failure (classifier row #4).
- Any orphan files matching a cluster's prefix when the cluster aborted → leave them in place; the dedup/fp judges still process whatever exists.

This check is a defense-in-depth signal, not authoritative — but the inconsistency was missed in past runs and warrants surfacing.

#### Write the findings index

Always write a deterministic manifest of finding files before spawning judges. This gives judges a `Glob`-independent fallback path (the dedup-judge has only `Read/Write/Edit/Glob` — no `Bash`):

```bash
find "${output_dir}/findings" -maxdepth 1 -type f -name '*.md' 2>/dev/null \
  | sort > "${output_dir}/findings-index.txt"
```

`find` returns an empty stream (not an error) when the directory has no matches, so the resulting file is empty — which is the unambiguous "zero findings" signal. One absolute path per line, sorted lexicographically for reproducibility.

**Even if zero findings**, still run Phase 8 — the fp-judge protocol writes empty-results `REPORT.md` and `REPORT.sarif` so callers always get the same artifact set. Skipping Phase 8 here would silently break SARIF-consuming CI. The only adjustment for zero findings: dedup-judge can be skipped when `findings-index.txt` is empty; fp-judge tolerates a missing `dedup-summary.md` only for an empty finding set.

### Phase 8: Judge Pipeline (sequential, dedup → fp+severity)

**Entry:** `findings-index.txt` exists. **Exit:** dedup-judge has returned (skipped only when `findings-index.txt` is empty) and fp-judge has returned; `dedup-summary.md` (when applicable), `fp-summary.md`, `REPORT.md`, and ideally `REPORT.sarif` are written.

Each judge's full protocol is its system prompt (`agents/c-review-{dedup,fp}-judge.md`) — loaded by the harness at spawn. Your spawn prompt passes only per-run variables; do not paste the protocol or restate it.

Dedup runs first on the raw worker output so the FP judge only ever sees merged primaries — one analysis per underlying bug.

**Dedup-judge** (runs first):
```
Agent(
  subagent_type="c-review:c-review-dedup-judge",
  description="Dedup judge",
  prompt=f"output_dir: {output_dir}"
)
```

**FP + Severity judge** (after Dedup completes):
```
Agent(
  subagent_type="c-review:c-review-fp-judge",
  description="FP + severity judge",
  prompt=f"""output_dir: {output_dir}
sarif_generator_path: {sarif_generator_path}"""
)
```

Resolve `sarif_generator_path` to an absolute path under `${C_REVIEW_PLUGIN_ROOT}/scripts/generate_sarif.py` before spawning.

### Phase 8b: SARIF safety net

**Entry:** fp-judge returned, OR the run gave up early (e.g., a cluster exhausted its retry cap and fp-judge was skipped). **Exit:** `${output_dir}/REPORT.sarif` exists.

Verify `${output_dir}/REPORT.sarif` exists. If it is missing — because the fp-judge errored, was skipped, or the run aborted before Phase 8 — run the generator yourself so CI consumers always get the file:

```bash
test -f "${output_dir}/REPORT.sarif" || \
  python3 "<absolute path to scripts/generate_sarif.py>" "${output_dir}"
```

The generator is idempotent and reads only finding frontmatter + `context.md`; it produces `results: []` for zero-survivor runs and gracefully handles the partial-run case (some findings have `fp_verdict`, others don't — those without verdicts are emitted as `LIKELY_TP` so they don't silently disappear).

**Run Phase 8b unconditionally — even on partial / aborted runs.** A partial run with 6 findings on disk should still produce a SARIF over those 6, not nothing. The only exception is if `${output_dir}/findings/` itself doesn't exist (Phase 2 failed).

### Phase 9: Return Report

**Entry:** `REPORT.md` and `REPORT.sarif` exist. **Exit:** `REPORT.md` content + Artifacts list returned to the caller.

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

Each finding is a markdown file with YAML frontmatter at `${output_dir}/findings/<id>.md` (e.g. `BOF-001.md`). **The authoritative schema lives in the worker agent's system prompt at `plugins/c-review/agents/c-review-worker.md` ("Finding File Format" / "Body structure"); do not duplicate it here.**

Frontmatter is written in three stages:

1. **Worker** writes the initial file with: `id`, `bug_class`, `title`, `location`, `function`, `confidence`, `worker`, plus the seven body sections (Description, Code, Data flow, Reachability trace, Impact, Mitigations checked, Recommendation).
2. **Dedup-judge** edits frontmatter only — adds `merged_into: <primary-id>` on duplicates, or `also_known_as: [...]` + `locations: [...]` on primaries that absorbed duplicates.
3. **FP+Severity judge** edits frontmatter only — adds `fp_verdict` + `fp_rationale` on every primary; for survivors (`TRUE_POSITIVE` / `LIKELY_TP`) also adds `severity`, `attack_vector`, `exploitability`, `severity_rationale`.

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

---

## Reference Index

| File | Purpose |
|------|---------|
| `agents/c-review-worker.md` | Worker subagent — authoritative finding-file schema and per-cluster protocol |
| `agents/c-review-dedup-judge.md` | Dedup-judge subagent — full Tier-1/Tier-2 dedup protocol |
| `agents/c-review-fp-judge.md` | FP+severity-judge subagent — full FP taxonomy, severity rules, REPORT.md/REPORT.sarif templates |
| `prompts/clusters/manifest.json` | Authoritative cluster gates, pass ordering, prefixes, per-class prompt paths |
| `prompts/clusters/*.md` | Per-cluster shared-context preambles (one per worker) |
| `prompts/{general,linux-userspace,windows-userspace}/*.md` | Per-bug-class finder prompts (read by workers per pass) |
| `scripts/build_run_plan.py` | Reads manifest + run flags → emits plan.json and worker-prompts/worker-N.txt (Phase 4) |
| `scripts/generate_sarif.py` | SARIF 2.1.0 generator from finding frontmatter |

---

## Success Criteria

A run is complete and correct when all of the following hold:

- [ ] `${output_dir}/context.md` exists with frontmatter parameters and codebase summary
- [ ] `${output_dir}/plan.json` exists with `version: 1` and `len(workers) >= 1`
- [ ] Every cluster task created in Phase 5 has `status="completed"` (verify via `TaskList`)
- [ ] `${output_dir}/findings-index.txt` exists (an empty file is the unambiguous "zero findings" signal, not an error)
- [ ] `${output_dir}/dedup-summary.md` exists when `findings-index.txt` is non-empty
- [ ] `${output_dir}/fp-summary.md` exists with verdict counts
- [ ] Every primary finding (no `merged_into` in frontmatter) has `fp_verdict` and `fp_rationale`
- [ ] Every survivor (`fp_verdict ∈ {TRUE_POSITIVE, LIKELY_TP}`) has `severity`, `attack_vector`, `exploitability`, `severity_rationale`
- [ ] `${output_dir}/REPORT.md` exists, severity-filtered per `severity_filter`
- [ ] `${output_dir}/REPORT.sarif` exists (Phase 8b safety net guarantees this even if the fp-judge errored)
