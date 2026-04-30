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

Runs in the main conversation (invoke via `/c-review:c-review`). Orchestrator owns the `Task*` ledger as bookkeeping for retries; workers and judges have no Task tools. Workers and judges are named plugin subagents (`c-review:c-review-worker`, `c-review:c-review-dedup-judge`, `c-review:c-review-fp-judge`); tool sets are declared in `plugins/c-review/agents/*.md`. Findings are exchanged via markdown-with-YAML files in a shared output directory.

## Scope

**Use for:** native C/C++ application security review (memory safety, integer overflow, races, type confusion, Linux/macOS daemons, Windows userspace services).

**Not for:** kernel drivers/modules, managed languages, embedded/bare-metal without libc.

## Subagents

| Subagent type | Purpose | Tool set |
|---|---|---|
| `c-review:c-review-worker` | Run assigned cluster, write findings | Read, Write, Edit, Grep, Glob, Bash |
| `c-review:c-review-dedup-judge` | Merge duplicates (runs **first**) | Read, Write, Edit, Glob |
| `c-review:c-review-fp-judge` | FP + severity + final reports (runs **second**) | Read, Write, Edit, Grep, Glob, Bash |

Tools come from each agent's frontmatter at spawn time. The orchestrator's `Task*`/`Agent`/`Bash`/etc. come from this skill's `allowed-tools`.

---

## Architecture

```
coordinator: write context.md → build_run_plan.py → TaskCreate × M
          → spawn primer (foreground) → spawn M workers (parallel)
          → classify Phase-7 outcomes + write findings-index.txt
          → dedup-judge → fp-judge → SARIF safety net → return REPORT.md
```

Output directory contains: `context.md`, `plan.json`, `worker-prompts/`, `findings/`, `findings-index.d/` (per-worker shards), `findings-index.txt`, `run-summary.md`, `dedup-summary.md` (omitted on zero-findings), `fp-summary.md`, `REPORT.md`, `REPORT.sarif`.

**Path convention:** set `${C_REVIEW_PLUGIN_ROOT}=${CLAUDE_PLUGIN_ROOT}` if that resolves (`Bash: ls "${CLAUDE_PLUGIN_ROOT}/prompts/clusters/buffer-write-sinks.md"`), otherwise `Bash: find ~/.claude -path '*/plugins/c-review/prompts/clusters/buffer-write-sinks.md' -print -quit`.

**Scope convention:** keep two scopes separate throughout the run:

- `finding_scope_root` — the user-requested audit subtree. Workers may only file findings whose vulnerable location is inside this subtree.
- `context_roots` — read-only repo roots/files workers and judges may inspect to verify reachability, callers, wrappers, build flags, mitigations, and threat-model details. Default to `.` unless the user explicitly forbids broader context. Reading context outside `finding_scope_root` is allowed; filing findings there is not.

---

## Orchestration Workflow

Run these phases **in the main conversation**.

### Phase 0: Parameter Collection

**Entry:** skill invoked. **Exit:** `threat_model`, `worker_model`, `severity_filter` resolved; `scope_subpath` resolved or set to `"."`; `finding_scope_root=scope_subpath`; `context_roots` resolved.

The skill is invoked directly (no command wrapper). Parse any free-text arguments the user passed on the `/c-review:c-review` line (e.g. `flamenco only`, `high severity only`, `use haiku`) and pre-fill the answers they imply — then ask for any missing required parameters with **one** `AskUserQuestion` call. Never silently default the required parameters.

Required parameters:

| Parameter | Values | How to infer from args |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | Words like "remote", "network", "attacker" → `REMOTE`; "local", "unprivileged" → `LOCAL_UNPRIVILEGED`; otherwise ask. |
| `worker_model` | `haiku` / `sonnet` / `opus` | Explicit model name in args. Otherwise ask (no silent default). |
| `severity_filter` | `all` / `medium` / `high` | "all", "every", "noisy" → `all`; "medium and above" → `medium`; "high only", "criticals only" → `high`. Otherwise ask — **no silent default**. |
| `scope_subpath` | repo-relative directory (optional) | Phrases like "X only", "just audit X/", "review subdirectory X" → `src/X/` or the matching subdir. Apply fuzzy matching against top-level subdirectories of the repo. If absent, set `"."`; if ambiguous, ask. |

Call `AskUserQuestion` exactly once with only unresolved required parameters (`threat_model`, `worker_model`, `severity_filter`) plus `scope_subpath` only when the user explicitly requested a narrowed scope but it is ambiguous. If the required parameters were all pre-filled and scope is absent or resolved, skip the question.

After resolving `scope_subpath`, set `finding_scope_root="${scope_subpath:-.}"`. Set `context_roots="."` by default so workers can verify callers/build settings outside a narrowed subtree without filing out-of-scope findings. If the user explicitly asks to forbid broader context, set `context_roots="${finding_scope_root}"` and note that reachability confidence may be lower.

### Phase 1: Prerequisites

**Entry:** Phase 0 complete. **Exit:** `is_cpp`, `is_posix`, `is_windows` flags determined.

Probe within `${finding_scope_root:-.}`. Prefer `Glob`/`Grep` when available in the orchestrator's tool set; some sessions only expose `Bash`, so fall back to the equivalents below — both forms produce identical signals (non-empty output ⇒ flag true):

```bash
# is_cpp
find "${finding_scope_root:-.}" -type f \( -name '*.cpp' -o -name '*.cxx' -o -name '*.cc' -o -name '*.hpp' -o -name '*.hh' \) -print -quit
# is_posix
grep -rlE '#include[[:space:]]*<(pthread|signal|sys/(socket|stat|types|wait)|unistd|errno)\.h>' --include='*.c' --include='*.h' "${finding_scope_root:-.}" | head -1
# is_windows
grep -rlE '#include[[:space:]]*<(windows|winbase|winnt|winuser|winsock|ntdef|ntstatus)\.h>' --include='*.c' --include='*.h' "${finding_scope_root:-.}" | head -1
```

`compile_commands.json` is informational (no agent currently uses LSP), but the probe is mandatory so the run summary records whether richer local tooling is available. Probe via `Glob: **/compile_commands.json` under `${context_roots}`. If `Glob` is unavailable, use:

```bash
printf '%s\n' "${context_roots:-.}" | tr ',' '\n' | while IFS= read -r root; do
  [ -n "$root" ] && find "$root" -name compile_commands.json -print -quit
done | head -1
# `find "$root"` is quoted intentionally so a context root containing spaces
# (e.g. "/Users/me/My Repo") survives word-splitting. Do not unquote it.
```

If absent, suggest CMake `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`/Bear/compiledb to the user but continue.

### Phase 2: Output Directory

**Entry:** Phase 1 flags set. **Exit:** absolute `output_dir` resolved; `${output_dir}/findings/` exists.

Resolve an absolute path for `output_dir` (default: `$(pwd)/.c-review-results/$(date -u +%Y%m%dT%H%M%SZ)/`):

```bash
mkdir -p "${output_dir}/findings"
```

### Phase 3: Codebase Context

**Entry:** `${output_dir}` exists. **Exit:** `${output_dir}/context.md` written.

Skim `README.{md,rst,txt}` and any build file (`Makefile`, `CMakeLists.txt`, `meson.build`, `configure.ac`) — preflight with the `Glob` tool before any `Read` (a `Read` on a missing file aborts the turn). Do **not** use `Bash: ls README*` for the preflight: under zsh, an unmatched glob aborts the whole compound command before `2>/dev/null` runs (observed: a Phase-3 `ls src/X/README*` call failed with `no matches found` and dropped the entire preflight). If you must use `Bash`, use `find . -maxdepth 2 -name 'README*' -o -name 'Makefile' -o -name 'CMakeLists.txt' -o -name 'meson.build'`, which never fails on no-match.

Write `${output_dir}/context.md` with: YAML frontmatter (`threat_model`, `severity_filter`, `scope_subpath`, `finding_scope_root`, `context_roots`, `is_cpp`, `is_posix`, `is_windows`, `output_dir`, `compile_commands` as `present`/`absent` plus path when present), then a short markdown body with five sections — **Purpose** (1-3 sentences), **Scope** (what's in `finding_scope_root`, and that findings outside it are out of scope), **Entry points** (where untrusted data enters: network, files, CLI, IPC), **Trust boundaries** (sandboxed vs trusted peers vs arbitrary remote), **Existing hardening** (fuzzing corpora, sanitizers, privilege separation).

### Phase 4: Build Run Plan (deterministic)

**Entry:** language flags + `threat_model` known; `${output_dir}/findings/` exists. **Exit:** `${output_dir}/plan.json` and `${output_dir}/worker-prompts/*.txt` written; `M = worker_count` known.

Selection, filtering, path resolution, and spawn-prompt rendering are **delegated to the script** to prevent the "orchestrator paraphrases the spawn template and drops fields" failure mode:

```bash
python3 "${C_REVIEW_PLUGIN_ROOT}/scripts/build_run_plan.py" \
  --plugin-root "${C_REVIEW_PLUGIN_ROOT}" --output-dir "${output_dir}" \
  --threat-model "${threat_model}" --severity-filter "${severity_filter}" \
  --scope-subpath "${finding_scope_root:-.}" --context-roots "${context_roots:-.}" \
  --is-cpp "${is_cpp}" --is-posix "${is_posix}" --is-windows "${is_windows}"
```

The script writes `plan.json` + `worker-prompts/worker-N.txt` + (if `--cache-primer=true`, the default) `worker-prompts/cache-primer.txt`, and prints a JSON summary on stdout. Exits non-zero on any missing prompt — surface the message and stop. Typical M: 7 (C POSIX), 8 (C++ POSIX), 10 (C POSIX + Windows), 11 (C++ POSIX + Windows). After it returns, `Read plan.json` for the structured selection — never re-derive filtering or paths.

### Phase 5: Create Bookkeeping Tasks (orchestrator-internal)

**Entry:** `${output_dir}/plan.json` exists; `M = plan.workers.length`. **Exit:** `cluster_task_ids[]` created (1:1 with `plan.workers`), all `pending`.

The task ledger is **orchestrator bookkeeping only** (TUI visibility + Phase-7 retry tracking) — workers never read or write it. One `TaskCreate` per worker, populating `metadata` with `kind="cluster"`, `worker_n`, `cluster_id`, `spawn_prompt_path`, `pass_prefixes`, `attempt=1` — all values copied verbatim from `plan.workers[i]`. Track `cluster_task_ids[]` in `plan.workers` order.

### Phase 6: Spawn workers (optional cache-primer first, then M in parallel)

**Entry:** `cluster_task_ids[]` populated; per-worker spawn prompt files exist at `${output_dir}/worker-prompts/worker-N.txt`. **Exit:** all M `Agent` calls have returned (the parallel spawn block completed).

#### Phase 6a: Cache primer (gated on `plan.run.cache_primer`)

A parallel batch from cold start cannot share cache (all M requests dispatch simultaneously, none has finished writing). To warm the prefix, spawn a tiny primer first — **foreground** (background spawns don't share cache with subsequent foreground spawns).

If `plan.run.cache_primer == true`, `build_run_plan.py` has written `${output_dir}/worker-prompts/cache-primer.txt`. Spawn it in its own assistant message: `Read` the file, pass verbatim as `Agent` `prompt` with `subagent_type=c-review:c-review-worker`, `model=${worker_model}`, `description="C review cache primer"`, no `run_in_background`. The script wrote the prefix byte-identical to `worker-1.txt` through the `<context>` block — that byte-identity is what gives the parallel workers their cache hit. The primer trailer contains `Cache primer: true`, which the worker system prompt treats as a first-class mode and returns exactly `worker-PRIMER abort: cache primer (no analysis performed)` in one text response with zero tool calls. Discard the abort line — Phase 7 ignores it (no `worker-N` id).

Foreground spawn already serializes — no `sleep` needed before Phase 6c. Skip Phase 6a entirely if `plan.run.cache_primer == false`.

#### Phase 6c: Spawn M real workers in ONE message

> **🚨 STOP — read this before composing the spawn message.**
>
> Workers MUST be spawned **foreground** (no `run_in_background` field, or `run_in_background=false`).
> "Parallel" here means *one assistant message containing M `Agent` calls* — that already runs them concurrently. **Background spawns are NOT how you parallelize this skill.**
>
> Background spawns defeat Phase 6a's primer cache: every worker pays full cache-creation on its first turn (`cache_read_input_tokens=0`), and the primer's ~15 K tokens are wasted M times over. Two real runs (audit logs available) had exactly this symptom — every worker started with `first_cr=0`.
>
> Before sending the spawn message, audit your draft: every `Agent` call must have **no** `run_in_background` key. If you wrote `run_in_background=true`, delete it.

**Required spawn shape:** emit a single assistant message containing M `Agent` tool invocations. Sequential spawning serializes the review and is also wrong, but that failure is loud (timing); the background-spawn failure is silent (cost).

For each worker `N ∈ [1..M]`:

1. `Read: ${output_dir}/worker-prompts/worker-N.txt`
2. Pass the file contents **verbatim** as the `Agent` tool's `prompt` argument:

| Parameter | Value |
|-----------|-------|
| `subagent_type` | `c-review:c-review-worker` |
| `model` | `${worker_model}` (haiku / sonnet / opus) |
| `description` | `C review worker N` |
| `prompt` | the full text of `worker-N.txt` (no edits) |
| `run_in_background` | **field MUST be omitted, OR set to `false`.** Never `true`. See the foreground-spawn warning above. |

The spawn prompt is the single authority. Pass it verbatim — every field is required by the worker's self-check; any deviation triggers `worker-N abort: spawn prompt malformed`.

**Anti-patterns to reject:**

- ❌ **Passing `run_in_background=true`** (the dominant historical defect — see warning above).
- ❌ Hand-typing the spawn prompt instead of reading `worker-N.txt`.
- ❌ Inserting Task-related instructions ("first call TaskList", "Assigned task id: <N>"). Workers have no Task tools.
- ❌ Editing the rendered prompt before passing it (trimming "redundant" fields, collapsing pass lists).

### Phase 7: Wait for Workers and Classify Outcomes

**Entry:** all M Phase-6 `Agent` calls have returned. **Exit:** every cluster has either succeeded or been retried up to the cap; `${output_dir}/findings-index.txt` written.

The Phase-6 `Agent` invocations block until each worker returns. Inspect each worker's return text and apply this classifier in order — first match wins:

| # | Match (in return text) | Outcome | Action |
|---|---|---|---|
| 1 | `worker-N complete:` | **success** | `TaskUpdate` to `completed`. |
| 2 | `abort: spawn prompt malformed`, `abort: pre-work budget exceeded`, or `abort: TaskList unavailable` (legacy) | **non-retryable orchestrator bug** | Stop the run, surface the abort + spawn-prompt path. Re-running the same prompt repeats the failure — pre-work-budget exhaustion always means the worker couldn't pass its self-check, which a retry won't fix. |
| 3 | other `worker-N abort:` | **retryable** | Mark `pending`, set `metadata.abort_reason`, `needs_respawn=true`, increment `attempt`. |
| 4 | `Agent` errored or no `complete:`/`abort:` token | **retryable** | Same as #3 (transient worker crash). |

If any non-retryable, stop. Otherwise re-spawn each `pending` retryable with `attempt < 2` in one parallel block (cap = 2 attempts per cluster). Replacement workers can safely overwrite partial files — finding IDs are deterministic per prefix.

#### Sanity-check + write index

For every `complete:` cluster, list `${output_dir}/findings/${prefix}-*.md` for each `pass_prefix` (from `plan.json`). A worker that says "wrote N finding files" with N>0 but zero files on disk is **suspicious** — treat as retryable (classifier row #4). Zero claimed + zero on disk is fine.

Then build the index — workers wrote per-worker shards under `${output_dir}/findings-index.d/`, prefer those:

```bash
# Use `find` rather than a `worker-*.txt` glob: zsh aborts the compound command on no-match
# even with `2>/dev/null`, so an empty findings-index.d would otherwise drop the index file.
if [ -d "${output_dir}/findings-index.d" ]; then
  find "${output_dir}/findings-index.d" -maxdepth 1 -type f -name 'worker-*.txt' -exec cat {} + 2>/dev/null \
    | sort -u > "${output_dir}/findings-index.txt"
else
  find "${output_dir}/findings" -maxdepth 1 -type f -name '*.md' 2>/dev/null | sort > "${output_dir}/findings-index.txt"
fi
```

`sort -u` collapses duplicates from Phase-7 retries. Empty file is the unambiguous "zero findings" signal. Cross-check the line count against the sum of `wrote N` worker claims; log mismatches but don't abort.

After task updates and index creation, run `TaskList` and write `${output_dir}/run-summary.md` with:

- resolved parameters (`threat_model`, `severity_filter`, `finding_scope_root`, `context_roots`, language/platform flags, compile-commands status)
- worker outcome table (`worker_n`, `cluster_id`, claimed finding count, shard line count, task status, retry/abort state)
- `findings-index.txt` line count and any mismatch against worker claims
- judge status once Phase 8 finishes, or the reason a judge was skipped/failed

If any Phase-5 cluster task is not `completed`, include it prominently in `run-summary.md` and the final response. Do not hide a partial run behind a successful report.

**Always run Phase 8 even on zero findings** — fp-judge writes empty `REPORT.md`/`REPORT.sarif` so SARIF consumers get a stable artifact set. Dedup-judge is the only phase that can be skipped on an empty index.

### Phase 8: Judge Pipeline (sequential, dedup → fp+severity)

**Entry:** `findings-index.txt` exists. **Exit:** dedup-judge has returned (skipped only when `findings-index.txt` is empty) and fp-judge has returned; `dedup-summary.md` (when applicable), `fp-summary.md`, `REPORT.md`, and ideally `REPORT.sarif` are written.

Each judge's full protocol is its system prompt (`agents/c-review-{dedup,fp}-judge.md`); spawn prompts pass only per-run variables. Do **not** reference `prompts/internal/judges/` — those files don't exist.

Spawn sequentially (dedup first, fp-judge sees only merged primaries):

- `Agent(subagent_type="c-review:c-review-dedup-judge", description="Dedup judge", prompt=f"output_dir: {output_dir}")`
- `Agent(subagent_type="c-review:c-review-fp-judge", description="FP + severity judge", prompt=f"output_dir: {output_dir}\nsarif_generator_path: {sarif_generator_path}")` — resolve `sarif_generator_path` to `${C_REVIEW_PLUGIN_ROOT}/scripts/generate_sarif.py`.

**Judge failure handling.** Same shape as Phase 7's classifier, applied to judge return text:

- `… complete:` → **success.**
- `… abort:` → **non-retryable.** Surface the abort line plus `ls -l ${output_dir}/findings-index.txt`; stop.
- No `complete:` (help message / error / question) → **retryable once.** `SendMessage(to=<agentId>, …)` rather than a fresh spawn (the agent already paid the protocol-parse cost). Include the explicit finding paths from `findings-index.txt`. If the second try still fails, surface the transcript and continue to Phase 8b.

### Phase 8b: SARIF safety net

**Entry:** fp-judge returned, or the run aborted early. **Exit:** `${output_dir}/REPORT.sarif` exists.

```bash
test -f "${output_dir}/REPORT.sarif" || python3 "${C_REVIEW_PLUGIN_ROOT}/scripts/generate_sarif.py" "${output_dir}"
```

Run unconditionally — generator is idempotent, emits `results: []` for zero-survivor runs, and handles partial runs (findings without `fp_verdict` are emitted as `LIKELY_TP` rather than being silently dropped). Skip only if `${output_dir}/findings/` doesn't exist (Phase 2 failed). After this phase, update `${output_dir}/run-summary.md` with judge/SARIF status.

### Phase 9: Return Report

`Read ${output_dir}/REPORT.md` and return its content to the caller. Append an Artifacts list pointing at `findings/`, `findings-index.txt`, `run-summary.md`, `dedup-summary.md`, `fp-summary.md`, `REPORT.md`, `REPORT.sarif`.

---

## Finding file frontmatter — three stages

Authoritative schema: `agents/c-review-worker.md` ("Finding File Format"). Three-stage write:

1. **Worker** — base fields (`id`, `bug_class`, `title`, `location`, `function`, `confidence`, `worker`) + seven body sections.
2. **Dedup-judge** — adds `merged_into` on duplicates, or `also_known_as` + `locations` on primaries that absorbed.
3. **FP+Severity judge** — adds `fp_verdict` + `fp_rationale` on every primary; on survivors (`TRUE_POSITIVE`/`LIKELY_TP`) also adds `severity`, `attack_vector`, `exploitability`, `severity_rationale`.

## Bug classes / clusters

Authoritative: `prompts/clusters/manifest.json`. 47 always-on bug classes, up to 64 with all conditional clusters enabled. `buffer-write-sinks` is fully consolidated (its sub-prompts are not re-read at runtime).

---

## Success Criteria

The phase exits already cover most of this; the orchestrator-visible end-state is:

- Every Phase-5 cluster task is `completed` (verify via `TaskList`).
- `${output_dir}/run-summary.md` exists and records resolved scope/context, compile-commands probe result, worker claims vs index count, task status, and judge/SARIF status.
- Every primary finding (no `merged_into`) has `fp_verdict` + `fp_rationale`; every survivor (`TRUE_POSITIVE`/`LIKELY_TP`) also has `severity`, `attack_vector`, `exploitability`, `severity_rationale`.
- `REPORT.md` exists, severity-filtered per `severity_filter`.
- `REPORT.sarif` exists (Phase 8b safety net guarantees this).
