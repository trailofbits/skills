---
name: rust-review
description: Performs comprehensive Rust security review for safe/unsafe boundary issues, memory safety in unsafe blocks, concurrency hazards, panic-induced DoS, FFI safety, and async runtime mistakes. Use when auditing Rust crates, services, or libraries — particularly those with `unsafe`, FFI, or concurrent code.
allowed-tools: Agent AskUserQuestion SendMessage TaskCreate TaskUpdate TaskList TaskGet Grep Glob Read Write Bash
---

# Rust Security Review

Runs in the main conversation (invoke via `/rust-review:rust-review`). Orchestrator owns the `Task*` ledger as bookkeeping for retries; workers and judges have no Task tools. Workers and judges are named plugin subagents (`rust-review:rust-review-worker`, `rust-review:rust-review-dedup-judge`, `rust-review:rust-review-fp-judge`); tool sets are declared in `plugins/rust-review/agents/*.md`. Findings are exchanged via markdown-with-YAML files in a shared output directory.

## When to Use

Rust application/library security review: safe/unsafe boundary auditing, memory safety in `unsafe` blocks, concurrency hazards, panic-induced DoS on servers, FFI safety, async-runtime mistakes.

## When NOT to Use

- Pure-C / pure-C++ codebases — use `c-review` instead.
- Smart contracts (Solana programs / NEAR contracts / Ink!) — use `solana-vulnerability-scanner` or the contract-specific skill.
- Kernel-mode Rust drivers without userspace allocator — coverage is incomplete; flag as advisory only.

## Subagents

| Subagent type | Purpose | Tool set |
|---|---|---|
| `rust-review:rust-review-worker` | Run assigned cluster, write findings | Read, Write, Edit, Grep, Glob, Bash |
| `rust-review:rust-review-dedup-judge` | Merge duplicates (runs **first**) | Read, Write, Edit, Glob |
| `rust-review:rust-review-fp-judge` | FP + severity + final reports (runs **second**) | Read, Write, Edit, Grep, Glob, Bash |

Tools come from each agent's frontmatter at spawn time. The orchestrator's `Task*`/`Agent`/`Bash`/etc. come from this skill's `allowed-tools`.

---

## Architecture

```
coordinator: write context.md → build_run_plan.py → TaskCreate × M
          → spawn primer (foreground) → spawn M workers (parallel)
          → classify Phase-7 outcomes + write findings-index.txt
          → dedup-judge → fp-judge → SARIF safety net → return REPORT.md
```

Output directory contains: `context.md`, `plan.json`, `worker-prompts/`, `findings/`, `findings-index.d/` (per-worker shards), `findings-index.txt`, `coverage/` (per-worker coverage-gate files), `run-summary.md`, `dedup-summary.md`, `fp-summary.md`, `REPORT.md`, `REPORT.sarif`.

**Path convention:** set `${RUST_REVIEW_PLUGIN_ROOT}=${CLAUDE_PLUGIN_ROOT}` if that resolves (`Bash: ls "${CLAUDE_PLUGIN_ROOT}/prompts/clusters/unsafe-boundary.md"`), otherwise `Bash: find ~/.claude -path '*/plugins/rust-review/prompts/clusters/unsafe-boundary.md' -print -quit`.

**Scope convention:** keep two scopes separate throughout the run:

- `finding_scope_root` — the user-requested audit subtree. Workers may only file findings whose vulnerable location is inside this subtree.
- `context_roots` — read-only repo roots/files workers and judges may inspect to verify reachability, callers, wrappers, build flags, mitigations, and threat-model details. Default to `.` unless the user explicitly forbids broader context. Reading context outside `finding_scope_root` is allowed; filing findings there is not.

---

## Rationalizations to Reject

- **"`unsafe` is rare, skip the memory-safety cluster."** Run the cluster anyway; it self-gates per-pass on `has_unsafe`. The unsafe-boundary cluster always runs (consolidated, covers safety-doc and repr(C) hygiene that apply to FFI declarations even without `unsafe { }` blocks visible at this scope).
- **"The compiler caught it."** The borrow checker proves absence of safe-code data races; it proves nothing about unsafe blocks, panic reachability, ABBA deadlocks, atomic-load/store sequencing, or FFI ABI mismatch.
- **"`unwrap()` is fine if it's `// SAFETY: documented infallible`."** `// SAFETY:` documents `unsafe` operations, not infallibility claims. An `unwrap()` on documented-infallible input is still risky if the documentation is wrong — file as low severity and let the FP judge decide.
- **"`has_unsafe=false` so skip the run."** Pure safe-Rust crates still have panic-DoS, atomic races, drop-panics, and trait-implementation hazards. Run the always-on clusters.
- **"Background spawns parallelize the workers."** They do not — `Agent` calls in a single assistant message already run concurrently. `run_in_background=true` defeats the Phase 6a primer cache, so every worker pays full cache-creation (`cache_read_input_tokens=0`) and the ~15 K-token primer is wasted M times. Default: omit `run_in_background` from worker spawns.
- **"I'll re-derive the cluster list / paths / pass prefixes inline instead of running `build_run_plan.py`."** The script is the only authority for selection and rendering. Paraphrasing it drops fields that the worker self-check requires, producing `worker-N abort: spawn prompt malformed`. Always run the script and `Read plan.json`.
- **"The run partially succeeded — I'll just write `REPORT.md` from what completed."** Hiding partial runs behind a successful report is a correctness bug. If any Phase-5 cluster task is not `completed`, surface it prominently in `run-summary.md` and the final response.
- **"Zero findings — skip Phase 8."** Always run both judges and Phase 8b: dedup-judge writes a minimal no-op `dedup-summary.md` on an empty index, fp-judge writes empty `REPORT.md`/`REPORT.sarif`, and Phase 8b's SARIF generator emits `results: []` for the empty case. SARIF consumers depend on a stable artifact set.
- **"`Bash: ls README*` is fine for the preflight."** Under zsh, an unmatched glob aborts the whole compound command before `2>/dev/null` runs. Use `Glob` (preferred) or `find` (never fails on no-match).

---

## Orchestration Workflow

Run these phases **in the main conversation**.

### Phase 0: Parameter Collection

**Entry:** skill invoked. **Exit:** `threat_model`, `worker_model`, `severity_filter` resolved; `scope_subpath` resolved or set to `"."`; `finding_scope_root=scope_subpath`; `context_roots` resolved.

The skill is invoked directly (no command wrapper). Parse any free-text arguments the user passed on the `/rust-review:rust-review` line (e.g. `flamenco only`, `high severity only`, `use haiku`) and pre-fill the answers they imply — then ask for any missing required parameters with **one** `AskUserQuestion` call. Never silently default the required parameters.

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

**Entry:** Phase 0 complete. **Exit:** `has_unsafe`, `has_ffi`, `has_concurrency`, `has_async` flags determined. Abort with a clear message if no `*.rs` files exist under `${finding_scope_root}`.

Probe within `${finding_scope_root:-.}`. Prefer `Glob`/`Grep`; fall back to `Bash` equivalents below (non-empty output ⇒ flag true).

```bash
# Rust source presence (precondition)
find "${finding_scope_root:-.}" -name '*.rs' -print -quit

# has_unsafe
grep -rlE '\bunsafe\s+(extern|fn|impl|trait)\b|\bunsafe\s*\{' --include='*.rs' "${finding_scope_root:-.}" | head -1

# has_ffi
grep -rlE 'extern\s+"C"|#\[repr\(C\)\]|use\s+(libc|core::ffi|cty)' --include='*.rs' "${finding_scope_root:-.}" | head -1

# has_concurrency
grep -rlE '\b(std::(thread|sync)|parking_lot::|crossbeam|rayon::|tokio::sync|core::sync::atomic|std::sync::atomic|Atomic[A-Za-z0-9_]*|UnsafeCell|static\s+mut|unsafe\s+impl\s+(Send|Sync)|memmap2::|Mmap(Options|Mut)?|MAP_SHARED|shm_open|mmap\s*\()' --include='*.rs' "${finding_scope_root:-.}" | head -1

# has_async
grep -rlE '\basync\s+(fn|move|\{)|\.await\b|tokio::|async_std::|futures::' --include='*.rs' "${finding_scope_root:-.}" | head -1
```

Note for `Cargo.toml`: also probe for `[dependencies] tokio`, `async-std`, etc., to set `has_async=true` even if the scope subpath has no `.await` yet (library crates often re-export).

Also probe `Cargo.toml` presence (informational — note in `run-summary.md` whether the audit was over a Cargo workspace, single crate, or loose `.rs` files):

```bash
find "${context_roots:-.}" -name 'Cargo.toml' -print -quit
```

### Phase 2: Output Directory

**Entry:** Phase 1 flags set. **Exit:** absolute `output_dir` resolved; `${output_dir}/findings/` and `${output_dir}/coverage/` exist.

Resolve an absolute path for `output_dir` (default: `$(pwd)/.rust-review-results/$(date -u +%Y%m%dT%H%M%SZ)/`):

```bash
mkdir -p "${output_dir}/findings" "${output_dir}/coverage"
```

The `coverage/` subdirectory holds per-worker coverage-gate audit files (`coverage/worker-{N}.md`). Workers write to it instead of embedding the table in their reply — see `agents/rust-review-worker.md` step 5.

### Phase 3: Codebase Context

**Entry:** `${output_dir}` exists. **Exit:** `${output_dir}/context.md` written.

Skim `README.{md,rst,txt}` and any build/manifest file (`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `build.rs`) — preflight with the `Glob` tool before any `Read` (a `Read` on a missing file aborts the turn). Do **not** use `Bash: ls README*` for the preflight: under zsh, an unmatched glob aborts the whole compound command before `2>/dev/null` runs. If you must use `Bash`, use `find . -maxdepth 2 -name 'README*' -o -name 'Cargo.toml' -o -name 'rust-toolchain.toml' -o -name 'build.rs'`, which never fails on no-match.

Write `${output_dir}/context.md` with: YAML frontmatter (`threat_model`, `severity_filter`, `scope_subpath`, `finding_scope_root`, `context_roots`, `has_unsafe`, `has_ffi`, `has_concurrency`, `has_async`, `output_dir`, `cargo_manifest` as `workspace`/`single-crate`/`absent` plus path when present), then a short markdown body with five sections — **Purpose** (1-3 sentences), **Scope** (what's in `finding_scope_root`, and that findings outside it are out of scope), **Entry points** (where untrusted data enters: network, files, CLI, IPC, `serde` deserialization, FFI inputs), **Trust boundaries** (sandboxed vs trusted peers vs arbitrary remote), **Existing hardening** (fuzzing harnesses, MIRI runs, `clippy::pedantic`, `cargo-deny`, `cargo-audit`).

### Phase 4: Build Run Plan (deterministic)

**Entry:** capability flags + `threat_model` known; `${output_dir}/findings/` exists. **Exit:** `${output_dir}/plan.json` and `${output_dir}/worker-prompts/*.txt` written; `M = worker_count` known.

Selection, filtering, path resolution, and spawn-prompt rendering are **delegated to the script** to keep spawn prompts complete and consistent:

```bash
python3 "${RUST_REVIEW_PLUGIN_ROOT}/scripts/build_run_plan.py" \
  --plugin-root "${RUST_REVIEW_PLUGIN_ROOT}" --output-dir "${output_dir}" \
  --threat-model "${threat_model}" --severity-filter "${severity_filter}" \
  --scope-subpath "${finding_scope_root:-.}" --context-roots "${context_roots:-.}" \
  --has-unsafe "${has_unsafe}" --has-ffi "${has_ffi}" \
  --has-concurrency "${has_concurrency}" --has-async "${has_async}" \
  --max-passes-per-worker 4
```

The script writes `plan.json` + `worker-prompts/worker-N.txt` + (if `--cache-primer=true`, the default) `worker-prompts/cache-primer.txt`, and prints a JSON summary on stdout. Exits non-zero on any missing prompt — surface the message and stop. Typical M: 7 (pure safe Rust, no FFI / concurrency / async), 10 (concurrent safe Rust), 15 (full Rust: unsafe + FFI + concurrency + async). After it returns, `Read plan.json` for the structured selection — never re-derive filtering or paths.

`--max-passes-per-worker N` caps the per-worker pass count. The planner deterministically splits any cluster with more than `N` passes into `ceil(K/N)` contiguous chunks; each chunk becomes its own `rust-review-worker` spawn with a `-{i}`-suffixed `cluster_id` (e.g. `unsafe-boundary-1`, `unsafe-boundary-2`). The shared prompt-cache prefix and `Cluster prompt:` path are byte-identical across chunks, so the cache primer still warms every worker. Default 4 is calibrated against the heavy-tail clusters in `manifest.json`. Some output-heavy clusters declare a smaller manifest-level `max_passes_per_worker` override so each expensive pass gets its own worker. Pass `--max-passes-per-worker 0` to disable all chunking, including manifest overrides (one worker per cluster).

### Phase 5: Create Bookkeeping Tasks (orchestrator-internal)

**Entry:** `${output_dir}/plan.json` exists; `M = plan.workers.length`. **Exit:** `cluster_task_ids[]` created (1:1 with `plan.workers`), all `pending`.

The task ledger is **orchestrator bookkeeping only** (TUI visibility + Phase-7 retry tracking) — workers never read or write it. One `TaskCreate` per worker, populating `metadata` with `kind="cluster"`, `worker_n`, `cluster_id`, `spawn_prompt_path`, `pass_prefixes`, `attempt=1` — all values copied verbatim from `plan.workers[i]`. Track `cluster_task_ids[]` in `plan.workers` order.

### Phase 6: Spawn workers (optional cache-primer first, then M in parallel)

**Entry:** `cluster_task_ids[]` populated; per-worker spawn prompt files exist at `${output_dir}/worker-prompts/worker-N.txt`. **Exit:** all M `Agent` calls have returned (the parallel spawn block completed).

#### Phase 6a: Cache primer (gated on `plan.run.cache_primer`)

A parallel batch from cold start cannot share cache (all M requests dispatch simultaneously, none has finished writing). To warm the prefix, spawn a tiny primer first — **foreground** (background spawns don't share cache with subsequent foreground spawns).

If `plan.run.cache_primer == true`, `build_run_plan.py` has written `${output_dir}/worker-prompts/cache-primer.txt`. Spawn it in its own assistant message: `Read` the file, pass verbatim as `Agent` `prompt` with `subagent_type=rust-review:rust-review-worker`, `model=${worker_model}`, `description="Rust review cache primer"`, no `run_in_background`. The script wrote the prefix byte-identical to `worker-1.txt` through the `<context>` block — that byte-identity is what gives the parallel workers their cache hit. The primer trailer contains `Cache primer: true`, which the worker system prompt treats as a first-class mode and returns exactly `worker-PRIMER abort: cache primer (no analysis performed)` in one text response with zero tool calls. Discard the abort line — Phase 7 ignores it (no `worker-N` id).

Foreground spawn already serializes — no `sleep` needed before Phase 6b. Skip Phase 6a entirely if `plan.run.cache_primer == false`.

#### Phase 6b: Spawn M real workers in ONE message

> **STOP — read this before composing the spawn message.**
>
> Workers MUST be spawned **foreground** (no `run_in_background` field, or `run_in_background=false`).
> "Parallel" here means *one assistant message containing M `Agent` calls* — that already runs them concurrently. **Background spawns are NOT how you parallelize this skill.**
>
> Background spawns defeat Phase 6a's primer cache: every worker pays full cache-creation on its first turn (`cache_read_input_tokens=0`), and the primer's ~15 K tokens are wasted M times over. Two real runs had exactly this symptom — every worker started with `first_cr=0`.
>
> Before sending the spawn message, audit your draft: every `Agent` call must have **no** `run_in_background` key. If you wrote `run_in_background=true`, delete it.

**Required spawn shape:** emit a single assistant message containing M `Agent` tool invocations. Sequential spawning serializes the review and is also wrong, but that failure is loud (timing); the background-spawn failure is silent (cost).

For each worker `N ∈ [1..M]`:

1. `Read: ${output_dir}/worker-prompts/worker-N.txt`
2. Pass the file contents **verbatim** as the `Agent` tool's `prompt` argument:

| Parameter | Value |
|-----------|-------|
| `subagent_type` | `rust-review:rust-review-worker` |
| `model` | `${worker_model}` (haiku / sonnet / opus) |
| `description` | `Rust review worker N` |
| `prompt` | the full text of `worker-N.txt` (no edits) |
| `run_in_background` | **field MUST be omitted, OR set to `false`.** Never `true`. See the foreground-spawn warning above. |

The spawn prompt is the single authority. Pass it verbatim — every field is required by the worker's self-check; any deviation triggers `worker-N abort: spawn prompt malformed`.

**Anti-patterns to reject:**

- **Passing `run_in_background=true`** (see warning above).
- Hand-typing the spawn prompt instead of reading `worker-N.txt`.
- Inserting Task-related instructions ("first call TaskList", "Assigned task id: <N>"). Workers have no Task tools.
- Editing the rendered prompt before passing it (trimming "redundant" fields, collapsing pass lists).

### Phase 7: Wait for Workers and Classify Outcomes

**Entry:** all M Phase-6 `Agent` calls have returned. **Exit:** every cluster has either succeeded or been retried up to the cap; `${output_dir}/findings-index.txt` written.

The Phase-6 `Agent` invocations block until each worker returns. Inspect each worker's return text and apply this classifier in order — first match wins:

| # | Match (in return text) | Outcome | Action |
|---|---|---|---|
| 1 | `worker-N complete:` | **provisional success** | Parse the `wrote N finding files` count, then run the artifact validator below before `TaskUpdate` to `completed`. |
| 2 | `abort: spawn prompt malformed`, `abort: pre-work budget exceeded`, or `abort: TaskList unavailable` (legacy) | **non-retryable orchestrator bug** | Stop the run, surface the abort + spawn-prompt path. Re-running the same prompt repeats the failure — pre-work-budget exhaustion always means the worker couldn't pass its self-check, which a retry won't fix. |
| 3 | other `worker-N abort:` | **retryable** | Mark `pending`, set `metadata.abort_reason`, `needs_respawn=true`, increment `attempt`. |
| 4 | `Agent` errored or no `complete:`/`abort:` token | **retryable** | Same as #3 (transient worker crash). |

If any non-retryable, stop. Otherwise re-spawn each `pending` retryable with `attempt < 2` in one parallel block (cap = 2 attempts per cluster). Replacement workers can safely overwrite partial files — finding IDs are deterministic per prefix.

#### Sanity-check + write index

For every provisional `complete:` cluster, validate the worker-owned shard, coverage file, coverage rows, filed IDs, and claimed finding count against `plan.json` before marking the task completed. Run one command per completed worker, or validate multiple workers in one command. Both claimed-count forms below are valid; do not pass bare `worker-N=N` values without either grouping them after a `--claimed-count` flag or repeating the flag.

```bash
python3 "${RUST_REVIEW_PLUGIN_ROOT}/scripts/validate_artifacts.py" "${output_dir}/plan.json" \
  --worker worker-N --claimed-count worker-N=<claimed_count_from_complete_line>
```

```bash
python3 "${RUST_REVIEW_PLUGIN_ROOT}/scripts/validate_artifacts.py" "${output_dir}/plan.json" \
  --worker worker-1 --worker worker-2 \
  --claimed-count worker-1=0 worker-2=3
```

```bash
python3 "${RUST_REVIEW_PLUGIN_ROOT}/scripts/validate_artifacts.py" "${output_dir}/plan.json" \
  --worker worker-1 --worker worker-2 \
  --claimed-count worker-1=0 --claimed-count worker-2=3
```

If validation exits non-zero, treat the completion as malformed and retryable (classifier row #4): mark the task `pending`, store the validator output in `metadata.abort_reason`, set `needs_respawn=true`, and increment `attempt`. Missing `findings-index.d/worker-N.txt`, missing `coverage/worker-N.md`, missing coverage rows, invalid `skipped:` rows, filed IDs absent from the shard or disk, and claimed-count mismatches are all malformed completions. After the retry cap, leave the cluster task incomplete and surface the validator output in `run-summary.md` and the final response. Only validation-clean provisional completions may be `TaskUpdate`d to `completed`.

Then build the index — workers wrote per-worker shards under `${output_dir}/findings-index.d/`, prefer those:

```bash
# Use `find` rather than a `worker-*.txt` glob: zsh aborts the compound command on no-match
# even with `2>/dev/null`, so an empty findings-index.d would otherwise drop the index file.
# `awk 1` (vs `cat`) normalizes a missing trailing newline on any shard, so a future
# worker that writes shards via Write/printf instead of `ls -1 | sort` can't silently glue
# the last path of one shard onto the first of the next when sort -u dedupes.
if [ -d "${output_dir}/findings-index.d" ]; then
  find "${output_dir}/findings-index.d" -maxdepth 1 -type f -name 'worker-*.txt' -exec awk 1 {} + 2>/dev/null \
    | sort -u > "${output_dir}/findings-index.txt"
else
  find "${output_dir}/findings" -maxdepth 1 -type f -name '*.md' 2>/dev/null | sort > "${output_dir}/findings-index.txt"
fi
```

`sort -u` collapses duplicates from Phase-7 retries. Empty file is the unambiguous "zero findings" signal. Cross-check the line count against the sum of `wrote N` worker claims; log mismatches but don't abort.

After task updates and index creation, run `TaskList` and write `${output_dir}/run-summary.md` with:

- resolved parameters (`threat_model`, `severity_filter`, `finding_scope_root`, `context_roots`, capability flags `has_unsafe`/`has_ffi`/`has_concurrency`/`has_async`, Cargo manifest status)
- worker outcome table (`worker_n`, `cluster_id`, claimed finding count, shard line count, coverage-file path (`coverage/worker-{N}.md`), task status, retry/abort state)
- `findings-index.txt` line count and any mismatch against worker claims
- judge status once Phase 8 finishes, or the reason a judge was skipped/failed

If any Phase-5 cluster task is not `completed`, include it prominently in `run-summary.md` and the final response. Do not hide a partial run behind a successful report.

**Always run Phase 8 even on zero findings** — both judges short-circuit on an empty index: dedup-judge writes a minimal no-op `dedup-summary.md`, and fp-judge writes empty `REPORT.md`/`REPORT.sarif` so SARIF consumers get a stable artifact set.

### Phase 8: Judge Pipeline (sequential, dedup → fp+severity)

**Entry:** `findings-index.txt` exists. **Exit:** dedup-judge and fp-judge have returned; `dedup-summary.md`, `fp-summary.md`, `REPORT.md`, and ideally `REPORT.sarif` are written.

Each judge's full protocol is its system prompt (`agents/rust-review-{dedup,fp}-judge.md`); spawn prompts pass only per-run variables. Do **not** reference `prompts/internal/judges/` — those files don't exist.

Spawn sequentially (dedup first, fp-judge sees only merged primaries):

- `Agent(subagent_type="rust-review:rust-review-dedup-judge", description="Dedup judge", prompt=f"output_dir: {output_dir}")`
- `Agent(subagent_type="rust-review:rust-review-fp-judge", description="FP + severity judge", prompt=f"output_dir: {output_dir}\nsarif_generator_path: {sarif_generator_path}")` — resolve `sarif_generator_path` to `${RUST_REVIEW_PLUGIN_ROOT}/scripts/generate_sarif.py`.

**Judge failure handling.** Same shape as Phase 7's classifier, applied to judge return text:

- `… complete:` → **success.**
- `… abort:` → **non-retryable.** Surface the abort line plus `ls -l ${output_dir}/findings-index.txt`; stop.
- No `complete:` (help message / error / question) → **retryable once.** `SendMessage(to=<agentId>, …)` rather than a fresh spawn (the agent already paid the protocol-parse cost). Include the explicit finding paths from `findings-index.txt`. If the second try still fails, surface the transcript and continue to Phase 8b.

### Phase 8b: SARIF safety net

**Entry:** fp-judge returned, or the run aborted early. **Exit:** `${output_dir}/REPORT.sarif` exists.

```bash
test -d "${output_dir}/findings" && python3 "${RUST_REVIEW_PLUGIN_ROOT}/scripts/generate_sarif.py" "${output_dir}"
```

Run unconditionally whenever `findings/` exists — generator is idempotent (full overwrite), emits `results: []` for zero-survivor runs, and handles partial runs (findings without `fp_verdict` are emitted as `LIKELY_TP` rather than being silently dropped). Always overwriting protects against the case where fp-judge crashed mid-write and left a corrupt `REPORT.sarif` on disk. Skip only if `${output_dir}/findings/` doesn't exist (Phase 2 failed). After this phase, update `${output_dir}/run-summary.md` with judge/SARIF status.

### Phase 9: Return Report

**Entry:** Phase 8b complete. **Exit:** every item in [Success Criteria](#success-criteria) verified true; `REPORT.md` returned to the caller.

Before composing the response, walk the [Success Criteria](#success-criteria) checklist below and confirm each bullet against on-disk artifacts (`TaskList` for cluster tasks, `ls`/`Read` for the files). If any criterion fails, surface the failure prominently in the response — do **not** hide a partial run behind a successful report.

Then `Read ${output_dir}/REPORT.md` and return its content to the caller. Append an Artifacts list pointing at `findings/`, `findings-index.txt`, `run-summary.md`, `dedup-summary.md`, `fp-summary.md`, `REPORT.md`, `REPORT.sarif`.

---

## Finding file frontmatter — three stages

Authoritative schema: `agents/rust-review-worker.md` ("Finding File Format"). Three-stage write:

1. **Worker** — base fields (`id`, `bug_class`, `title`, `location`, `function`, `confidence`, `worker`) + seven body sections.
2. **Dedup-judge** — adds `merged_into` on duplicates, or `also_known_as` + `locations` on primaries that absorbed.
3. **FP+Severity judge** — adds `fp_verdict` + `fp_rationale` on every primary; on survivors (`TRUE_POSITIVE`/`LIKELY_TP`) also adds `severity`, `attack_vector`, `exploitability`, `severity_rationale`.

## Bug classes / clusters

Authoritative: `prompts/clusters/manifest.json`. ~24 always-on bug classes, up to ~39 with all conditional clusters enabled. `unsafe-boundary` and `concurrency-locking` are fully consolidated (their sub-prompts are not re-read at runtime).

---

## Success Criteria

The phase exits already cover most of this; the orchestrator-visible end-state is:

- Every Phase-5 cluster task is `completed` (verify via `TaskList`).
- `${output_dir}/run-summary.md` exists and records resolved scope/context, Cargo manifest probe result, worker claims vs index count, task status, and judge/SARIF status.
- Every primary finding (no `merged_into`) has `fp_verdict` + `fp_rationale`; every survivor (`TRUE_POSITIVE`/`LIKELY_TP`) also has `severity`, `attack_vector`, `exploitability`, `severity_rationale`.
- `REPORT.md` exists, severity-filtered per `severity_filter`.
- `REPORT.sarif` exists (Phase 8b safety net guarantees this).
