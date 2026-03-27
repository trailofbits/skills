---
name: c-review
description: >
  Performs comprehensive C/C++ security review using parallel workers to scan for
  memory corruption, integer overflows, race conditions, and platform-specific vulnerabilities.
  Triggers on "audit C code", "C security audit", "find buffer overflows", "review C++ for security",
  "check for use-after-free", "C++ vulnerability scan", "audit Windows service", "review Linux daemon",
  "check signal handlers", "review setuid program", "native code security review".
  NOT for kernel modules, managed languages, or embedded/bare-metal code.
allowed-tools:
  - Task
  - TaskCreate
  - TaskUpdate
  - TaskList
  - TaskGet
  - Grep
  - Glob
  - Read
  - LSP
  - Bash
---

# C/C++ Security Review

Comprehensive security review of C/C++ codebases using task-based orchestration with worker pool pattern.

## Essential Principles

1. **Verify before reporting.** Every finding must include actual code, traced data flow, and checked mitigations. Descriptions of code are not evidence.
2. **Threat model scopes everything.** A bug only matters if the defined attacker can reach it. REMOTE-only bugs are out of scope for a LOCAL audit and vice versa.
3. **Workers are self-organizing.** 8 workers claim tasks from a shared queue. Never spawn one worker per prompt — that doesn't scale.
4. **TOON for inter-task data.** All finding data between tasks uses TOON format for token efficiency. Human-readable markdown only at the final report.

## When to Use

- Auditing C/C++ applications for security vulnerabilities
- Pre-release security review of native code
- Finding memory safety issues (buffer overflows, use-after-free)
- Identifying integer overflow and type confusion bugs
- Detecting race conditions and concurrency issues
- Auditing Linux/macOS daemons, setuid programs, signal handlers
- Auditing Windows services, DLL loading, named pipes, CreateProcess

## When NOT to Use

- Windows kernel driver review — use kernel-specific audit checklists
- Linux/macOS kernel modules — use kernel-specific audit checklists
- Managed languages (Java, C#, Python) — use language-appropriate security tools
- Embedded/bare-metal code without libc — patterns assume hosted environment

---

## Architecture: Worker Pool Pattern

Instead of spawning one task per prompt (64 prompts), we spawn 8 workers that claim tasks from a shared queue:

```
Coordinator
├── Creates context task (shared parameters)
├── Creates N finder tasks (one per prompt, status=pending)
│   └── Each task stores: prompt_path, context_task_id, bug_class
├── Creates pipeline tasks with addBlockedBy chain
├── Spawns 8 workers in ONE message
│   └── Workers loop: TaskList → claim → execute → complete → repeat
├── Aggregates findings after all finders complete
└── Executes dedup judge
```

**Benefits:**
- **8 workers instead of 64** - Reduces spawn overhead and API calls
- **Self-organizing** - Workers naturally load-balance across prompts
- **Minimal prompts** - Workers read everything from TaskGet, not prompt injection
- **Context efficiency** - Prompt templates read on-demand from files

**Path convention:** This skill uses `${CLAUDE_PLUGIN_ROOT}` for all file paths. This is a plugin environment variable automatically set by Claude Code to the plugin's root directory.

**IMPORTANT:** Before Phase 1, verify the plugin root is accessible:
```
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/internal/worker.md
```
If this returns no results, the skill was not loaded via the plugin system. Fall back to searching for the c-review plugin directory:
```
Glob: **/plugins/c-review/prompts/internal/worker.md
```
Use the discovered path as the base for all subsequent file references.

---

## Orchestration Workflow

Execute these phases in order.

### Phase 0: Setup

**Entry:** User has provided threat model and worker model selection.

1. **Check prerequisites:**
   ```bash
   which clangd
   ```
   If not found, warn user that LSP features will be limited.

   ```
   Glob: **/compile_commands.json
   ```
   If not found, suggest: CMake (`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`), Bear, or compiledb.

2. **Detect code characteristics:**
   ```
   Glob: **/*.{cpp,cxx,cc,hpp}
   ```
   → `is_cpp = true` if any found

   ```
   Grep: pattern="#include.*<(pthread|signal|sys/(socket|stat|types|wait)|unistd|errno)\.h>"
   ```
   → `is_posix = true` if matches (Linux, macOS, BSD)

   ```
   Grep: pattern="#include.*<(windows|winbase|winnt|winuser|winsock|ntdef|ntstatus)\.h>"
   ```
   → `is_windows = true` if matches

3. **Calculate disabled prompts:**
   ```
   if threat_model == "REMOTE":
       disabled_prompts = ["privilege-drop-finder", "envvar-finder"]
   else:
       disabled_prompts = []
   ```

4. **Collect codebase context:**

   Gather a brief summary (5-10 lines) to help workers understand the codebase:

   - Read the first 50 lines of README.md (or README.rst) for project description
   - Use Glob to check for build files: `{Makefile,CMakeLists.txt,meson.build,configure.ac}`

   Summarize:
   - **Purpose**: What does this software do? (e.g., "HTTP server", "PDF parser", "crypto library")
   - **Entry points**: Where does untrusted data enter? (network, files, CLI args)
   - **Security-relevant features**: Authentication, crypto, privilege separation, sandboxing

   Store this as `codebase_context` for Phase 1.

**Exit:** `is_cpp`, `is_posix`, `is_windows`, `disabled_prompts`, and `codebase_context` are all determined.

### Phase 1: Create Context Task

**Entry:** Phase 0 exit criteria met.

Store shared parameters in a task for all workers to reference:

```
TaskCreate(
  subject="Review Context",
  description="Shared parameters for all bug finders",
  activeForm="Storing context",
  metadata={
    "codebase_context": "[from input]",
    "threat_model": "[REMOTE|LOCAL_UNPRIVILEGED|BOTH]",
    "is_cpp": true/false,
    "is_posix": true/false,
    "is_windows": true/false
  }
)
```

Store as `context_task_id`.

**Exit:** `context_task_id` is set and task exists with all metadata populated.

### Phase 2: Select Prompts

**Entry:** `context_task_id` exists.

Load prompts based on code characteristics:

```
# Always load general prompts (28 total: 21 C + 7 C++)
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/general/*.md
# C++ prompts in general/: init-order, iterator-invalidation, exception-safety,
# move-semantics, smart-pointer, virtual-function, lambda-capture

# If is_posix (Linux, macOS, BSD), load POSIX userspace prompts (26)
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/linux-userspace/*.md

# If is_windows, load Windows userspace prompts (10)
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/windows-userspace/*.md
```

Filter by `disabled_prompts` from input.

**Exit:** List of enabled prompt file paths determined.

### Phase 3: Create Bug-Finder Tasks

**Entry:** Prompt list from Phase 2 available.

For each enabled prompt, create a task with metadata pointing to the prompt file:

```
TaskCreate(
  subject="[bug-class]-finder",
  description="Scan for [bug class] vulnerabilities",
  activeForm="Scanning for [bug class]",
  metadata={
    "prompt_path": "${CLAUDE_PLUGIN_ROOT}/prompts/[category]/[bug-class]-finder.md",
    "context_task_id": "[context_task_id]",
    "bug_class": "[bug-class]"
  }
)
```

Collect all IDs into `finder_task_ids[]`. Tasks start with status="pending".

**Exit:** All finder tasks created. `finder_task_ids[]` populated.

### Phase 4: Create Pipeline Tasks with Dependencies

**Entry:** `finder_task_ids[]` and `context_task_id` available.

```
# Aggregation depends on ALL finders
TaskCreate(subject="Aggregate Findings", description="Collect findings from all workers")
TaskUpdate(aggregation_id, addBlockedBy=finder_task_ids)

# Dedup judge depends on aggregation
TaskCreate(subject="Dedup-Judge", metadata={"input_task_id": aggregation_id})
TaskUpdate(dedup_judge_id, addBlockedBy=[aggregation_id])
```

**Exit:** `aggregation_id` and `dedup_judge_id` created with correct dependency chain.

### Phase 5: Spawn Worker Pool

**Entry:** All tasks from Phases 3-4 created.

**CRITICAL: All 8 workers MUST be spawned in a SINGLE assistant message containing 8 parallel Task tool calls.**

This is non-negotiable for performance:
- DO NOT spawn workers sequentially
- DO NOT wait for one worker to complete before spawning the next
- Workers self-organize via task claiming and naturally load-balance

The user selects the worker model at review start:
- **haiku** - Fast, cost-effective, good for large codebases
- **sonnet** - Deeper reasoning, better for subtle bugs
- **opus** - Maximum capability, highest cost

**Spawn all 8 workers in ONE response:**

Emit a single response containing **8 Task tool invocations**. Each invocation uses these parameters:

| Parameter | Value |
|-----------|-------|
| subagent_type | `general-purpose` |
| model | `[worker_model from user selection]` |
| description | `worker-N` (where N = 1-8) |
| prompt | `Read ${CLAUDE_PLUGIN_ROOT}/prompts/internal/worker.md. Context: [context_task_id]. You are worker-N.` |

**Example prompt for worker-3:**
```
Read ${CLAUDE_PLUGIN_ROOT}/prompts/internal/worker.md. Context: task-abc123. You are worker-3.
```

All 8 Task invocations MUST appear in the same message to enable parallel execution. Do NOT wait for workers to return before spawning others.

Each worker:
1. Calls TaskList() to find pending "-finder" tasks
2. Claims task with TaskUpdate(taskId, status="in_progress", owner="worker-N")
3. Reads prompt from task.metadata.prompt_path
4. Reads shared instructions from prompts/shared/common.md
5. Executes analysis using Grep, Read, LSP
6. Stores findings with TaskUpdate(taskId, status="completed", metadata={findings_toon: ..., findings_detail_toon: ...})
7. Loops back to step 1 until no pending tasks

**Exit:** All 8 workers have returned. All finder tasks have status="completed".

### Phase 6: Execute Aggregation

**Entry:** All finder tasks completed (all workers returned).

After all workers exit:

```python
all_findings_toon = ""
all_findings_detail_toon = ""
for task_id in finder_task_ids:
    task = TaskGet(task_id)
    if task.metadata.findings_toon:
        all_findings_toon += task.metadata.findings_toon + "\n"
    if task.metadata.findings_detail_toon:
        all_findings_detail_toon += task.metadata.findings_detail_toon + "\n"

TaskUpdate(
  taskId=aggregation_id,
  status="completed",
  metadata={
    "all_findings_toon": all_findings_toon,
    "all_findings_detail_toon": all_findings_detail_toon
  }
)
```

**Exit:** Aggregation task completed with `all_findings_toon` and `all_findings_detail_toon` in metadata.

### Phase 7: Execute Dedup Judge

**Entry:** Aggregation task completed.

The dedup judge runs a deterministic Python script to remove duplicate findings (same file:line location). This handles the common case where overlapping bug-finders (e.g., buffer-overflow-finder, string-issues-finder, banned-functions-finder) all flag the same source line — the first finder wins.

**Dedup-Judge:**
```
Task(
  subagent_type="general-purpose",
  model="haiku",
  prompt="Read ${CLAUDE_PLUGIN_ROOT}/prompts/internal/judges/dedup-judge.md for instructions. Input task: [aggregation_id]. Your task: [dedup_judge_id]."
)
```

The agent writes aggregated TOON to temp files, runs `uv run ${CLAUDE_PLUGIN_ROOT}/scripts/dedup_findings.py`, and stores the script's stdout as `deduped_toon` in task metadata.

**Exit:** Dedup judge task completed with `deduped_toon` in metadata (deduplicated findings + filtered details + stats).

### Phase 8: Return Report

**Entry:** Dedup judge task completed.

1. Read final results:
   ```
   final = TaskGet(dedup_judge_id)
   deduped_toon = final.metadata.deduped_toon
   ```
   The `deduped_toon` contains:
   - `findings[N]{...}:` — deduplicated summary table
   - `details[N]{...}:` / `data_flows[N]{...}:` / nested `finding:` blocks — filtered to match surviving IDs
   - `dedup_stats:` — original_count, after_dedup, duplicates_removed

2. **Verify completeness:**
   - `dedup_stats.after_dedup` count matches length of findings array
   - Every finding has non-empty location and bug_class
   - No placeholder text remains in any finding
   - If `dedup_error` is set in metadata, warn user that dedup failed and results are unfiltered

3. Format deduplicated findings as a markdown report grouped by bug class. Include for each finding:
   - Title, location, function
   - Description with code snippet
   - Impact and recommendation
   - Data flow (source → sink)

4. Present summary statistics:
   - Total findings (after dedup)
   - Duplicates removed
   - Breakdown by bug class
   - Breakdown by confidence level

**Exit:** Markdown report presented to user.

---

## TOON Format for Internal Communication

All inter-task finding data uses [TOON format](references/toon-format.md) for token efficiency (~40% reduction vs JSON). Workers and judges read the full format specification from `prompts/shared/common.md`.

---

## Bug Classes (Prompt Counts)

| Category | Count | Loaded When |
|----------|-------|-------------|
| General C | 21 | Always |
| General C++ | 7 | `is_cpp = true` |
| POSIX Userspace | 26 | `is_posix = true` (Linux/macOS/BSD) |
| Windows Userspace | 10 | `is_windows = true` |

Each prompt file contains: bug patterns, false positive guidance, analysis process, and search patterns. See individual `*-finder.md` files for details.

---

## Threat Model Filtering

| Threat Model | Disabled Prompts |
|--------------|------------------|
| REMOTE | privilege-drop-finder, envvar-finder |
| LOCAL_UNPRIVILEGED | (none) |
| BOTH | (none) |

---

## Reference Index

| File | Content |
|------|---------|
| [toon-format.md](references/toon-format.md) | TOON format specification for inter-task finding data |
| [prompts/shared/common.md](${CLAUDE_PLUGIN_ROOT}/prompts/shared/common.md) | Shared worker instructions: LSP usage, TOON output schema, quality standards |
| [prompts/internal/worker.md](${CLAUDE_PLUGIN_ROOT}/prompts/internal/worker.md) | Worker loop and finder execution instructions |
| [prompts/internal/judges/dedup-judge.md](${CLAUDE_PLUGIN_ROOT}/prompts/internal/judges/dedup-judge.md) | Dedup judge: thin orchestrator that runs the dedup script |
| [scripts/dedup_findings.py](${CLAUDE_PLUGIN_ROOT}/scripts/dedup_findings.py) | Deterministic dedup script: removes duplicate findings by location (file:line) |

---

## Rationalizations to Reject

- "Code path is unreachable" → Prove it with caller trace
- "ASLR/DEP prevents exploitation" → Mitigations are bypass targets
- "Too complex to exploit" → Report it anyway
- "Input validated elsewhere" → Verify the validation exists
- "Only crashes, not exploitable" → Memory corruption may be controllable
- "Signal handler is simple enough" → Even simple handlers can call non-async-signal-safe functions
- "Only called from one thread" → Thread usage patterns change
- "Environment is trusted" → Environment variables are attacker-controlled

---

## Success Criteria

- [ ] All finder tasks completed (no pending/in_progress tasks remain)
- [ ] Every finding includes verified code snippet, location, and traced data flow
- [ ] Dedup judge merged true duplicates without dropping distinct findings
- [ ] Final report covers all bug classes that were scanned
- [ ] No placeholder text in any finding description
- [ ] Findings are scoped to the declared threat model
