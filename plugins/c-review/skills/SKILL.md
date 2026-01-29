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

## When to Use

- Auditing C/C++ applications for security vulnerabilities
- Pre-release security review of native code
- Finding memory safety issues (buffer overflows, use-after-free)
- Identifying integer overflow and type confusion bugs
- Detecting race conditions and concurrency issues
- Auditing Linux/macOS daemons, setuid programs, signal handlers
- Auditing Windows services, DLL loading, named pipes, CreateProcess

## When NOT to Use

- Windows kernel driver review (different checklist)
- Linux/macOS kernel modules (different checklist)
- Managed languages (Java, C#, Python)
- Embedded/bare-metal code without libc

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
└── Executes judge pipeline: FP → Dedup → Severity
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

**Check prerequisites:**
```bash
which clangd
```
If not found, warn user that LSP features will be limited.

```bash
fd compile_commands.json . --type f 2>/dev/null | head -5
```
If not found, suggest: CMake (`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`), Bear, or compiledb.

**Detect code characteristics:**
```bash
fd -e cpp -e cxx -e cc -e hpp . | head -5
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

**Calculate disabled prompts** (coordinator logic):
```
if threat_model == "REMOTE":
    disabled_prompts = ["privilege-drop-finder", "envvar-finder"]
else:
    disabled_prompts = []
```

**Collect codebase context:**

Gather a brief summary (5-10 lines) to help workers understand the codebase:

```bash
# Check for README/documentation
head -50 README.md 2>/dev/null || head -50 README.rst 2>/dev/null
```

```bash
# Detect build system
ls -la Makefile CMakeLists.txt meson.build configure.ac 2>/dev/null | head -5
```

Summarize:
- **Purpose**: What does this software do? (e.g., "HTTP server", "PDF parser", "crypto library")
- **Entry points**: Where does untrusted data enter? (network, files, CLI args)
- **Security-relevant features**: Authentication, crypto, privilege separation, sandboxing

Store this as `codebase_context` for Phase 1.

### Phase 1: Create Context Task

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

### Phase 2: Select Prompts

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

### Phase 3: Create Bug-Finder Tasks

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

### Phase 4: Create Pipeline Tasks with Dependencies

```
# Aggregation depends on ALL finders
TaskCreate(subject="Aggregate Findings", description="Collect findings from all workers")
TaskUpdate(aggregation_id, addBlockedBy=finder_task_ids)

# Judge pipeline with explicit dependencies
TaskCreate(subject="FP-Judge", metadata={"input_task_id": aggregation_id})
TaskUpdate(fp_judge_id, addBlockedBy=[aggregation_id])

TaskCreate(subject="Dedup-Judge", metadata={"input_task_id": fp_judge_id})
TaskUpdate(dedup_judge_id, addBlockedBy=[fp_judge_id])

TaskCreate(subject="Severity-Agent", metadata={"input_task_id": dedup_judge_id})
TaskUpdate(severity_agent_id, addBlockedBy=[dedup_judge_id])
```

### Phase 5: Spawn Worker Pool

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

### Phase 6: Execute Aggregation

After all workers exit (all finder tasks completed):

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

### Phase 7: Execute Judge Pipeline

Each judge reads input from its dependency via TaskGet:

**FP-Judge:**
```
Task(
  subagent_type="general-purpose",
  prompt="Read ${CLAUDE_PLUGIN_ROOT}/prompts/internal/judges/fp-judge.md for instructions. Aggregation task: [aggregation_id]. Context task: [context_task_id]. Your task: [fp_judge_id]."
)
```

**Dedup-Judge:** (runs after fp-judge completes via addBlockedBy)
```
Task(
  subagent_type="general-purpose",
  prompt="Read ${CLAUDE_PLUGIN_ROOT}/prompts/internal/judges/dedup-judge.md for instructions. Input task: [fp_judge_id]. Your task: [dedup_judge_id]."
)
```

**Severity-Agent:** (runs after dedup-judge completes)
```
Task(
  subagent_type="general-purpose",
  prompt="Read ${CLAUDE_PLUGIN_ROOT}/prompts/internal/judges/severity-agent.md for instructions. Input task: [dedup_judge_id]. Context task: [context_task_id]. Your task: [severity_agent_id]."
)
```

### Phase 8: Return Report

```
final = TaskGet(severity_agent_id)
return final.metadata.final_findings
```

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

## Rationalizations to Reject

- "Code path is unreachable" → Prove it with caller trace
- "ASLR/DEP prevents exploitation" → Mitigations are bypass targets
- "Too complex to exploit" → Report it anyway
- "Input validated elsewhere" → Verify the validation exists
- "Only crashes, not exploitable" → Memory corruption may be controllable
- "Signal handler is simple enough" → Even simple handlers can call non-async-signal-safe functions
- "Only called from one thread" → Thread usage patterns change
- "Environment is trusted" → Environment variables are attacker-controlled
