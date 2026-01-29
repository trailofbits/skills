---
name: c-review
version: 3.2.0
description: >
  Performs comprehensive C/C++ security review using parallel worker agents to scan for
  memory corruption, integer overflows, race conditions, and platform-specific vulnerabilities.
  Supports Linux/macOS/BSD (POSIX) and Windows userspace codebases. Triggers on "audit C code",
  "find buffer overflows", "review C++ for security", "check for use-after-free",
  "audit Windows service", "review Linux daemon", "find memory corruption bugs",
  "check signal handlers", "review setuid program", or similar security review requests
  for native code.
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

Instead of spawning one agent per prompt (54 agents), we spawn 8 workers that claim tasks from a shared queue:

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
- **8 agents instead of 54** - Reduces spawn overhead and API calls
- **Self-organizing** - Workers naturally load-balance across prompts
- **Minimal prompts** - Workers read everything from TaskGet, not prompt injection
- **Context efficiency** - Prompt templates read on-demand from files

---

## Orchestration Workflow

The coordinator agent follows this workflow using task management.

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

**CRITICAL: Spawn 8 workers in ONE message with 8 parallel Task calls.**

Workers self-organize: claim pending tasks, execute, complete, repeat until done.

The user selects the worker model at review start:
- **haiku** - Fast, cost-effective, good for large codebases
- **sonnet** - Deeper reasoning, better for subtle bugs
- **opus** - Maximum capability, highest cost

```
Task(
  subagent_type="c-review:worker",
  model="[worker_model]",
  description="worker-1",
  prompt="Context task: [context_task_id]. Claim and execute finder tasks until none remain."
)
Task(subagent_type="c-review:worker", model="[worker_model]", description="worker-2", prompt="Context task: [context_task_id]. ...")
Task(subagent_type="c-review:worker", model="[worker_model]", description="worker-3", prompt="Context task: [context_task_id]. ...")
Task(subagent_type="c-review:worker", model="[worker_model]", description="worker-4", prompt="Context task: [context_task_id]. ...")
Task(subagent_type="c-review:worker", model="[worker_model]", description="worker-5", prompt="Context task: [context_task_id]. ...")
Task(subagent_type="c-review:worker", model="[worker_model]", description="worker-6", prompt="Context task: [context_task_id]. ...")
Task(subagent_type="c-review:worker", model="[worker_model]", description="worker-7", prompt="Context task: [context_task_id]. ...")
Task(subagent_type="c-review:worker", model="[worker_model]", description="worker-8", prompt="Context task: [context_task_id]. ...")
```

Each worker:
1. Calls TaskList() to find pending "-finder" tasks
2. Claims task with TaskUpdate(taskId, status="in_progress", owner="worker-N")
3. Reads prompt from task.metadata.prompt_path
4. Reads shared instructions from prompts/shared/common.md
5. Executes analysis using Grep, Read, LSP
6. Stores findings with TaskUpdate(taskId, status="completed", metadata={findings_toon: ...})
7. Loops back to step 1 until no pending tasks

### Phase 6: Execute Aggregation

After all workers exit (all finder tasks completed):

```
all_findings_toon = ""
for task_id in finder_task_ids:
    task = TaskGet(task_id)
    if task.metadata.findings_toon:
        all_findings_toon += task.metadata.findings_toon + "\n"

TaskUpdate(
  taskId=aggregation_id,
  status="completed",
  metadata={"all_findings_toon": all_findings_toon}
)
```

### Phase 7: Execute Judge Pipeline

Each judge reads input from its dependency via TaskGet:

**FP-Judge:**
```
Task(
  subagent_type="c-review:judges:fp-judge",
  prompt="Aggregation task: [aggregation_id]. Context task: [context_task_id]. Your task: [fp_judge_id]."
)
```

**Dedup-Judge:** (runs after fp-judge completes via addBlockedBy)
```
Task(
  subagent_type="c-review:judges:dedup-judge",
  prompt="Input task: [fp_judge_id]. Your task: [dedup_judge_id]."
)
```

**Severity-Agent:** (runs after dedup-judge completes)
```
Task(
  subagent_type="c-review:judges:severity-agent",
  prompt="Input task: [dedup_judge_id]. Context task: [context_task_id]. Your task: [severity_agent_id]."
)
```

### Phase 8: Return Report

```
final = TaskGet(severity_agent_id)
return final.metadata.final_findings
```

---

## TOON Format for Internal Communication

All inter-agent finding data uses [TOON format](https://github.com/toon-format/toon) for token efficiency (~40% reduction vs JSON).

**TOON basics:**
- YAML-like indentation for nested objects
- CSV-style rows for uniform arrays
- `[N]{field1,field2,...}:` declares array length and headers
- Rows are comma-separated values

### Finding Summary (tabular)

For passing finding lists between agents:

```toon
findings[3]{id,bug_class,title,location,function,confidence,verdict,severity}:
 BOF-001,buffer-overflow,Stack overflow in parse_header,file.c:123,parse_header,High,,
 UAF-001,use-after-free,UAF in conn_close,conn.c:456,conn_close,Medium,,
 INT-001,integer-overflow,Integer overflow in calc_size,alloc.c:78,calc_size,High,,
```

### Finding Details (nested)

For full finding data including descriptions:

```toon
finding:
  id: BOF-001
  bug_class: buffer-overflow
  title: Stack buffer overflow in parse_header
  location: file.c:123
  function: parse_header
  confidence: High
  verdict:
  severity:
  description: |
    Unchecked strcpy from network input allows stack buffer overflow.
  code_snippet: |
    char buf[64]; strcpy(buf, input);
  impact: Remote code execution via controlled return address
  data_flow:
    source: network input via recv()
    sink: strcpy() buffer overflow
    validation: No length check
  recommendation: Use strncpy() with sizeof(buf)-1
```

**Field ownership:**
- Bug finder: id, bug_class, title, location, function, confidence, description, code_snippet, impact, data_flow, recommendation
- FP-judge: verdict
- Severity-agent: severity

**Final report:** Severity-agent outputs markdown for human consumption. All prior stages use TOON.

---

## Bug Classes

### General C/C++ (28 prompts: 21 C + 7 C++)

| Bug Class | Description |
|-----------|-------------|
| buffer-overflow | Spatial safety, bounds checking |
| use-after-free | Temporal safety, UAF, double-free |
| integer-overflow | Numeric errors, signedness |
| type-confusion | Type safety, casts, unions |
| format-string | Printf/scanf format bugs |
| string-issues | Null termination, encoding |
| uninitialized-data | Uninitialized memory |
| null-deref | Null pointer dereferences |
| error-handling | Unchecked errors |
| memory-leak | Resource leaks |
| race-condition | TOCTOU, double fetch |
| filesystem-issues | Symlinks, temp files |
| banned-functions | Dangerous functions |
| dos | Denial of service |
| undefined-behavior | UB patterns |
| compiler-bugs | Compiler optimizations |
| operator-precedence | Precedence mistakes |
| time-issues | Clock/time bugs |
| access-control | Privilege issues |
| regex-issues | ReDoS, bypasses |
| exploit-mitigations | Typos in security flags |

### C++ (7 additional prompts)

init-order, iterator-invalidation, exception-safety, move-semantics, smart-pointer, virtual-function, lambda-capture

### POSIX Userspace (26 additional prompts)

Applies to Linux, macOS, and BSD userspace code using standard libc/POSIX APIs.

thread-safety, signal-handler, privilege-drop, errno-handling, eintr-handling, envvar, open-issues, unsafe-stdlib, scanf-uninit, snprintf-retval, oob-comparison, socket-disconnect, strlen-strcpy, strncpy-termination, va-start-end, inet-aton, qsort, null-zero, half-closed-socket, spinlock-init, flexible-array, memcpy-size, printf-attr, strncat-misuse, negative-retval, overlapping-buffers

### Windows Userspace (10 additional prompts)

Applies to Windows userspace applications using Win32 APIs.

| Bug Class | Description |
|-----------|-------------|
| dll-planting | LoadLibrary without full path, DLL hijacking |
| createprocess | Unquoted paths, handle inheritance, dangerous flags |
| windows-path | DOS device names, 8.3 names, UNC, junctions |
| named-pipe | Pipe security, DACL, remote access |
| windows-alloc | Uninitialized alloc, mismatched free, secure zeroing |
| cross-process | VirtualAllocEx, WriteProcessMemory, injection |
| token-privilege | SeDebugPrivilege, privilege escalation |
| windows-crypto | Deprecated CSP APIs, weak algorithms |
| installer-race | Temp file races, MSI rollback, symlink attacks |
| service-security | Service privileges, binary ACLs, protected process |

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
