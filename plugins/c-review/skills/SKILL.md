---
name: c-review
version: 3.1.0
description: >
  This skill should be used when the user asks to "review C code for security issues",
  "audit C/C++ codebase", "find vulnerabilities in C code", "security review C program",
  "check C code for bugs", "find memory corruption bugs", "audit native code security",
  "find buffer overflows", "check for use-after-free", "review parser code",
  "review Linux C code", "review macOS C code", "review Windows C code",
  "audit Linux daemon", "audit macOS daemon", "audit Windows service",
  "check signal handlers", "review setuid program", "find thread safety issues",
  "check errno handling", "review DLL loading", "check CreateProcess calls",
  "audit named pipes", "review Windows crypto", or needs comprehensive C/C++ security analysis.
---

# C/C++ Security Review

Comprehensive security review of C/C++ codebases using task-based orchestration.

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
# Always load general C prompts (21)
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/general/*.md

# If is_cpp, these are already in general/ (7 C++ prompts)
# init-order, iterator-invalidation, exception-safety, move-semantics,
# smart-pointer, virtual-function, lambda-capture

# If is_posix (Linux, macOS, BSD), load POSIX userspace prompts (26)
# Note: "linux-userspace" prompts apply to ALL POSIX systems including macOS
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/linux-userspace/*.md

# If is_windows, load Windows userspace prompts (10)
Glob: ${CLAUDE_PLUGIN_ROOT}/prompts/windows-userspace/*.md
```

Filter by `disabled_prompts` from input.

### Phase 3: Create Bug-Finder Tasks

For each enabled prompt, create a tracking task:

```
TaskCreate(
  subject="[bug-class]-finder",
  description="Scan for [bug class] vulnerabilities",
  activeForm="Scanning for [bug class]",
  metadata={
    "bug_class": "[bug-class]",
    "context_task_id": "[context_task_id]",
    "findings": []
  }
)
```

Collect all IDs into `finder_task_ids[]`.

### Phase 4: Create Pipeline Tasks with Dependencies

```
# Aggregation depends on ALL finders
TaskCreate(subject="Aggregate Findings", ...)
TaskUpdate(aggregation_id, addBlockedBy=finder_task_ids)

# FP-Judge depends on aggregation
TaskCreate(subject="FP-Judge", metadata={"input_task_id": aggregation_id})
TaskUpdate(fp_judge_id, addBlockedBy=[aggregation_id])

# Dedup-Judge depends on FP-Judge
TaskCreate(subject="Dedup-Judge", metadata={"input_task_id": fp_judge_id})
TaskUpdate(dedup_judge_id, addBlockedBy=[fp_judge_id])

# Severity-Agent depends on Dedup-Judge
TaskCreate(subject="Severity-Agent", metadata={"input_task_id": dedup_judge_id})
TaskUpdate(severity_agent_id, addBlockedBy=[dedup_judge_id])
```

### Phase 5: Spawn Bug Finders in Parallel

**CRITICAL: ONE message with MULTIPLE Task calls.**

Each worker:
1. Reads context via `TaskGet(context_task_id)`
2. Reads its prompt template
3. Analyzes codebase
4. Stores findings via `TaskUpdate(task_id, metadata={findings: [...]})`

```
Task(
  subagent_type="general-purpose",
  description="[bug-class]-finder",
  prompt="""
You are a [BUG CLASS] vulnerability finder.

1. Read context: TaskGet("[context_task_id]")
2. Read template: Read ${CLAUDE_PLUGIN_ROOT}/prompts/[path]/[bug-class]-finder.md
3. Read shared: Read ${CLAUDE_PLUGIN_ROOT}/prompts/shared/common.md
4. Analyze codebase using LSP tools
5. Store findings:
   TaskUpdate(
     taskId="[your_task_id]",
     status="completed",
     metadata={"findings": [...]}
   )

Your task ID: [task_id]
Context task ID: [context_task_id]
"""
)
```

### Phase 6: Execute Aggregation

After all finders complete (check via TaskList):

```
all_findings = []
for task_id in finder_task_ids:
    task = TaskGet(task_id)
    all_findings.extend(task.metadata.findings)

TaskUpdate(
  taskId=aggregation_id,
  status="completed",
  metadata={"all_findings": all_findings}
)
```

### Phase 7: Execute Judge Pipeline

Each judge reads input from its dependency:

**FP-Judge:**
```
Task(
  subagent_type="c-review:judges:fp-judge",
  prompt="""
1. TaskGet("[aggregation_id]") → all_findings
2. TaskGet("[context_task_id]") → threat_model
3. Evaluate each finding: TRUE_POSITIVE, LIKELY_TP, LIKELY_FP, FALSE_POSITIVE, OUT_OF_SCOPE
4. TaskUpdate("[fp_judge_id]", metadata={"filtered_findings": [TPs only]})

Your task ID: [fp_judge_id]
"""
)
```

**Dedup-Judge:**
```
Task(
  subagent_type="c-review:judges:dedup-judge",
  prompt="""
1. TaskGet("[fp_judge_id]") → filtered_findings
2. Merge duplicates, preserve all IDs
3. TaskUpdate("[dedup_judge_id]", metadata={"deduplicated_findings": [...]})

Your task ID: [dedup_judge_id]
"""
)
```

**Severity-Agent:**
```
Task(
  subagent_type="c-review:judges:severity-agent",
  prompt="""
1. TaskGet("[dedup_judge_id]") → deduplicated_findings
2. TaskGet("[context_task_id]") → threat_model
3. Assign: CRITICAL, HIGH, MEDIUM, LOW
4. TaskUpdate("[severity_agent_id]", metadata={"final_findings": [...]})

Your task ID: [severity_agent_id]
"""
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

### Context Task

```toon
context:
  threat_model: REMOTE
  is_cpp: true
  is_posix: true
  is_windows: false
  codebase_context: |
    [audit-context-building output]
```

**Field ownership:**
- Bug finder: id, bug_class, title, location, function, confidence, description, code_snippet, impact, data_flow, recommendation
- FP-judge: verdict
- Severity-agent: severity

**Final report:** Severity-agent outputs markdown for human consumption. All prior stages use TOON.

---

## Bug Classes

### General C (21 prompts)

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
