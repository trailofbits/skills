# C/C++ Security Review Workflow

Reference documentation for the review workflow. The authoritative source is `skills/SKILL.md`.

## Architecture

```
/c-review command
    │
    ├─► Check prerequisites (clangd, compile_commands.json)
    ├─► Detect code (is_cpp, is_posix: Linux/macOS/BSD)
    ├─► Ask threat model
    ├─► Build context (optional)
    │
    └─► Invoke coordinator agent
            │
            ├─► Read skill for workflow
            ├─► Create context task (shared parameters)
            ├─► Create finder tasks (20-53)
            ├─► Create aggregation task (blockedBy: all finders)
            ├─► Create judge pipeline (blockedBy: chain)
            ├─► Spawn all finders (parallel)
            ├─► Aggregate findings
            ├─► Execute FP-judge
            ├─► Execute Dedup-judge
            ├─► Execute Severity-agent
            │
            └─► Return final findings
```

## Task Communication

| Pattern | Usage |
|---------|-------|
| Task metadata | Store structured data (findings, parameters) |
| addBlockedBy | Create dependency chains |
| TaskGet | Retrieve data from completed tasks |
| Task IDs in prompts | Workers know where to read/write |

## Data Flow

```
context_task (parameters)
    │
    ├─► finder_1 ─┐
    ├─► finder_2 ─┼─► aggregation ─► fp_judge ─► dedup_judge ─► severity_agent
    └─► finder_N ─┘
```

Each arrow is a `blockedBy` relationship. Data flows via task metadata.

## See Also

- `skills/SKILL.md` - Full workflow, schemas, bug classes
- `agents/coordinator.md` - Coordinator agent
- `commands/review.md` - Entry point command
