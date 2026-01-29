# c-review

Comprehensive C/C++ security code review plugin using task-based orchestration with a worker pool pattern.

## Features

- **Zero global context** - No registered agents; all prompts loaded on-demand
- **Worker pool architecture** - 8 parallel workers instead of 64 separate tasks
- **64 bug-finding prompts** - 28 general (21 C + 7 C++), 26 POSIX, 10 Windows
- **Platform-aware** - Automatically selects prompts for Linux/macOS/BSD or Windows
- **Judge pipeline** - FP filtering, deduplication, and severity assignment
- **TOON format** - Token-efficient inter-task communication (~40% reduction vs JSON)

## Usage

```
/c-review
```

The command will prompt for:
- Target path (codebase to review)
- Threat model (REMOTE, LOCAL_UNPRIVILEGED, or BOTH)
- Worker model (haiku for speed, sonnet for depth, opus for maximum capability)

## Architecture

```
/c-review command (thin)
└── Spawns general-purpose task to execute skill
    └── Skill orchestrates:
        ├── Creates context task (shared parameters)
        ├── Creates N finder tasks (one per prompt)
        ├── Spawns 8 workers (general-purpose tasks reading prompts/internal/worker.md)
        │   └── Workers loop: TaskList → claim → execute → complete → repeat
        ├── Aggregates findings after all finders complete
        └── Executes judge pipeline: FP → Dedup → Severity
```

## Bug Classes

| Category | Count | Examples |
|----------|-------|----------|
| General C | 21 | buffer-overflow, use-after-free, integer-overflow, format-string |
| C++ | 7 | init-order, iterator-invalidation, exception-safety, move-semantics |
| POSIX | 26 | signal-handler, privilege-drop, errno-handling, thread-safety |
| Windows | 10 | dll-planting, createprocess, named-pipe, service-security |

## Requirements

- Claude Code with task management tools (TaskCreate, TaskUpdate, TaskList, TaskGet)
- LSP server for the target codebase (recommended for better analysis)

## Version History

- **1.0.0** - Initial release with worker pool pattern, 64 prompts, TOON format
