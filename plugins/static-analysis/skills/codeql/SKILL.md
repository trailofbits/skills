---
name: codeql
description: >-
  Run CodeQL static analysis for security vulnerability detection with
  interprocedural data flow tracking. Use when analyzing codebases with
  CodeQL, creating databases, selecting rulesets, or interpreting results.
  NOT for writing custom queries or CI/CD setup.
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Grep
  - AskUserQuestion
  - Task
  - TaskCreate
  - TaskList
  - TaskUpdate
  - WebFetch
---

# CodeQL Analysis

CodeQL provides interprocedural data flow and taint tracking for security vulnerability detection.

## Prerequisites

```bash
command -v codeql >/dev/null 2>&1 && codeql --version || echo "NOT INSTALLED"
```

## When to Use

- Source code access with ability to build (for compiled languages)
- Need for interprocedural data flow and taint tracking
- Finding complex vulnerabilities requiring AST/CFG analysis
- Comprehensive security audits

**Consider Semgrep instead when:**
- No build capability for compiled languages
- Need fast, lightweight pattern matching
- Single-file analysis is sufficient

## When NOT to Use

- **Writing custom queries** - Use a dedicated query development skill
- **CI/CD integration** - Use GitHub Actions documentation directly
- **Quick pattern searches** - Use Semgrep or grep for speed

---

## Workflow Selection

This skill has three workflows:

| Workflow | Purpose |
|----------|---------|
| [build-database](workflows/build-database.md) | Create CodeQL database using 3 build methods in sequence |
| [create-data-extensions](workflows/create-data-extensions.md) | Detect or generate data extension models for project APIs |
| [run-analysis](workflows/run-analysis.md) | Select rulesets, execute queries, process results |


### Auto-Detection Logic

**If user explicitly specifies** what to do (e.g., "build a database", "run analysis"), execute that workflow.

**Default pipeline for "test", "scan", "analyze", or similar:** Execute all three workflows sequentially: build → extensions → analysis. The create-data-extensions step is critical for finding vulnerabilities in projects with custom frameworks or annotations that CodeQL doesn't model by default.

```bash
# Check if database exists
if codeql database info codeql.db 2>/dev/null; then
  echo "DATABASE EXISTS - can run analysis"
else
  echo "NO DATABASE - need to build first"
fi
```

| Condition | Action |
|-----------|--------|
| No database exists | Execute build → extensions → analysis (full pipeline) |
| Database exists, no extensions | Execute extensions → analysis |
| Database exists, extensions exist | Ask user: run analysis on existing DB, or rebuild? |
| User says "just run analysis" or "skip extensions" | Run analysis only |


### Decision Prompt

If unclear, ask user:

```
I can help with CodeQL analysis. What would you like to do?

1. **Full scan (Recommended)** - Build database, create extensions, then run analysis
2. **Build database** - Create a new CodeQL database from this codebase
3. **Create data extensions** - Generate custom source/sink models for project APIs
4. **Run analysis** - Run security queries on existing database (codeql.db)

[If database exists: "I found an existing database at codeql.db"]
```
