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
- **Projects that cannot be built** - CodeQL requires successful compilation for compiled languages
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

**If user says "scan with CodeQL" or similar**, determine automatically:

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
| No database exists | Execute build-database workflow, then ask if user wants to continue |
| Database exists, no extensions | Ask user: create data extensions, run analysis, or both? |
| Database exists, extensions exist | Ask user: run analysis on existing DB, or rebuild? |
| User says "full scan" | Execute all three workflows sequentially: build → extensions → analysis |

### Decision Prompt

If unclear, ask user:

```
I can help with CodeQL analysis. What would you like to do?

1. **Build database** - Create a new CodeQL database from this codebase
2. **Create data extensions** - Generate custom source/sink models for project APIs
3. **Run analysis** - Run security queries on existing database (codeql.db)
4. **Full scan** - Build database, create extensions, then run analysis

[If database exists: "I found an existing database at codeql.db"]
```
