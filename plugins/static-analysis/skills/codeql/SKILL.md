---
name: codeql
description: >-
  Scans a codebase for security vulnerabilities using CodeQL's interprocedural data flow and
  taint tracking analysis. Triggers on "run codeql", "codeql scan", "codeql analysis", "build
  codeql database", or "find vulnerabilities with codeql". Supports "run all" (security-and-quality
  suite) and "important only" (high-precision security findings) scan modes. Also handles
  creating data extension models and processing CodeQL SARIF output.
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Grep
  - AskUserQuestion
  - TaskCreate
  - TaskList
  - TaskUpdate
  - TaskGet
---

# CodeQL Analysis

Supported languages: Python, JavaScript/TypeScript, Go, Java/Kotlin, C/C++, C#, Ruby, Swift.

**Skill resources:** Reference files and templates are located at `{baseDir}/references/` and `{baseDir}/workflows/`.

## Essential Principles

1. **Database quality is non-negotiable.** A database that builds is not automatically good. Always run quality assessment (file counts, baseline LoC, extractor errors) and compare against expected source files. A cached build produces zero useful extraction.

2. **Data extensions catch what CodeQL misses.** Even projects using standard frameworks (Django, Spring, Express) have custom wrappers around database calls, request parsing, or shell execution. Skipping the create-data-extensions workflow means missing vulnerabilities in project-specific code paths.

3. **Explicit suite references prevent silent query dropping.** Never pass pack names directly to `codeql database analyze` — each pack's `defaultSuiteFile` applies hidden filters that can produce zero results. Always generate a custom `.qls` suite file.

4. **Zero findings needs investigation, not celebration.** Zero results can indicate poor database quality, missing models, wrong query packs, or silent suite filtering. Investigate before reporting clean.

5. **macOS Apple Silicon requires workarounds for compiled languages.** Exit code 137 is `arm64e`/`arm64` mismatch, not a build failure. Try Homebrew arm64 tools or Rosetta before falling back to `build-mode=none`.

6. **Follow workflows step by step.** Once a workflow is selected, execute it step by step without skipping phases. Each phase gates the next — skipping quality assessment or data extensions leads to incomplete analysis.

## Quick Start

For the common case ("scan this codebase for vulnerabilities"):

```bash
# 1. Verify CodeQL is installed
command -v codeql >/dev/null 2>&1 && codeql --version || echo "NOT INSTALLED"

# 2. Check for existing database
ls -dt codeql_*.db 2>/dev/null | head -1
```

Then execute the full pipeline: **build database → create data extensions → run analysis** using the workflows below.

## When to Use

- Scanning a codebase for security vulnerabilities with deep data flow analysis
- Building a CodeQL database from source code (with build capability for compiled languages)
- Finding complex vulnerabilities that require interprocedural taint tracking or AST/CFG analysis
- Performing comprehensive security audits with multiple query packs

## When NOT to Use

- **Writing custom queries** - Use a dedicated query development skill
- **CI/CD integration** - Use GitHub Actions documentation directly
- **Quick pattern searches** - Use Semgrep or grep for speed
- **No build capability** for compiled languages - Consider Semgrep instead
- **Single-file or lightweight analysis** - Semgrep is faster for simple pattern matching

## Rationalizations to Reject

These shortcuts lead to missed findings. Do not accept them:

- **"security-extended is enough"** - It is the baseline. Always check if Trail of Bits packs and Community Packs are available for the language. They catch categories `security-extended` misses entirely.
- **"The database built, so it's good"** - A database that builds does not mean it extracted well. Always run quality assessment and check file counts against expected source files.
- **"Data extensions aren't needed for standard frameworks"** - Even Django/Spring apps have custom wrappers that CodeQL does not model. Skipping extensions means missing vulnerabilities.
- **"build-mode=none is fine for compiled languages"** - It produces severely incomplete analysis. Only use as an absolute last resort. On macOS, try the arm64 toolchain workaround or Rosetta first.
- **"The build fails on macOS, just use build-mode=none"** - Exit code 137 is caused by `arm64e`/`arm64` mismatch, not a fundamental build failure. See [macos-arm64e-workaround.md](references/macos-arm64e-workaround.md).
- **"No findings means the code is secure"** - Zero findings can indicate poor database quality, missing models, or wrong query packs. Investigate before reporting clean results.
- **"I'll just run the default suite"** / **"I'll just pass the pack names directly"** - Each pack's `defaultSuiteFile` applies hidden filters and can produce zero results. Always use an explicit suite reference.

---

## Workflow Selection

This skill has three workflows. **Once a workflow is selected, execute it step by step without skipping phases.**

| Workflow | Purpose |
|----------|---------|
| [build-database](workflows/build-database.md) | Create CodeQL database using build methods in sequence |
| [create-data-extensions](workflows/create-data-extensions.md) | Detect or generate data extension models for project APIs |
| [run-analysis](workflows/run-analysis.md) | Select rulesets, execute queries, process results |

### Auto-Detection Logic

**If user explicitly specifies** what to do (e.g., "build a database", "run analysis"), execute that workflow.

**Default pipeline for "test", "scan", "analyze", or similar:** Execute all three workflows sequentially: build → extensions → analysis.

```bash
DB=$(ls -dt codeql_*.db 2>/dev/null | head -1)
if [ -n "$DB" ] && codeql resolve database -- "$DB" >/dev/null 2>&1; then
  echo "DATABASE EXISTS ($DB) - can run analysis"
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
4. **Run analysis** - Run security queries on existing database

[If database exists: "I found an existing database at <DB_NAME>"]
```

---

## Reference Index

| File | Content |
|------|---------|
| **Workflows** | |
| [workflows/build-database.md](workflows/build-database.md) | Database creation with build method sequence |
| [workflows/create-data-extensions.md](workflows/create-data-extensions.md) | Data extension generation pipeline |
| [workflows/run-analysis.md](workflows/run-analysis.md) | Query execution and result processing |
| **References** | |
| [references/macos-arm64e-workaround.md](references/macos-arm64e-workaround.md) | Apple Silicon build tracing workarounds |
| [references/build-fixes.md](references/build-fixes.md) | Build failure fix catalog |
| [references/quality-assessment.md](references/quality-assessment.md) | Database quality metrics and improvements |
| [references/extension-yaml-format.md](references/extension-yaml-format.md) | Data extension YAML column definitions and examples |
| [references/sarif-processing.md](references/sarif-processing.md) | jq commands for SARIF output processing |
| [references/diagnostic-query-templates.md](references/diagnostic-query-templates.md) | QL queries for source/sink enumeration |
| [references/important-only-suite.md](references/important-only-suite.md) | Important-only suite template and generation |
| [references/run-all-suite.md](references/run-all-suite.md) | Run-all suite template |
| [references/ruleset-catalog.md](references/ruleset-catalog.md) | Available query packs by language |
| [references/threat-models.md](references/threat-models.md) | Threat model configuration |
| [references/language-details.md](references/language-details.md) | Language-specific build and extraction details |
| [references/performance-tuning.md](references/performance-tuning.md) | Memory, threading, and timeout configuration |

---

## Success Criteria

A complete CodeQL analysis run should satisfy:

- [ ] Database built with quality assessment passed (baseline LoC > 0, errors < 5%)
- [ ] Data extensions evaluated — either created for project-specific APIs or explicitly skipped with justification
- [ ] Analysis run with explicit suite reference (not default pack suite)
- [ ] All installed query packs (official + Trail of Bits + Community) used or explicitly excluded
- [ ] Results processed with severity summary and file locations
- [ ] Zero-finding results investigated (database quality, model coverage, suite selection)
- [ ] Build log preserved with all commands, fixes, and quality assessments
