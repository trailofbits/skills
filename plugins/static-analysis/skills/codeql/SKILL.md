---
name: codeql
description: >-
  Scans a codebase for security vulnerabilities using CodeQL's interprocedural data flow and
  taint tracking analysis. Triggers on "run codeql", "codeql scan", "build codeql database",
  "SAST scan", "taint analysis", "dataflow analysis", or "find vulnerabilities in this repo".
  Covers Python, JavaScript/TypeScript, Go, Java/Kotlin, C/C++, C#, Ruby, and Swift. Supports
  "run all" (security-and-quality + security-experimental) and "important only"
  (high-precision) scan modes, and creates data extension models for project-specific sources
  and sinks. For fast single-file pattern matching, or when no build is available for a
  compiled language, use the semgrep skill; to parse SARIF that already exists rather than
  produce it, use the sarif-parsing skill.
allowed-tools: Bash Read Write Edit Glob Grep AskUserQuestion TaskCreate TaskList TaskUpdate TaskGet
---

# CodeQL Analysis

Supported languages: Python, JavaScript/TypeScript, Go, Java/Kotlin, C/C++, C#, Ruby, Swift.

**Skill resources:** Reference files and templates are located at `{baseDir}/references/` and `{baseDir}/workflows/`.

## Essential Principles

1. **Database quality is non-negotiable.** A database that builds is not automatically good — a cached build extracts nothing while reporting success.

2. **Data extensions catch what CodeQL misses.** Django, Spring, and Express projects still wrap database calls, request parsing, and shell execution in project-specific APIs that no shipped model covers.

3. **Explicit suite references prevent silent query dropping.** Never pass pack names to `codeql database analyze` — each pack's `defaultSuiteFile` applies hidden filters that can produce zero results. Always generate a `.qls`.

4. **Zero findings needs investigation, not celebration.** It can mean poor extraction, missing models, the wrong packs, or suite filtering. Run `{baseDir}/scripts/check_db_quality.py` after the build, confirm `{baseDir}/scripts/verify_query_suite.py` exited zero for the suite in use — the generation scripts run it, so invoke it by hand only for a reused or hand-edited suite — and say in the report that both passed.

5. **macOS Apple Silicon requires workarounds for compiled languages.** Exit code 137 is an `arm64e`/`arm64` mismatch, not a build failure. Try Homebrew arm64 tools or Rosetta before falling back to `build-mode=none`.

6. **Follow workflows step by step.** Each phase gates the next; skipping quality assessment or data extensions leaves the gap invisible in the results.

## Each Bash call is a fresh shell

Nothing carries across a Bash call: not variables, not arrays, not functions sourced from
`build_log.sh`. Every block below that uses a value must re-establish it in the same block.
The workflows point back here rather than repeating it; what they do state is the specific
damage at that site, because each one fails differently and silently:

- a lost **function** makes `run_logged` exit 127, which the build ladder reads as a failed
  method and walks down to `--build-mode=none`, never having invoked CodeQL
- a lost **array** expands to nothing, so every `--threat-model` and `--model-packs` the user
  chose is dropped while the final report still lists them as used
- a lost **scalar** under `set -u` aborts the block with `unbound variable`

## Output Directory

All generated files (database, build logs, diagnostics, extensions, results) are stored in a single output directory.

- **If the user specifies an output directory** in their prompt, use it as `OUTPUT_DIR`.
- **If not specified**, default to `./static_analysis_codeql_1`. If that already exists, increment to `_2`, `_3`, etc.

In both cases, **always create the directory** with `mkdir -p` before writing any files.

Set `USER_SPECIFIED_DIR` to the literal path from the user's prompt before running this,
or leave it unset to auto-increment. Nothing else assigns it.

```bash
# Resolve output directory
USER_SPECIFIED_DIR="${USER_SPECIFIED_DIR:-}"   # substitute the user's path here, if any
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  BASE="static_analysis_codeql"
  N=1
  while [ -e "${BASE}_${N}" ]; do
    N=$((N + 1))
  done
  OUTPUT_DIR="${BASE}_${N}"
fi
mkdir -p "$OUTPUT_DIR"
```

The output directory is resolved **once** at the start before any workflow executes. All workflows receive `$OUTPUT_DIR` and store their artifacts there:

```
$OUTPUT_DIR/
├── rulesets.txt                 # Selected query packs (logged after Step 3)
├── codeql.db/                   # CodeQL database (dir containing codeql-database.yml)
├── build.log                    # Build log
├── codeql-config.yml            # Exclusion config (interpreted languages)
├── diagnostics/                 # Diagnostic queries and CSVs
├── extensions/                  # Data extension YAMLs
├── raw/                         # Unfiltered analysis output
│   ├── results.sarif
│   └── run-all.qls | important-only.qls
└── results/                     # Final results (filtered for important-only, copied for run-all)
    └── results.sarif
```

### Database Discovery

A CodeQL database is identified by the presence of a `codeql-database.yml` marker file inside its directory. When searching for existing databases, **always collect all matches** — there may be multiple databases from previous runs or for different languages.

**Discovery command.** `find_databases.sh` prints one database path per line, filtering
out the marker files a failed build leaves behind. Build the array **in the same block
that selects from it** — each Bash call is a fresh shell, so an array built here is empty
by the next call, and the run concludes there is no database:

```bash
# Command substitution, not `done < <(...)`: a process substitution discards the script's
# exit status, so "codeql is not on this shell's PATH" (exit 2) would arrive as an empty
# list and route to "build a new database" with three good ones sitting on disk.
if ! DB_LIST=$("{baseDir}/scripts/find_databases.sh" "${OUTPUT_DIR:-.}" .); then
  echo "ERROR: database discovery failed — see the message above" >&2
  exit 1
fi

FOUND_DBS=()
while IFS= read -r db; do
  [ -n "$db" ] || continue
  FOUND_DBS+=("$db")
done <<<"$DB_LIST"

echo "Found ${#FOUND_DBS[@]} existing database(s)"

# The metadata the selection prompt needs, collected here rather than in a block of its
# own: FOUND_DBS is gone by the next Bash call, and a loop over an array that no longer
# exists prints nothing and reports success.
for db in "${FOUND_DBS[@]}"; do
  CODEQL_LANG=$(codeql resolve database --format=json -- "$db" 2>/dev/null | jq -r '.languages[0]')
  CREATED=$(grep '^creationMetadata:' -A5 "$db/codeql-database.yml" 2>/dev/null | grep 'creationTime' | awk '{print $2}')
  echo "$db — language: $CODEQL_LANG, created: $CREATED"
done
```

Never assume a database is named `codeql.db` — discover it by its marker file.

**When multiple databases are found:** use `AskUserQuestion` to let the user select which database to use, or to build a new one, from the language and creation time printed above. `AskUserQuestion` takes at most four options, so with more databases than that, offer the three most recent plus "Build a new database" and list the rest in the prompt text. **Skip `AskUserQuestion` if the user explicitly stated which database to use or to build a new one in their prompt.**

## Quick Start

For the common case ("scan this codebase for vulnerabilities"):

```bash
# Verify CodeQL is installed. Stop here if it is not — every later command fails with
# a less informative error, and the run wastes a build cycle before saying why.
if ! command -v codeql >/dev/null 2>&1; then
  echo "ERROR: codeql not found on PATH. Install it with one of:" >&2
  echo "  gh extension install github/gh-codeql   # then: gh codeql install-stub" >&2
  echo "  brew install --cask codeql" >&2
  echo "  https://github.com/github/codeql-action/releases  (codeql-bundle)" >&2
  exit 1
fi

# jq parses `codeql resolve database --format=json` in the very next step. Without it
# CODEQL_LANG comes back empty and the run continues against the wrong language.
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq not found on PATH (brew install jq / apt install jq)" >&2
  exit 1
fi

# uv runs both guard scripts and both suite generators. Check it here rather than at
# suite generation, which is after the build — otherwise a machine without uv spends
# the whole build before failing.
if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: uv not found on PATH (https://docs.astral.sh/uv/getting-started/)" >&2
  exit 1
fi

codeql --version
```

Then resolve `OUTPUT_DIR` using the block in [Output Directory](#output-directory) above —
it honours a user-specified directory, which a bare auto-increment does not.

Then execute the full pipeline: **build database → create data extensions → run analysis** using the workflows below.

## Rationalizations to Reject

These shortcuts lead to missed findings. Do not accept them:

- **"security-extended is enough"** - It is the baseline. Always check if Trail of Bits packs and Community Packs are available for the language. They catch categories `security-extended` misses entirely.
- **"security-and-quality is the broadest suite"** - `security-and-quality` excludes all `experimental/` query paths. For run-all mode, import both `security-and-quality` and `security-experimental`. The delta is 1–52 queries depending on the language.
- **"The database built, so it's good"** - A database that builds does not mean it extracted well. Always run quality assessment and check file counts against expected source files.
- **"Data extensions aren't needed for standard frameworks"** - Even Django/Spring apps have custom wrappers that CodeQL does not model. Skipping extensions means missing vulnerabilities.
- **"build-mode=none is fine for compiled languages"** - It produces severely incomplete analysis. Only use as an absolute last resort. On macOS, try the arm64 toolchain workaround or Rosetta first.
- **"The build fails on macOS, just use build-mode=none"** - Exit code 137 is caused by `arm64e`/`arm64` mismatch, not a fundamental build failure. See [macos-arm64e-workaround.md](references/macos-arm64e-workaround.md).
- **"No findings means the code is secure"** - Run `check_db_quality.py` and `verify_query_suite.py` and report that they passed. Without them, zero findings and a database that extracted nothing are the same output.
- **"I'll just run the default suite"** / **"I'll just pass the pack names directly"** - Each pack's `defaultSuiteFile` applies hidden filters and can produce zero results. Always use an explicit suite reference.
- **"I'll put files in the current directory"** - All generated files must go in `$OUTPUT_DIR`. Scattering files in the working directory makes cleanup impossible and risks overwriting previous runs.
- **"Just use the first database I find"** - Multiple databases may exist for different languages or from previous runs. When more than one is found, present all options to the user. Only skip the prompt when the user already specified which database to use.
- **"The user said 'scan', that means they want me to pick a database"** - "Scan" is not database selection. If multiple databases exist and the user didn't name one, ask.

---

## Workflow Selection

This skill has three workflows. **Once a workflow is selected, execute it step by step without skipping phases.**

These runs are long. A database build has four fallback methods, so use the task tools to
track progress. Decide which steps are worth tracking based on the run.

| Workflow | Purpose |
|----------|---------|
| [build-database](workflows/build-database.md) | Create CodeQL database using build methods in sequence |
| [create-data-extensions](workflows/create-data-extensions.md) | Detect or generate data extension models for project APIs |
| [run-analysis](workflows/run-analysis.md) | Select rulesets, execute queries, process results |

### Building unattended

This plugin ships `/static-analysis:codeql-build`, which runs the build-database steps
end to end: detect the language and toolchain, walk the method ladder applying fixes from
[build-fixes.md](references/build-fixes.md) between rungs, and enforce the quality gate.

```
/static-analysis:codeql-build {"target": "/abs/path", "lang": "cpp"}
```

It asks nothing. Every method failing, and a database that built but sits below the quality
threshold, come back as statuses — `no-method-succeeded` and `built-below-threshold` — for you
to act on here, because whether the remaining extractor errors are confined to code nobody
needs analysed is a judgement call the run cannot make.

Use it when the build is the long, uncertain part and you want it driven to a conclusion. Work
[build-database.md](workflows/build-database.md) by hand when you want a say in which method is
tried, or when a build failure needs interpreting as it happens.

### Auto-Detection Logic

**If user explicitly specifies** what to do (e.g., "build a database", "run analysis on ./my-db"), execute that workflow directly. **Do NOT call `AskUserQuestion` for database selection if the user's prompt already makes their intent clear** — e.g., "build a new database", "analyze the codeql database in static_analysis_codeql_2", "run a full scan from scratch".

**Default pipeline for "test", "scan", "analyze", or similar:** Discover existing databases
using the command in [Database Discovery](#database-discovery) above, then decide.

| Condition | Action |
|-----------|--------|
| No databases found | Resolve new `$OUTPUT_DIR`, execute build → extensions → analysis (full pipeline) |
| One database found | Use `AskUserQuestion`: reuse it or build new? |
| Multiple databases found | Use `AskUserQuestion`, capped at four options — see [Database Discovery](#database-discovery) |
| User explicitly stated intent | Skip `AskUserQuestion`, act on their instructions directly |

### Database Selection Prompt

When existing databases are found **and the user did not explicitly specify which to use**,
present them via `AskUserQuestion` under the header "Existing CodeQL Databases". Label each
option with the path, language, and creation time collected above — `./static_analysis_codeql_1/codeql.db
(language: python, created: 2026-02-24)` — and make the last option "Build a new database".

After selection:
- **If user picks an existing database:** Set `$OUTPUT_DIR` to its parent directory (or the directory containing it), set `$DB_NAME` to the selected path, then proceed to extensions → analysis.
- **If user picks "Build new":** Resolve a new `$OUTPUT_DIR`, execute build → extensions → analysis.

### General Decision Prompt

If neither the database nor the workflow is clear from the prompt, offer the four
workflows via `AskUserQuestion` — full scan (recommended), build database, create data
extensions, run analysis — naming any databases found and the resolved `$OUTPUT_DIR`.

---

## Reference Index

| File | Content |
|------|---------|
| **Scripts** | |
| [scripts/verify_query_suite.py](scripts/verify_query_suite.py) | Fails a suite that resolves to zero queries. The generation scripts run it; invoke by hand only for a reused or hand-edited suite |
| [scripts/check_db_quality.py](scripts/check_db_quality.py) | Fails a database with no analysable source. Run after every build |
| [scripts/build_log.sh](scripts/build_log.sh) | `log_step`/`run_logged` helpers; source before any build step |
| [scripts/find_databases.sh](scripts/find_databases.sh) | Prints every database that `codeql resolve database` accepts, one per line. Build your array from it in the block that reads it |
| [scripts/generate_suite.sh](scripts/generate_suite.sh) | Writes the run-all or important-only `.qls` and verifies it resolves to a non-zero query count |
| **References** — the three workflows are listed under [Workflow Selection](#workflow-selection) | |
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

- [ ] Output directory resolved (user-specified or auto-incremented default)
- [ ] All generated files stored inside `$OUTPUT_DIR`
- [ ] Database built (discovered via `codeql-database.yml` marker) and `{baseDir}/scripts/check_db_quality.py` exited zero
- [ ] Data extensions evaluated — either created in `$OUTPUT_DIR/extensions/` or explicitly skipped with justification
- [ ] Analysis run with explicit suite reference (not default pack suite), and `{baseDir}/scripts/verify_query_suite.py` exited zero for it
- [ ] All installed query packs (official + Trail of Bits + Community) used or explicitly excluded
- [ ] Selected query packs logged to `$OUTPUT_DIR/rulesets.txt`
- [ ] Unfiltered results preserved in `$OUTPUT_DIR/raw/results.sarif`
- [ ] Final results in `$OUTPUT_DIR/results/results.sarif` (filtered for important-only, copied for run-all)
- [ ] Zero-finding results investigated (database quality, model coverage, suite selection)
- [ ] Build log preserved at `$OUTPUT_DIR/build.log` with all commands, fixes, and quality assessments
