---
name: semgrep
description: Run Semgrep static analysis scan on a codebase using parallel subagents. Use when asked to scan
  code for vulnerabilities, run a security audit with Semgrep, find bugs, or perform
  static analysis. Spawns parallel workers for multi-language codebases and triage.
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
  - Write
  - Task
---

# Semgrep Security Scan

Run a complete Semgrep scan with automatic language detection, parallel execution via Task subagents, and parallel triage.

## Prerequisites

**Required:** Semgrep CLI

```bash
semgrep --version
```

If not installed, see [Semgrep installation docs](https://semgrep.dev/docs/getting-started/).

## When to Use

- Security audit of a codebase
- Finding vulnerabilities before code review
- Scanning for known bug patterns
- First-pass static analysis

## When NOT to Use

- Need cross-file taint tracking → CodeQL or Semgrep Pro
- Binary analysis → Use binary analysis tools
- Already have Semgrep CI configured → Use existing pipeline

---

## Orchestration Architecture

This skill uses **parallel Task subagents** for maximum efficiency:

```
┌─────────────────────────────────────────────────────────────────┐
│ MAIN AGENT                                                      │
│ 1. Detect languages                                             │
│ 2. Present plan, get approval                                   │
│ 3. Spawn parallel scan Tasks                                    │
│ 4. Spawn parallel triage Tasks                                  │
│ 5. Collect and report results                                   │
└─────────────────────────────────────────────────────────────────┘
          │ Step 3                           │ Step 4
          ▼                                  ▼
┌─────────────────┐              ┌─────────────────┐
│ Scan Tasks      │              │ Triage Tasks    │
│ (parallel)      │              │ (parallel)      │
├─────────────────┤              ├─────────────────┤
│ Python scanner  │              │ Python triager  │
│ JS/TS scanner   │              │ JS/TS triager   │
│ Go scanner      │              │ Go triager      │
│ Docker scanner  │              │ Docker triager  │
└─────────────────┘              └─────────────────┘
```

---

## Workflow

### Step 1: Detect Languages (Main Agent)

```bash
# Find languages by file extension
fd -t f -e py -e js -e ts -e jsx -e tsx -e go -e rb -e java -e php -e c -e cpp -e rs | \
  sed 's/.*\.//' | sort | uniq -c | sort -rn

# Check for frameworks/technologies
ls -la package.json pyproject.toml Gemfile go.mod Cargo.toml pom.xml 2>/dev/null
fd -t f "Dockerfile" "docker-compose" ".tf" "*.yaml" "*.yml" | head -20
```

Map findings to categories:

| Detection | Category | Rulesets |
|-----------|----------|----------|
| `.py`, `pyproject.toml` | Python | `p/python`, `p/django`, `p/flask` |
| `.js`, `.ts`, `package.json` | JavaScript/TypeScript | `p/javascript`, `p/typescript`, `p/react`, `p/nodejs` |
| `.go`, `go.mod` | Go | `p/golang`, `p/trailofbits` |
| `.rb`, `Gemfile` | Ruby | `p/ruby`, `p/rails` |
| `.java`, `pom.xml` | Java | `p/java`, `p/spring` |
| `.php` | PHP | `p/php` |
| `.c`, `.cpp` | C/C++ | `p/c` |
| `Dockerfile` | Docker | `p/dockerfile` |
| `.tf` | Terraform | `p/terraform` |
| Any | Security baseline | `p/security-audit`, `p/owasp-top-ten`, `p/secrets` |

See [references/rulesets.md](references/rulesets.md) for complete ruleset reference.

### Step 2: Create Plan and Get Approval (Main Agent)

Present plan to user:

```
## Semgrep Scan Plan

**Target:** /path/to/codebase
**Output directory:** ./semgrep-results/

### Detected Languages/Technologies:
- Python (1,234 files) - Django framework detected
- JavaScript (567 files) - React detected
- Dockerfile (3 files)

### Execution Strategy:
- Spawn 3 parallel scan Tasks (one per language category)
- Each Task runs its rulesets in parallel
- Then spawn parallel triage Tasks for each result

Proceed with scan?
```

Wait for user confirmation before proceeding.

### Step 3: Spawn Parallel Scan Tasks

Create output directory, then spawn Tasks:

```bash
mkdir -p semgrep-results
```

**Spawn N Tasks in a SINGLE message** (one per language category):

**Task Prompt for Scanner Subagent:**

```
You are a Semgrep scanner for [LANGUAGE_CATEGORY].

## Task
Run Semgrep scans for [LANGUAGE] files and save results.

## Commands to Run (in parallel)
```bash
semgrep --metrics=off --config [RULESET1] --json -o semgrep-results/[lang]-[ruleset1].json . &
semgrep --metrics=off --config [RULESET2] --json -o semgrep-results/[lang]-[ruleset2].json . &
semgrep --metrics=off --config p/security-audit --include="*.[ext]" --json -o semgrep-results/[lang]-security.json . &
semgrep --metrics=off --config p/secrets --include="*.[ext]" --json -o semgrep-results/[lang]-secrets.json . &
wait
```

## Critical Rules
- Always use --metrics=off
- Use --include to scope language-specific rulesets
- Run rulesets in parallel with & and wait

## Output
Report:
- Number of findings per ruleset
- Any scan errors
- File paths of JSON results
```

**Example - 3 Language Scan:**

Spawn these 3 Tasks in a SINGLE message:

1. **Task: Python Scanner**
   - Rulesets: p/python, p/django, p/security-audit, p/secrets
   - Output: semgrep-results/python-*.json

2. **Task: JavaScript Scanner**
   - Rulesets: p/javascript, p/react, p/security-audit, p/secrets
   - Output: semgrep-results/js-*.json

3. **Task: Docker Scanner**
   - Rulesets: p/dockerfile
   - Output: semgrep-results/docker-*.json

### Step 4: Spawn Parallel Triage Tasks

After scan Tasks complete, spawn triage Tasks:

**Task Prompt for Triage Subagent:**

```
You are a security finding triager for [LANGUAGE_CATEGORY].

## Input Files
[LIST OF JSON FILES TO TRIAGE]

## Task
For each finding:
1. Read the JSON finding
2. Read source code context (5 lines before/after)
3. Classify as TRUE_POSITIVE or FALSE_POSITIVE

## False Positive Criteria
- Test files (should add to .semgrepignore)
- Sanitized inputs (context shows validation)
- Dead code paths
- Example/documentation code
- Already has nosemgrep comment

## Output Format
Create: semgrep-results/[lang]-triage.json

```json
{
  "file": "[lang]-[ruleset].json",
  "total": 45,
  "true_positives": [
    {"rule": "...", "file": "...", "line": N, "reason": "..."}
  ],
  "false_positives": [
    {"rule": "...", "file": "...", "line": N, "reason": "..."}
  ]
}
```

## Report
Return summary:
- Total findings: N
- True positives: N
- False positives: N (with breakdown by reason)
```

### Step 5: Collect Results (Main Agent)

After all Tasks complete, merge and report:

```
## Semgrep Scan Complete

**Scanned:** 1,804 files
**Rulesets used:** 8
**Total raw findings:** 156
**After triage:** 32 true positives

### By Severity:
- ERROR: 5
- WARNING: 18
- INFO: 9

### By Category:
- SQL Injection: 3
- XSS: 7
- Hardcoded secrets: 2
- Insecure configuration: 12
- Code quality: 8

Results written to:
- semgrep-results/findings.json
- semgrep-results/triage.log
```

---

## Small Codebase Optimization

For **single-language codebases** or **<100 files**, skip Task spawning:

1. Run scans directly (still parallel with `&` and `wait`)
2. Triage inline
3. Report results

Overhead of Task spawning not worth it for small jobs.

---

## Common Mistakes

| Mistake | Correct Approach |
|---------|------------------|
| Running without `--metrics=off` | Always use `--metrics=off` |
| Running rulesets sequentially | Run in parallel with `&` and `wait` |
| Not scoping rulesets to languages | Use `--include="*.py"` for language-specific rules |
| Reporting raw findings without triage | Always triage to remove false positives |
| Single-threaded for multi-lang | Spawn parallel Tasks per language |
| Sequential Tasks | Spawn all Tasks in SINGLE message for parallelism |

## Limitations

1. Cannot track data flow across files (use Semgrep Pro or CodeQL)
2. Triage requires reading code context - parallelized via Tasks
3. Some false positive patterns require human judgment

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "Skip triage, report everything" | Floods user with noise; true issues get lost |
| "Run one ruleset at a time" | Wastes time; parallel execution is faster |
| "Use --config auto" | Sends metrics; less control over rulesets |
| "Triage later" | Findings without context are harder to evaluate |
| "One Task at a time" | Defeats parallelism; spawn all Tasks together |
