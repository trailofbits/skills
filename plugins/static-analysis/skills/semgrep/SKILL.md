---
name: semgrep
description: Run Semgrep static analysis scan on a codebase using parallel subagents. Supports
  two scan modes - "run all" (full coverage) and "important only" (high-confidence security
  vulnerabilities). Automatically detects and uses Semgrep Pro for cross-file analysis when
  available. Use when asked to scan code for vulnerabilities, run a security audit with Semgrep,
  find bugs, or perform static analysis. Spawns parallel workers for multi-language codebases.
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - AskUserQuestion
  - TaskCreate
  - TaskList
  - TaskUpdate
  - WebFetch
---

# Semgrep Security Scan

Run a complete Semgrep scan with automatic language detection, parallel execution via Task subagents, and merged SARIF output. Automatically uses Semgrep Pro for cross-file taint analysis when available.

## Prerequisites

**Required:** Semgrep CLI

```bash
semgrep --version
```

If not installed, see [Semgrep installation docs](https://semgrep.dev/docs/getting-started/).

**Optional:** Semgrep Pro (for cross-file analysis and Pro languages)

```bash
# Check if Semgrep Pro engine is installed
semgrep --pro --validate --config p/default 2>/dev/null && echo "Pro available" || echo "OSS only"

# If logged in, install/update Pro Engine
semgrep install-semgrep-pro
```

Pro enables: cross-file taint tracking, inter-procedural analysis, and additional languages (Apex, C#, Elixir).

## When to Use

- Security audit of a codebase
- Finding vulnerabilities before code review
- Scanning for known bug patterns
- First-pass static analysis

## When NOT to Use

- Binary analysis → Use binary analysis tools
- Already have Semgrep CI configured → Use existing pipeline
- Need cross-file analysis but no Pro license → Consider CodeQL as alternative
- Creating custom Semgrep rules → Use `semgrep-rule-creator` skill
- Porting existing rules to other languages → Use `semgrep-rule-variant-creator` skill

---

## Scan Modes

Two modes control scan scope and result filtering. Select mode early in the workflow (Step 2).

| Mode | Coverage | Findings Reported |
|------|----------|-------------------|
| **Run all** | All rulesets, all severity levels | Everything |
| **Important only** | All rulesets, but pre-filtered and post-filtered | Security vulnerabilities only, medium-high confidence and impact |

**Important only** applies two layers of filtering:
1. **Pre-filter**: `--severity MEDIUM --severity HIGH --severity CRITICAL` (CLI flag, excludes LOW/INFO at scan time)
2. **Post-filter**: JSON metadata filtering — keeps only findings where `category=security`, `confidence∈{MEDIUM,HIGH}`, `impact∈{MEDIUM,HIGH}`

See [scan-modes.md](references/scan-modes.md) for detailed metadata criteria and jq filter commands.

---

## Orchestration Architecture

This skill uses **parallel Task subagents** for maximum efficiency:

```
┌─────────────────────────────────────────────────────────────────┐
│ MAIN AGENT                                                      │
│ 1. Detect languages + check Pro availability                    │
│ 2. Select scan mode + rulesets (ref: rulesets.md, scan-modes.md)│
│ 3. Present plan + rulesets, get approval [⛔ HARD GATE]         │
│ 4. Spawn parallel scan Tasks (with approved rulesets + mode)    │
│ 5. Merge results and report                                     │
└─────────────────────────────────────────────────────────────────┘
          │ Step 4
          ▼
┌─────────────────┐
│ Scan Tasks      │
│ (parallel)      │
├─────────────────┤
│ Python scanner  │
│ JS/TS scanner   │
│ Go scanner      │
│ Docker scanner  │
└─────────────────┘
```

---

## Workflow Enforcement via Task System

This skill uses the **Task system** to enforce workflow compliance. On invocation, create these tasks:

```
TaskCreate: "Detect languages and Pro availability" (Step 1)
TaskCreate: "Select scan mode and rulesets" (Step 2) - blockedBy: Step 1
TaskCreate: "Present plan with rulesets, get approval" (Step 3) - blockedBy: Step 2
TaskCreate: "Execute scans with approved rulesets and mode" (Step 4) - blockedBy: Step 3
TaskCreate: "Merge results and report" (Step 5) - blockedBy: Step 4
```

### Mandatory Gates

| Task | Gate Type | Cannot Proceed Until |
|------|-----------|---------------------|
| Step 3: Get approval | **HARD GATE** | User explicitly approves rulesets + plan |

**Step 3 is a HARD GATE**: Mark as `completed` ONLY after user says "yes", "proceed", "approved", or equivalent.

### Task Flow Example

```
1. Create all 5 tasks with dependencies
2. TaskUpdate Step 1 → in_progress, execute detection
3. TaskUpdate Step 1 → completed
4. TaskUpdate Step 2 → in_progress, select rulesets
5. TaskUpdate Step 2 → completed
6. TaskUpdate Step 3 → in_progress, present plan with rulesets
7. STOP: Wait for user response (may modify rulesets)
8. User approves → TaskUpdate Step 3 → completed
9. TaskUpdate Step 4 → in_progress (now unblocked)
... continue workflow
```

---

## Workflow

### Step 1: Detect Languages and Pro Availability (Main Agent)

```bash
# Check if Semgrep Pro is available (non-destructive check)
SEMGREP_PRO=false
if semgrep --pro --validate --config p/default 2>/dev/null; then
  SEMGREP_PRO=true
  echo "Semgrep Pro: AVAILABLE (cross-file analysis enabled)"
else
  echo "Semgrep Pro: NOT AVAILABLE (OSS mode, single-file analysis)"
fi

# Find languages by file extension
fd -t f -e py -e js -e ts -e jsx -e tsx -e go -e rb -e java -e php -e c -e cpp -e rs | \
  sed 's/.*\.//' | sort | uniq -c | sort -rn

# Check for frameworks/technologies
ls -la package.json pyproject.toml Gemfile go.mod Cargo.toml pom.xml 2>/dev/null
fd -t f "Dockerfile" "docker-compose" ".tf" "*.yaml" "*.yml" | head -20
```

Map findings to categories:

| Detection | Category |
|-----------|----------|
| `.py`, `pyproject.toml` | Python |
| `.js`, `.ts`, `package.json` | JavaScript/TypeScript |
| `.go`, `go.mod` | Go |
| `.rb`, `Gemfile` | Ruby |
| `.java`, `pom.xml` | Java |
| `.php` | PHP |
| `.c`, `.cpp` | C/C++ |
| `.rs`, `Cargo.toml` | Rust |
| `Dockerfile` | Docker |
| `.tf` | Terraform |
| k8s manifests | Kubernetes |

### Step 2: Select Scan Mode and Rulesets

**First, select scan mode** using `AskUserQuestion`:

```
header: "Scan Mode"
question: "Which scan mode should be used?"
multiSelect: false
options:
  - label: "Run all (Recommended)"
    description: "Full coverage — all rulesets, all severity levels"
  - label: "Important only"
    description: "Security vulnerabilities only — medium-high confidence and impact, no code quality"
```

Record the selected mode. It affects Steps 4 and 5.

**Then, select rulesets.** Using the detected languages and frameworks from Step 1, select rulesets by following the **Ruleset Selection Algorithm** in [rulesets.md](references/rulesets.md).

The algorithm covers:
1. Security baseline (always included)
2. Language-specific rulesets
3. Framework rulesets (if detected)
4. Infrastructure rulesets
5. **Required** third-party rulesets (Trail of Bits, 0xdea, Decurity - NOT optional)
6. Registry verification

**Output:** Structured JSON passed to Step 3 for user review:

```json
{
  "baseline": ["p/security-audit", "p/secrets"],
  "python": ["p/python", "p/django"],
  "javascript": ["p/javascript", "p/react", "p/nodejs"],
  "docker": ["p/dockerfile"],
  "third_party": ["https://github.com/trailofbits/semgrep-rules"]
}
```

### Step 3: CRITICAL GATE - Present Plan and Get Approval

> **⛔ MANDATORY CHECKPOINT - DO NOT SKIP**
>
> This step requires explicit user approval before proceeding.
> User may modify rulesets before approving.

Present plan to user with **explicit ruleset listing**:

```
## Semgrep Scan Plan

**Target:** /path/to/codebase
**Output directory:** ./semgrep-results-001/
**Engine:** Semgrep Pro (cross-file analysis) | Semgrep OSS (single-file)
**Scan mode:** Run all | Important only (security vulns, medium-high confidence/impact)

### Detected Languages/Technologies:
- Python (1,234 files) - Django framework detected
- JavaScript (567 files) - React detected
- Dockerfile (3 files)

### Rulesets to Run:

**Security Baseline (always included):**
- [x] `p/security-audit` - Comprehensive security rules
- [x] `p/secrets` - Hardcoded credentials, API keys

**Python (1,234 files):**
- [x] `p/python` - Python security patterns
- [x] `p/django` - Django-specific vulnerabilities

**JavaScript (567 files):**
- [x] `p/javascript` - JavaScript security patterns
- [x] `p/react` - React-specific issues
- [x] `p/nodejs` - Node.js server-side patterns

**Docker (3 files):**
- [x] `p/dockerfile` - Dockerfile best practices

**Third-party (auto-included for detected languages):**
- [x] Trail of Bits rules - https://github.com/trailofbits/semgrep-rules

**Available but not selected:**
- [ ] `p/owasp-top-ten` - OWASP Top 10 (overlaps with security-audit)

### Execution Strategy:
- Spawn 3 parallel scan Tasks (Python, JavaScript, Docker)
- Total rulesets: 9
- [If Pro] Cross-file taint tracking enabled
- Scan agent: `static-analysis:semgrep-scanner`

**Want to modify rulesets?** Tell me which to add or remove.
**Ready to scan?** Say "proceed" or "yes".
```

**⛔ STOP: Await explicit user approval**

After presenting the plan:

1. **If user wants to modify rulesets:**
   - Add requested rulesets to the appropriate category
   - Remove requested rulesets
   - Re-present the updated plan
   - Return to waiting for approval

2. **Use AskUserQuestion** if user hasn't responded:
   ```
   "I've prepared the scan plan with 9 rulesets (including Trail of Bits). Proceed with scanning?"
   Options: ["Yes, run scan", "Modify rulesets first"]
   ```

3. **Valid approval responses:**
   - "yes", "proceed", "approved", "go ahead", "looks good", "run it"

4. **Mark task completed** only after approval with final rulesets confirmed

5. **Do NOT treat as approval:**
   - User's original request ("scan this codebase")
   - Silence / no response
   - Questions about the plan

### Pre-Scan Checklist

Before marking Step 3 complete, verify:
- [ ] Target directory shown to user
- [ ] Engine type (Pro/OSS) displayed
- [ ] Languages detected and listed
- [ ] **All rulesets explicitly listed with checkboxes**
- [ ] User given opportunity to modify rulesets
- [ ] User explicitly approved (quote their confirmation)
- [ ] **Final ruleset list captured for Step 4**
- [ ] Agent type listed: `static-analysis:semgrep-scanner`

### Step 4: Spawn Parallel Scan Tasks

Create output directory with run number to avoid collisions, then spawn Tasks with **approved rulesets from Step 3**:

```bash
# Find next available run number
LAST=$(ls -d semgrep-results-[0-9][0-9][0-9] 2>/dev/null | sort | tail -1 | grep -o '[0-9]*$' || true)
NEXT_NUM=$(printf "%03d" $(( ${LAST:-0} + 1 )))
OUTPUT_DIR="semgrep-results-${NEXT_NUM}"
mkdir -p "$OUTPUT_DIR"
echo "Output directory: $OUTPUT_DIR"
```

**Spawn N Tasks in a SINGLE message** (one per language category) using `subagent_type: static-analysis:semgrep-scanner`.

Use the scanner task prompt template from [scanner-task-prompt.md](references/scanner-task-prompt.md).

**Mode-dependent scanner flags:**
- **Run all**: No additional flags
- **Important only**: Add `--severity MEDIUM --severity HIGH --severity CRITICAL` to every `semgrep` command (set `[SEVERITY_FLAGS]` in the template)

**Example - 3 Language Scan (with approved rulesets):**

Spawn these 3 Tasks in a SINGLE message:

1. **Task: Python Scanner**
   - Approved rulesets: p/python, p/django, p/security-audit, p/secrets, https://github.com/trailofbits/semgrep-rules
   - Output: semgrep-results-001/python-*.json

2. **Task: JavaScript Scanner**
   - Approved rulesets: p/javascript, p/react, p/nodejs, p/security-audit, p/secrets, https://github.com/trailofbits/semgrep-rules
   - Output: semgrep-results-001/js-*.json

3. **Task: Docker Scanner**
   - Approved rulesets: p/dockerfile
   - Output: semgrep-results-001/docker-*.json

### Step 5: Merge Results and Report (Main Agent)

After all scan Tasks complete, apply mode-dependent filtering (if applicable), then generate merged SARIF and report.

**Important-only mode: Post-filter before merge**

In important-only mode, filter each scan result JSON to remove non-security and low-confidence findings before merging. See [scan-modes.md](references/scan-modes.md) for the complete jq filter.

```bash
# Apply important-only filter to all scan result JSON files
for f in "$OUTPUT_DIR"/*-*.json; do
  [[ "$f" == *-important.json ]] && continue
  jq '{
    results: [.results[] |
      ((.extra.metadata.category // "security") | ascii_downcase) as $cat |
      ((.extra.metadata.confidence // "HIGH") | ascii_upcase) as $conf |
      ((.extra.metadata.impact // "HIGH") | ascii_upcase) as $imp |
      select(
        ($cat == "security") and
        ($conf == "MEDIUM" or $conf == "HIGH") and
        ($imp == "MEDIUM" or $imp == "HIGH")
      )
    ],
    errors: .errors,
    paths: .paths
  }' "$f" > "${f%.json}-important.json"
done
```

**Generate merged SARIF:**

```bash
uv run scripts/merge_triaged_sarif.py [OUTPUT_DIR]
```

This script:
1. Attempts to use [SARIF Multitool](https://www.npmjs.com/package/@microsoft/sarif-multitool) for merging (if `npx` is available)
2. Falls back to pure Python merge if Multitool unavailable
3. Merges all `*.sarif` files into a single SARIF output
4. Writes output to `[OUTPUT_DIR]/findings.sarif`

**Optional: Install SARIF Multitool for better merge quality:**

```bash
npm install -g @microsoft/sarif-multitool
```

**Report to user:**

```
## Semgrep Scan Complete

**Scanned:** 1,804 files
**Rulesets used:** 9 (including Trail of Bits)
**Total findings:** 156

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
- semgrep-results-001/findings.sarif (merged SARIF)
- semgrep-results-001/*.json (raw scan results per ruleset)
- semgrep-results-001/*.sarif (raw SARIF per ruleset)
```

---

## Common Mistakes

| Mistake | Correct Approach |
|---------|------------------|
| Running without `--metrics=off` | Always use `--metrics=off` to prevent telemetry |
| Running rulesets sequentially | Run in parallel with `&` and `wait` |
| Not scoping rulesets to languages | Use `--include="*.py"` for language-specific rules |
| Single-threaded for multi-lang | Spawn parallel Tasks per language |
| Sequential Tasks | Spawn all Tasks in SINGLE message for parallelism |
| Using OSS when Pro is available | Check login status; use `--pro` for deeper analysis |
| Assuming Pro is unavailable | Always check with login detection before scanning |
| Passing GitHub URLs directly to `--config` | Clone repos into `[OUTPUT_DIR]/repos/` first; semgrep's URL handling fails on repos with non-standard YAML |
| Leaving cloned repos on disk after scan | Delete `[OUTPUT_DIR]/repos/` after all scans complete |
| Using `.` or relative path as `[TARGET]` | Always use an absolute path for `[TARGET]` to avoid ambiguity in subagents |

## Limitations

1. **OSS mode:** Cannot track data flow across files (login with `semgrep login` and run `semgrep install-semgrep-pro` to enable)
2. **Pro mode:** Cross-file analysis uses `-j 1` (single job) which is slower per ruleset, but parallel rulesets compensate

## Agents

This plugin provides a specialized agent for the scan phase:

| Agent | Tools | Purpose |
|-------|-------|---------|
| `static-analysis:semgrep-scanner` | Bash | Executes parallel semgrep scans for a language category |

Use `subagent_type: static-analysis:semgrep-scanner` in Step 4 when spawning Task subagents.

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "User asked for scan, that's approval" | Original request ≠ plan approval; user must confirm specific parameters. Present plan, use AskUserQuestion, await explicit "yes" |
| "Step 3 task is blocking, just mark complete" | Lying about task status defeats enforcement. Only mark complete after real approval |
| "I already know what they want" | Assumptions cause scanning wrong directories/rulesets. Present plan with all parameters for verification |
| "Just use default rulesets" | User must see and approve exact rulesets before scan |
| "Add extra rulesets without asking" | Modifying approved list without consent breaks trust |
| "Skip showing ruleset list" | User can't make informed decision without seeing what will run |
| "Third-party rulesets are optional" | Trail of Bits, 0xdea, Decurity rules catch vulnerabilities not in official registry - they are REQUIRED when language matches |
| "Run one ruleset at a time" | Wastes time; parallel execution is faster |
| "Use --config auto" | Sends metrics; less control over rulesets |
| "One Task at a time" | Defeats parallelism; spawn all Tasks together |
| "Pro is too slow, skip --pro" | Cross-file analysis catches 250% more true positives; worth the time |
| "Don't bother checking for Pro" | Missing Pro = missing critical cross-file vulnerabilities |
| "OSS is good enough" | OSS misses inter-file taint flows; always prefer Pro when available |
| "Semgrep handles GitHub URLs natively" | URL handling is unreliable for repos with non-standard YAML (floats as keys, etc.); always clone first |
| "Cleanup is optional" | Cloned repos left behind pollute the user's workspace and accumulate across runs |
