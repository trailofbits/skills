# Semgrep Scan Workflow

Complete 5-step scan execution process. Read from start to finish and follow each step in order.

## Task System Enforcement

On invocation, create these tasks with dependencies:

```
TaskCreate: "Detect languages and Pro availability" (Step 1)
TaskCreate: "Select scan mode and rulesets" (Step 2) - blockedBy: Step 1
TaskCreate: "Present plan with rulesets, get approval" (Step 3) - blockedBy: Step 2
TaskCreate: "Execute scans with approved rulesets and mode" (Step 4) - blockedBy: Step 3
TaskCreate: "Merge results and report" (Step 5) - blockedBy: Step 4
```

### Mandatory Gate

| Task | Gate Type | Cannot Proceed Until |
|------|-----------|---------------------|
| Step 3 | **HARD GATE** | User explicitly approves rulesets + plan |

Mark Step 3 as `completed` ONLY after user says "yes", "proceed", "approved", or equivalent.

---

## Step 1: Detect Languages and Pro Availability

> **Entry:** User has specified or confirmed the target directory.
> **Exit:** Language list with file counts produced; Pro availability determined.

**Detect Pro availability** (requires Bash):

```bash
semgrep --pro --validate --config p/default 2>/dev/null && echo "Pro: AVAILABLE" || echo "Pro: NOT AVAILABLE"
```

**Detect languages** using Glob (not Bash). Run these patterns against the target directory and count matches:

`**/*.py`, `**/*.js`, `**/*.ts`, `**/*.tsx`, `**/*.jsx`, `**/*.go`, `**/*.rb`, `**/*.java`, `**/*.php`, `**/*.c`, `**/*.cpp`, `**/*.rs`, `**/Dockerfile`, `**/*.tf`

Also check for framework markers: `package.json`, `pyproject.toml`, `Gemfile`, `go.mod`, `Cargo.toml`, `pom.xml`. Use Read to inspect these files for framework dependencies (e.g., read `package.json` to detect React, Express, Next.js; read `pyproject.toml` for Django, Flask, FastAPI).

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

---

## Step 2: Select Scan Mode and Rulesets

> **Entry:** Step 1 complete — languages detected, Pro status known.
> **Exit:** Scan mode selected; structured rulesets JSON compiled for all detected languages.

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

**Then, select rulesets.** Using the detected languages and frameworks from Step 1, follow the **Ruleset Selection Algorithm** in [rulesets.md](../references/rulesets.md).

The algorithm covers:
1. Security baseline (always included)
2. Language-specific rulesets
3. Framework rulesets (if detected)
4. Infrastructure rulesets
5. **Required** third-party rulesets (Trail of Bits, 0xdea, Decurity — NOT optional)
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

---

## Step 3: CRITICAL GATE — Present Plan and Get Approval

> **Entry:** Step 2 complete — scan mode and rulesets selected.
> **Exit:** User has explicitly approved the plan (quoted confirmation).

> **⛔ MANDATORY CHECKPOINT — DO NOT SKIP**
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

**Want to modify rulesets?** Tell me which to add or remove.
**Ready to scan?** Say "proceed" or "yes".
```

**⛔ STOP: Await explicit user approval.**

1. **If user wants to modify rulesets:** Add/remove as requested, re-present the updated plan, return to waiting.
2. **Use AskUserQuestion** if user hasn't responded:
   ```
   "I've prepared the scan plan with N rulesets (including Trail of Bits). Proceed with scanning?"
   Options: ["Yes, run scan", "Modify rulesets first"]
   ```
3. **Valid approval:** "yes", "proceed", "approved", "go ahead", "looks good", "run it"
4. **NOT approval:** User's original request ("scan this codebase"), silence, questions about the plan

### Pre-Scan Checklist

Before marking Step 3 complete:
- [ ] Target directory shown to user
- [ ] Engine type (Pro/OSS) displayed
- [ ] Languages detected and listed
- [ ] **All rulesets explicitly listed with checkboxes**
- [ ] User given opportunity to modify rulesets
- [ ] User explicitly approved (quote their confirmation)
- [ ] **Final ruleset list captured for Step 4**
- [ ] Agent type listed: `static-analysis:semgrep-scanner`

---

## Step 4: Spawn Parallel Scan Tasks

> **Entry:** Step 3 approved — user explicitly confirmed the plan.
> **Exit:** All scan Tasks completed; result files exist in output directory.

**Create output directory** with run number to avoid collisions:

```bash
LAST=$(ls -d semgrep-results-[0-9][0-9][0-9] 2>/dev/null | sort | tail -1 | grep -o '[0-9]*$' || true)
NEXT_NUM=$(printf "%03d" $(( ${LAST:-0} + 1 )))
OUTPUT_DIR="semgrep-results-${NEXT_NUM}"
mkdir -p "$OUTPUT_DIR"
echo "Output directory: $OUTPUT_DIR"
```

**Spawn N Tasks in a SINGLE message** (one per language category) using `subagent_type: static-analysis:semgrep-scanner`.

Use the scanner task prompt template from [scanner-task-prompt.md](../references/scanner-task-prompt.md).

**Mode-dependent scanner flags:**
- **Run all**: No additional flags
- **Important only**: Add `--severity MEDIUM --severity HIGH --severity CRITICAL` to every `semgrep` command

**Example — 3 Language Scan (with approved rulesets):**

Spawn these 3 Tasks in a SINGLE message:

1. **Task: Python Scanner** — Rulesets: p/python, p/django, p/security-audit, p/secrets, trailofbits → `semgrep-results-001/python-*.json`
2. **Task: JavaScript Scanner** — Rulesets: p/javascript, p/react, p/nodejs, p/security-audit, p/secrets, trailofbits → `semgrep-results-001/js-*.json`
3. **Task: Docker Scanner** — Rulesets: p/dockerfile → `semgrep-results-001/docker-*.json`

### Operational Notes

- Always use **absolute paths** for `[TARGET]` — subagents can't resolve relative paths
- Clone GitHub URL rulesets into `[OUTPUT_DIR]/repos/` — never pass URLs directly to `--config` (semgrep's URL handling fails on repos with non-standard YAML)
- Delete `[OUTPUT_DIR]/repos/` after all scans complete
- Run rulesets in parallel with `&` and `wait`, not sequentially
- Use `--include="*.py"` for language-specific rulesets, but NOT for cross-language rulesets (p/security-audit, p/secrets, third-party repos)

---

## Step 5: Merge Results and Report

> **Entry:** Step 4 complete — all scan Tasks finished.
> **Exit:** `findings.sarif` exists in output directory and is valid JSON.

**Important-only mode: Post-filter before merge.** Apply the filter from [scan-modes.md](../references/scan-modes.md) ("Filter All Result Files in a Directory" section) to each result JSON.

**Generate merged SARIF** using the merge script. The resolved path is in SKILL.md's "Merge command" section — use that exact path:

```bash
uv run {baseDir}/scripts/merge_triaged_sarif.py [OUTPUT_DIR]
```

**Verify merged SARIF is valid:**

```bash
python -c "import json; d=json.load(open('[OUTPUT_DIR]/findings.sarif')); print(f'{sum(len(r.get(\"results\",[]))for r in d.get(\"runs\",[]))} findings in merged SARIF')"
```

If verification fails, the merge script produced invalid output — investigate before reporting.

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

**Verify** before reporting: confirm `findings.sarif` exists and is valid JSON.
