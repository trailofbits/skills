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

## Step 1: Resolve Output Directory, Detect Languages and Pro Availability

> **Entry:** User has specified or confirmed the target directory.
> **Exit:** `OUTPUT_DIR` resolved and created; language list with file counts produced; Pro availability determined.

### Resolve Output Directory

If the user specified an output directory in their prompt, use it as `OUTPUT_DIR`. Otherwise, auto-increment. In both cases, **always `mkdir -p`** to ensure the directory exists.

```bash
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  BASE="static_analysis_semgrep"
  N=1
  while [ -e "${BASE}_${N}" ]; do
    N=$((N + 1))
  done
  OUTPUT_DIR="${BASE}_${N}"
fi
mkdir -p "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results"

# Absolute from here on. run-scans.sh rejects a relative path, and that rejection lands
# *after* the user has passed the hard gate, so a path this skill generated itself would send
# them back through approval.
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
# The -d test first: `cd ""` returns 0, so a TARGET that was never bound would pass a bare
# `cd || exit` and silently resolve to the session's CWD, scanning whatever happens to be there.
[ -n "$TARGET" ] && [ -d "$TARGET" ] || { echo "ERROR: TARGET is unset or not a directory"; exit 1; }
TARGET=$(cd "$TARGET" && pwd)
echo "Output directory: $OUTPUT_DIR"
echo "Target: $TARGET"
```

Pass `$TARGET` and `$OUTPUT_DIR` to Step 4 exactly as resolved here. Do not re-derive either.

`$OUTPUT_DIR` is used by all subsequent steps. Raw per-scan output goes to `$OUTPUT_DIR/raw/`; merged and filtered results go to `$OUTPUT_DIR/results/`.

**Detect Pro availability** (requires Bash):

```bash
if ! command -v semgrep >/dev/null 2>&1; then
  echo "ERROR: semgrep is not installed. Install from https://semgrep.dev/docs/getting-started/"
  exit 1
fi
semgrep --version
# --metrics=off applies here too. This is the first semgrep invocation of the run and it
# resolves p/default against the registry, so without the flag an audit phones home before
# the user has approved anything. Principle 1 has no exceptions.
semgrep --pro --validate --metrics=off --config p/default 2>/dev/null && echo "Pro: AVAILABLE" || echo "Pro: NOT AVAILABLE"
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
**Output directory:** $OUTPUT_DIR
**Engine:** Semgrep Pro (cross-file analysis) | Semgrep OSS (single-file)
**Scan mode:** Run all | Important only (security vulns, medium-high confidence/impact)
[in important-only mode, add:] Note: important-only passes --severity WARNING --severity ERROR
to every command, including the third-party repos. Trail of Bits / 0xdea / Decurity rules that
ship with CLI severity INFO are dropped at scan time, before the metadata filter that would
otherwise keep them. Choose "Run all" if you want those.

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

### Log Approved Rulesets

After approval, write the approved plan to `$OUTPUT_DIR/rulesets.json`. This is the same file
Step 4 hands to the scanner: what the user approved and what runs are one artifact, so there is
no second copy to transcribe and no way for the two to disagree.

Fill in the plan that was just approved. Every value is an array, even a single ruleset:

```bash
cat > "$OUTPUT_DIR/rulesets.json" << 'RULESETS'
{
  "baseline": [<the always-on rulesets from Step 2>],
  "<each detected language>": [<its approved rulesets>],
  "third_party": [<approved repository URLs>]
}
RULESETS
```

One key per language *detected in Step 1*, using the lowercase names from that step. A language
key for a language the target does not contain scans nothing: its `--include` globs match no
file, semgrep exits 0 with an empty result, and the report shows the ruleset with 0 findings
exactly as it would for a ruleset that ran and found nothing. The script counts the files each
scan opened and lists any that covered nothing under `coveredNothing` in `scans.json`, but
getting the languages right here is what stops it happening.

Repository URLs go under `third_party` and nowhere else. Registry identifiers like `p/python`
go under a language key; a `https://…` there fails the identifier check and the script exits
without scanning.

---

## Step 4: Run the Scans

> **Entry:** Step 3 approved — user explicitly confirmed the plan.
> **Exit:** `$OUTPUT_DIR/scans.json` exists; result files exist in `$OUTPUT_DIR/raw/`.

Run the script against the plan Step 3 already wrote. One Bash call; there is no subagent in
this step, and no second copy of the ruleset list to compose here.

```bash
{baseDir}/scripts/run-scans.sh \
  --target "$TARGET" \
  --output-dir "$OUTPUT_DIR" \
  --mode run-all \
  --rulesets "$OUTPUT_DIR/rulesets.json"
```

Do not rewrite `rulesets.json` here. It is the plan the user approved at the Step 3 gate, and
regenerating it at this point is how a ruleset nobody agreed to reaches the scanner. If it needs
to change, go back to Step 3 and get the change approved.

`--mode` is `run-all` or `important-only`. Add `--pro` only when Step 1
printed `Pro: AVAILABLE`; it puts `--pro` on every command, so passing it without a licence
fails every scan in the run. `--jobs N` sets how many semgrep processes run at once (default 4);
semgrep holds the rules and the scanned ASTs in memory, so raising it on a large tree trades
memory for wall-clock.

Repository URLs go under `third_party` and nowhere else. A `https://…` under a language key
fails the registry-identifier check and the script exits without scanning.

The script clones each third-party repo once, generates every `semgrep` command, and runs them
in batches. `--metrics=off`, the `--include` scoping rule, `--exclude` for the output directory
and the severity flags are all its job, not yours. It writes `$OUTPUT_DIR/scans.json`:

| Field | Meaning |
|-------|---------|
| `scans` | Rulesets that ran, with `json`, `sarif`, `findings` and `filesScanned` for each. `findings` is counted from the JSON the scan wrote; `filesScanned` is how many files semgrep opened, or `-1` when it did not say |
| `coveredNothing` | Rulesets that ran against zero files, because their `--include` globs matched nothing in the target. They report 0 findings exactly like a ruleset that ran and found nothing, so a plan naming a language the target does not contain reads as a clean audit. **Must be shown.** |
| `failed` | Rulesets that ran and did not produce usable output, with the `json` and `sarif` paths they may have partly written, and the stderr excerpt. **Must be shown to the user.** |
| `skipped` | Rulesets dropped before scanning, mostly repos that would not clone. **Must be shown.** |
| `unscoped` | Languages with no `--include` globs, which ran against every file |
| `alsoShared` | Rulesets dropped from a language because the same ruleset is already running unscoped over the whole target. Coverage is unaffected; report them so a per-ruleset accounting adds up |
| `excludePattern` | Set when the output directory sits inside the target: the pattern passed as `--exclude` to every scan, or `""`. semgrep matches it anywhere in the tree, so `out` also drops `src/out/`. **Must be shown when non-empty.** |
| `reposPath` | The clone directory Step 5 deletes |

**A non-zero exit means no scan succeeded.** The script exits 1 when `scans` is empty, so a run
that produced nothing fails loudly rather than handing Step 5 an empty result to report as zero
findings. Read the message, say that no scan ran, and stop; do not retry with adjusted
arguments, because the approved plan is what produced them.

**If `failed` or `skipped` is non-empty**, carry both into the Step 5 report. A run that covered
four of nine rulesets reads exactly like one that covered four of four unless you say otherwise.

---

## Step 5: Merge Results and Report

> **Entry:** Step 4 complete — the workflow returned.
> **Exit:** `results.sarif` exists in `$OUTPUT_DIR/results/` and is valid JSON; `repos/` deleted.

Read the result with `jq` from `$OUTPUT_DIR/scans.json`. Every entry there was written after
the script checked the exit code and confirmed both output files were non-empty, so the entries
do not need re-verifying.

**Important-only mode: Post-filter before merge.** Apply the filter from [scan-modes.md](../references/scan-modes.md) ("Filter All Result Files in a Directory" section) to each result JSON in `$OUTPUT_DIR/raw/`. The filter creates `*-important.json` files alongside the originals — the originals are preserved unmodified.

**Generate merged SARIF** using the merge script. The resolved path is in SKILL.md's "Merge command" section — use that exact path:

```bash
# run-all
uv run {baseDir}/scripts/merge_sarif.py "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results/results.sarif" \
  --scans "$OUTPUT_DIR/scans.json"

# important-only, once the post-filter above has run over every file in raw/
uv run {baseDir}/scripts/merge_sarif.py "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results/results.sarif" \
  --important --scans "$OUTPUT_DIR/scans.json"
```

- **Run-all mode:** The script merges all `*.sarif` files from `$OUTPUT_DIR/raw/`.
- **Important-only mode:** `--important` is not optional. The JSON post-filter does not touch the
  SARIF files the merge reads, so without that flag `results.sarif` keeps every finding the mode
  exists to exclude while the JSON side is correctly filtered, and the Total findings counted from
  it is the run-all total.

  Do **not** try to run the jq filter from scan-modes.md against a `.sarif` file. It reads
  `.results[].extra.metadata`, which SARIF does not have — there is no top-level `.results` at
  all — so it exits with `Cannot iterate over null` and, if redirected over its own input,
  truncates the merged SARIF to nothing. `--important` matches findings across the two formats on
  `(rule, file, line)`, the same key the merge dedups on, and fails rather than filtering if any
  scan in `raw/` has no `*-important.json` beside it.

**Verify merged SARIF is valid:**

```bash
python -c "import json; d=json.load(open('$OUTPUT_DIR/results/results.sarif')); print(f'{sum(len(r.get(\"results\",[]))for r in d.get(\"runs\",[]))} findings in merged SARIF')"
```

If verification fails, the merge script produced invalid output — investigate before reporting.

**Delete the cloned rulesets** once the merge has succeeded. The workflow clones each
third-party repo into `repos/` and leaves it there for the scanners; this is the only place
the deletion happens, and nothing that reads it is still running by now.

```bash
[ -n "$OUTPUT_DIR" ] && rm -rf "$OUTPUT_DIR/repos"
```

**Report to user:**

```
## Semgrep Scan Complete

**Scanned:** 1,804 files
**Rulesets used:** 9 (including Trail of Bits)
**Total findings:** 156   [count this from results.sarif, never by summing scans[].findings:
one finding flagged by two rulesets is one row in the merge and two in that sum]

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

### Did Not Run:
[omit this section only when failed and skipped are both empty]
- Skipped: <ruleset> — <reason from the workflow>
- Failed: <ruleset> — <error from the workflow>

### Also Covered Unscoped:
[omit when alsoShared is empty]
- <ruleset> — already running over the whole target from the baseline, so it was not scanned
  again under <language>. Coverage is unaffected; this is why the ruleset count and the scan
  count differ

### Ran Unscoped:
[omit when unscoped is empty]
- <language> — no --include map, so its rulesets ran against every file

### Covered Nothing:
[omit when coveredNothing is empty]
- <language>/<ruleset> — matched no file in the target, so it reports 0 findings without having
  looked at anything. Check the plan against the languages Step 1 detected: this is what a
  ruleset for a language the target does not contain looks like

### Missing From The Merge:
[omit when the merge printed no "unparseable:" line]
- <file> — the scan succeeded and is counted in scans.json, but its SARIF could not be parsed,
  so its findings are not in results.sarif. The total below is short by that scan's `findings`
  count from scans.json

### Excluded From Every Scan:
[omit when excludePattern is empty]
- <excludePattern> — the output directory sits inside the target, so this pattern was excluded
  from every scan. semgrep matches it anywhere in the tree, so any other directory with that
  name was skipped too. Move the output directory outside the target to scan those files

Results written to:
- $OUTPUT_DIR/results/results.sarif (merged SARIF)
- $OUTPUT_DIR/raw/ (per-scan raw results, unfiltered)
- $OUTPUT_DIR/rulesets.json (the approved plan, as passed to the scanner)
```

**Verify** before reporting: confirm `results.sarif` exists and is valid JSON.
