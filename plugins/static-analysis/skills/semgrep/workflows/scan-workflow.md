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

`**/*.py`, `**/*.pyi`, `**/*.js`, `**/*.jsx`, `**/*.mjs`, `**/*.cjs`, `**/*.ts`, `**/*.tsx`, `**/*.go`, `**/*.rb`, `**/*.java`, `**/*.jsp`, `**/*.kt`, `**/*.kts`, `**/*.php`, `**/*.phtml`, `**/*.c`, `**/*.cc`, `**/*.cpp`, `**/*.cxx`, `**/*.h`, `**/*.hh`, `**/*.hpp`, `**/*.hxx`, `**/*.cs`, `**/*.rs`, `**/*.scala`, `**/*.swift`, `**/*.ex`, `**/*.exs`, `**/*.cls`, `**/*.trigger`, `**/*.sol`, `**/Dockerfile`, `**/*.dockerfile`, `**/*.tf`, `**/*.tfvars`, `**/*.hcl`, `**/*.yaml`, `**/*.yml`, `**/*.json`

Step 2 can only select a ruleset for a category this step detected, so an extension missing here removes its ruleset from the scan with no signal — the report then reads clean rather than incomplete. The list is the union of the `includes_for` globs in [run-scans.sh](../scripts/run-scans.sh); keep the two in sync when either changes. `.mts`, `.cts`, `.C`, `Containerfile`, and `Dockerfile.prod` are absent from both, because semgrep does not parse them.

**Two extensions are matched by glob but assigned by content, not by extension.** `.yaml`/`.yml` and `.json` each feed several categories, and both are common in repositories that have no infrastructure to scan at all — nearly every project carries `package.json`, `tsconfig.json` and a lockfile. Assigning a category from the extension alone would attach an AWS IAM ruleset to every scan and report a JSON "language" for a project that has none. Assigning nothing would leave `r/json.aws` and JSON-format CloudFormation unreachable, which is worse: an unselected category never enters `rulesets.json`, so it cannot appear in `coveredNothing`, `failed` or `skipped` either, and the report reads clean. Glob for both, then read a sample and assign on the markers below.

Also check for framework markers: `**/package.json`, `**/pyproject.toml`, `**/requirements.txt`, `**/Gemfile`, `**/composer.json`, `**/go.mod`, `**/Cargo.toml`, `**/pom.xml`. Use Read to inspect these files for framework dependencies (e.g., read `package.json` to detect React, Express, Next.js; read `pyproject.toml` for Django, Flask, FastAPI). The `**/` prefix is required, not cosmetic: a bare `package.json` matches only the target root, so a monorepo with `packages/*/package.json` or `services/*/go.mod` gets no framework rulesets at all.

Map findings to categories:

| Detection | Category |
|-----------|----------|
| `.py`, `.pyi`, `pyproject.toml`, `requirements.txt` | Python |
| `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `package.json` | JavaScript/TypeScript |
| `.go`, `go.mod` | Go |
| `.rb`, `Gemfile` | Ruby |
| `.java`, `.jsp`, `pom.xml` | Java |
| `.kt`, `.kts` | Kotlin |
| `.php`, `.phtml`, `composer.json` | PHP |
| `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`, `.hxx` | C/C++ |
| `.cs` | C# |
| `.rs`, `Cargo.toml` | Rust |
| `.scala` | Scala |
| `.swift` | Swift |
| `.ex`, `.exs` | Elixir |
| `.cls`, `.trigger` | Apex |
| `.sol` | Solidity |
| `Dockerfile`, `.dockerfile` | Docker |
| `.tf`, `.tfvars`, `.hcl` | Terraform |
| `.yaml`, `.yml` | YAML, Kubernetes, GitHub Actions, or CloudFormation — disambiguate below |
| `.json` | CloudFormation or JSON, or no category at all — disambiguate below |

**Disambiguating YAML.** One `.yaml`/`.yml` match feeds four categories, so Read a sample of the matches before assigning:

- path under `.github/workflows/` → GitHub Actions
- `apiVersion:` together with `kind:` → Kubernetes
- `AWSTemplateFormatVersion:`, or `Resources:` with a `Type: AWS::` member → CloudFormation
- anything else → YAML

These are not exclusive; assign every category that matches. Include the generic YAML category whenever any YAML is present, since `p/yaml` carries patterns the specific rulesets do not.

**Disambiguating JSON.** Unlike YAML, `.json` has no catch-all: most JSON in a repository is build configuration that no ruleset covers, so the default is to assign nothing. Read a sample and assign only on these markers:

- `"AWSTemplateFormatVersion"`, or `"Resources"` whose members carry a `"Type": "AWS::…"` → CloudFormation
- a `"Statement"` array whose elements have `"Effect"` → JSON (this is the IAM policy shape `r/json.aws` targets)
- anything else, including `package.json`, `tsconfig.json`, `composer.json`, lockfiles and editor settings → **no category**

Do not report a `json` category because JSON files exist. Report it when a sampled file has the IAM policy shape. Prefer sampling files whose path suggests infrastructure — `iam/`, `policies/`, `cloudformation/`, `infra/`, `*template*.json` — since a repository with thousands of JSON files will have its IAM policies outnumbered by build configuration, and a sample drawn without regard to path is likely to miss them.

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
| `scans` | Rulesets that ran, with `json`, `sarif`, `findings`, `filesScanned`, `partial` and `exitCode` for each. `findings` is counted from the JSON the scan wrote; `filesScanned` is how many files semgrep opened, or `-1` when it did not say; `exitCode` is what semgrep exited with |
| `scans[].partial` | `true` when the scan wrote complete output while some of its rules failed to compile — semgrep exits 2 and reports the rest of the run normally. The findings are real and in the merge; the rules that never compiled found nothing and cannot say so, so this reads as an unqualified success unless it is called out. **Must be shown.** |
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
The same line is why any scan with `partial: true` is carried across as well: it is in `scans` as
a success, so the rules of it that never ran are invisible in every count the report otherwise
prints.

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
uv run --no-project {baseDir}/scripts/merge_sarif.py "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results/results.sarif" \
  --scans "$OUTPUT_DIR/scans.json"

# important-only, once the post-filter above has run over every file in raw/
uv run --no-project {baseDir}/scripts/merge_sarif.py "$OUTPUT_DIR/raw" "$OUTPUT_DIR/results/results.sarif" \
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

### Ran Partially:
[omit when no scan has partial: true]
- <ruleset> — ran and wrote full output, but some of its rules failed to compile (semgrep exit
  <exitCode>). Its findings are in the total below; the rules that did not compile scanned
  nothing, so this ruleset's coverage is narrower than its entry in the scan count suggests

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
