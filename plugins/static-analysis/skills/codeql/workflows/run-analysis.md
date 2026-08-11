# Run Analysis Workflow

Execute CodeQL security queries on an existing database with ruleset selection and result formatting.

## Scan Modes

Two modes control analysis scope. Both use all installed packs — the difference is filtering.

| Mode | Description | Suite Reference |
|------|-------------|-----------------|
| **Run all** | The `security-and-quality` + `security-experimental` suites from every installed pack. Not literally every query in the packs — see [run-all-suite.md](../references/run-all-suite.md) | [run-all-suite.md](../references/run-all-suite.md) |
| **Important only** | Security queries filtered by precision and security-severity threshold | [important-only-suite.md](../references/important-only-suite.md) |

> **WARNING:** Do NOT pass pack names directly to `codeql database analyze` (e.g., `-- codeql/cpp-queries`). Each pack's `defaultSuiteFile` silently applies strict filters and can produce zero results. Always use an explicit suite reference.

---

## The one gate

Ask once, in Step 3, and present everything the run depends on together: scan mode, query
packs, model packs, and threat model.

Let the user change any part, then proceed. If the user already specified something in
their prompt, show it as chosen rather than asking again.

---

## Steps

### Step 1: Select Database and Detect Language

**Entry:** `$OUTPUT_DIR` is set (from parent skill). `$DB_NAME` may already be set if the parent skill resolved database selection.
**Exit:** `DB_NAME` and `CODEQL_LANG` variables set; database resolves successfully.

**If `$DB_NAME` is already set** (parent skill handled database selection): validate it and proceed.

**If `$DB_NAME` is not set:** discover databases with `find_databases.sh`, which filters
candidates through `codeql resolve database` so a marker file left behind by a failed
build cannot be selected as though it were a database.

```bash
# Discovery and selection must share a block: an array built in an earlier Bash call is
# gone by this one, and an empty FOUND_DBS reads as "no database" for a project that has
# one. The script is what SKILL.md's Database Discovery section calls too, so the search
# depth and the validity filter are defined once.
if [ -z "${DB_NAME:-}" ]; then
  # Command substitution, not `done < <(...)`: a process substitution discards the script's
  # exit status, so exit 2 ("codeql not on this shell's PATH" — a fresh shell each block,
  # so the preflight's PATH does not carry) would arrive here as an empty list and be
  # reported as "No CodeQL database found" for a project that has several.
  if ! DB_LIST=$("{baseDir}/scripts/find_databases.sh" "${OUTPUT_DIR:-.}" .); then
    echo "ERROR: database discovery failed — see the message above" >&2
    exit 1
  fi

  FOUND_DBS=()
  while IFS= read -r db; do
    [ -n "$db" ] || continue
    FOUND_DBS+=("$db")
  done <<<"$DB_LIST"

  if [ "${#FOUND_DBS[@]}" -eq 0 ]; then
    echo "ERROR: No CodeQL database found in $OUTPUT_DIR or project root" >&2
    exit 1
  elif [ "${#FOUND_DBS[@]}" -eq 1 ]; then
    DB_NAME="${FOUND_DBS[0]}"
  else
    # More than one: select with AskUserQuestion, at most four options — the three most
    # recent plus "Build a new database", the rest named in the prompt text. Skip the
    # prompt when the user already said which database to use.
    #
    # DB_NAME stays unset here on purpose, and the check below turns that into an error.
    # Falling through to FOUND_DBS[0] would analyse whichever database `find` happened to
    # return first — a different language or a stale build, chosen without the user ever
    # being told there was a choice. The `:` is required: an else branch of only comments
    # is a bash syntax error.
    :
  fi
fi

if [ -z "${DB_NAME:-}" ]; then
  echo "ERROR: more than one database found. Ask which one, then re-run this block with DB_NAME set." >&2
  exit 1
fi

CODEQL_LANG=$(codeql resolve database --format=json -- "$DB_NAME" | jq -r '.languages[0]')
echo "Using: $DB_NAME (language: $CODEQL_LANG)"
```

If the database holds more than one language, ask which to analyze.

---

### Step 2: Gather What the Run Depends On

**Entry:** Step 1 complete (`DB_NAME` and `CODEQL_LANG` set)
**Exit:** Scan mode, installed packs, and model packs determined. Nothing presented to the user yet.

Collect everything here and present it as one plan in Step 3. Default the scan mode to
**run all** unless the user's prompt says otherwise.

#### 2a: Query Packs

For each pack available for the detected language (see [ruleset-catalog.md](../references/ruleset-catalog.md)):

| Language | Trail of Bits | Community Pack |
|----------|---------------|----------------|
| C/C++ | `trailofbits/cpp-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-CPP` |
| Go | `trailofbits/go-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-Go` |
| Java | `trailofbits/java-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-Java` |
| JavaScript | — | `GitHubSecurityLab/CodeQL-Community-Packs-JavaScript` |
| Python | — | `GitHubSecurityLab/CodeQL-Community-Packs-Python` |
| C# | — | `GitHubSecurityLab/CodeQL-Community-Packs-CSharp` |
| Ruby | — | `GitHubSecurityLab/CodeQL-Community-Packs-Ruby` |

Check if installed (`codeql resolve qlpacks | grep -i "<PACK_NAME>"`). If not, ask user to install or ignore.

#### 2b: Detect Model Packs

Search three locations for data extension model packs:
1. **In-repo model packs** — `qlpack.yml`/`codeql-pack.yml` with `dataExtensions`
2. **In-repo standalone data extensions** — `.yml` files with `extensions:` key
3. **Installed model packs** — resolved by CodeQL

Record all detected packs for Step 3.

---

### Step 3: Confirm the Plan

**Entry:** Step 2 complete (mode, pack availability, and model packs all determined)
**Exit:** User confirmed; flag arrays built (`THREAT_MODEL_FLAGS`, `MODEL_PACK_FLAGS`, `ADDITIONAL_PACK_FLAGS`)

Present the whole plan in one `AskUserQuestion`, defaults filled in, and let the user
change any part before proceeding:

```
## CodeQL Analysis Plan

**Database:** $DB_NAME (language: $CODEQL_LANG)
**Scan mode:** Run all | Important only
**Query packs:** <installed packs — official, Trail of Bits, Community>
**Model packs:** <detected packs, or "None">
**Threat model:** Remote only (default) | + Local | All sources

Change anything, or say proceed.
```

Defaults, all overridable: **run all**, every installed pack, every detected model pack,
and **remote-only** threat models. Remote-only matches CodeQL's default. Widen it for CLI
tools, file parsers, and config readers, where the sources are `local` rather than
`remote`. See [threat-models.md](../references/threat-models.md).

Build the flags from the answer as arrays: `THREAT_MODEL_FLAGS=()` for remote-only,
`THREAT_MODEL_FLAGS=(--threat-model local)`, and so on. See Step 4 for why arrays rather
than strings.

**Model pack flags:**
- In-repo standalone extensions (`.yml`) are auto-discovered — pass source directory via `--additional-packs`
- In-repo model packs (with `qlpack.yml`) need parent directory via `--additional-packs`
- Installed model packs use `--model-packs`

---

### Step 4: Execute Analysis

**Entry:** Step 3 complete (all flags and pack selections finalized)
**Exit:** `$RAW_DIR/results.sarif` exists and contains valid SARIF output

#### Log selected query packs

Write the selected query packs, model packs, and threat models to `$OUTPUT_DIR/rulesets.txt`:

```bash
cat > "$OUTPUT_DIR/rulesets.txt" << RULESETS
# CodeQL Analysis — Selected Query Packs
# Generated: $(date -Iseconds)
# Scan mode: <run-all|important-only>
# Database: $DB_NAME
# Language: $CODEQL_LANG

## Query packs:
<one pack per line>

## Model packs:
<one pack per line, or "None">

## Threat models:
<threat model selection, or "default (remote)">
RULESETS
```

#### Generate custom suite

**Important-only mode:** Generate the custom `.qls` suite using the template and script in [important-only-suite.md](../references/important-only-suite.md).

**Run-all mode:** Generate the custom `.qls` suite using the template in [run-all-suite.md](../references/run-all-suite.md).

```bash
set -euo pipefail

RAW_DIR="$OUTPUT_DIR/raw"
RESULTS_DIR="$OUTPUT_DIR/results"
mkdir -p "$RAW_DIR" "$RESULTS_DIR"
# SCAN_MODE is "run-all" or "important-only", chosen in Step 3.
SUITE_FILE="$RAW_DIR/${SCAN_MODE}.qls"
```

The generation scripts above end by running `verify_query_suite.py`, so a suite produced
here is already checked. **Run it explicitly only if the suite came from somewhere else** —
reused from a previous run, or hand-edited:

```bash
uv run {baseDir}/scripts/verify_query_suite.py "$SUITE_FILE"
```

#### Run analysis

Output goes to `$RAW_DIR/results.sarif` (unfiltered). The final results are produced in Step 5.

Build the optional flags as **arrays**, not strings. A quoted empty string becomes an
empty argument that CodeQL rejects, and leaving a string unquoted so it can be empty also
lets `$DB_NAME` split on spaces. An array expands to nothing when empty and to each
element intact otherwise.

Expand them as `"${ARRAY[@]+"${ARRAY[@]}"}"`, not `"${ARRAY[@]}"`. Before bash 4.4 an
empty array under `set -u` is an unbound variable, so on macOS's `/bin/bash` 3.2 the plain
form aborts with `THREAT_MODEL_FLAGS[@]: unbound variable` before CodeQL runs — for the
documented default, a user who selected no threat models and no model packs.

**Declare the three arrays and the scalars in this block, filled in with the choices from
Step 3.** Nothing survives from Step 3 — see
[Each Bash call is a fresh shell](../SKILL.md#each-bash-call-is-a-fresh-shell). Leaving an
array empty is correct only when Step 3 selected nothing for it.

```bash
set -euo pipefail

DB_NAME="${DB_NAME:?set this to the database selected in Step 1}"
RAW_DIR="${RAW_DIR:-$OUTPUT_DIR/raw}"
SUITE_FILE="${SUITE_FILE:?set this to the .qls written in Step 2}"
mkdir -p "$RAW_DIR"

# Fill these from the Step 3 answers. Empty means "the user chose none".
THREAT_MODEL_FLAGS=()        # e.g. (--threat-model local --threat-model environment)
MODEL_PACK_FLAGS=()          # e.g. (--model-packs myorg/java-models)
ADDITIONAL_PACK_FLAGS=()     # e.g. (--additional-packs ./codeql-extensions)

codeql database analyze "$DB_NAME" \
  --format=sarif-latest \
  --output="$RAW_DIR/results.sarif" \
  --threads=0 \
  ${THREAT_MODEL_FLAGS[@]+"${THREAT_MODEL_FLAGS[@]}"} \
  ${MODEL_PACK_FLAGS[@]+"${MODEL_PACK_FLAGS[@]}"} \
  ${ADDITIONAL_PACK_FLAGS[@]+"${ADDITIONAL_PACK_FLAGS[@]}"} \
  -- "$SUITE_FILE"
```

`set -e` matters here: a failed analysis (out of memory, an unresolvable model pack) leaves
`raw/results.sarif` truncated or absent, and without it Step 5 copies that file forward and
the report prints "Total findings: 0" for a scan that never completed.

**Flag reference for model packs:**

| Source | Flag | Example |
|--------|------|---------|
| Installed model packs | `--model-packs` | `--model-packs=myorg/java-models` |
| In-repo model packs | `--additional-packs` | `--additional-packs=./lib/codeql-models` |
| In-repo standalone extensions | `--additional-packs` | `--additional-packs=.` |

### Performance

If codebase is large, read [performance-tuning.md](../references/performance-tuning.md) and apply relevant optimizations.

---

### Step 5: Process and Report Results

**Entry:** Step 4 complete (`$RAW_DIR/results.sarif` exists)
**Exit:** `$RESULTS_DIR/results.sarif` contains final results; findings summarized by severity, rule, and location; zero-finding results investigated; final report presented to user

#### Produce final results

- **Run-all mode:** Copy unfiltered results to the final location:
  ```bash
  cp "$RAW_DIR/results.sarif" "$RESULTS_DIR/results.sarif"
  ```

- **Important-only mode:** Apply the post-analysis filter from [sarif-processing.md](../references/sarif-processing.md#important-only-post-filter) to remove medium-precision results with `security-severity` < 6.0. The filter reads from `$RAW_DIR/results.sarif` and writes to `$RESULTS_DIR/results.sarif`, preserving the unfiltered original.

Process the final SARIF output (`$RESULTS_DIR/results.sarif`) using the jq commands in [sarif-processing.md](../references/sarif-processing.md): count findings, summarize by level, summarize by security severity, summarize by rule.

---

## Final Output

Report to user:

```
## CodeQL Analysis Complete

**Output directory:** $OUTPUT_DIR
**Database:** $DB_NAME
**Language:** <LANG>
**Scan mode:** Run all | Important only
**Query packs:** <list of query packs used>
**Model packs:** <list of model packs used, or "None">
**Threat models:** <list of threat models, or "default (remote)">

### Results Summary:
- Total findings: <N>
- Error: <N>
- Warning: <N>
- Note: <N>

### Output Files:
- SARIF (final): $OUTPUT_DIR/results/results.sarif
- SARIF (unfiltered): $OUTPUT_DIR/raw/results.sarif
- Rulesets: $OUTPUT_DIR/rulesets.txt
```
