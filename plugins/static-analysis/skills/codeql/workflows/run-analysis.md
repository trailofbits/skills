# Run Analysis Workflow

Execute CodeQL security queries on an existing database with ruleset selection and result formatting.

## Scan Modes

Two modes control analysis scope. Both use all installed packs — the difference is filtering.

| Mode | Description | Suite Reference |
|------|-------------|-----------------|
| **Run all** | All queries from all installed packs via `security-and-quality` suite | [run-all-suite.md](../references/run-all-suite.md) |
| **Important only** | Security queries filtered by precision and security-severity threshold | [important-only-suite.md](../references/important-only-suite.md) |

> **WARNING:** Do NOT pass pack names directly to `codeql database analyze` (e.g., `-- codeql/cpp-queries`). Each pack's `defaultSuiteFile` silently applies strict filters and can produce zero results. Always use an explicit suite reference.

---

## Task System

Create these tasks on workflow start:

```
TaskCreate: "Select database and detect language" (Step 1)
TaskCreate: "Select scan mode, check additional packs" (Step 2) - blockedBy: Step 1
TaskCreate: "Select query packs, model packs, and threat models" (Step 3) - blockedBy: Step 2
TaskCreate: "Execute analysis" (Step 4) - blockedBy: Step 3
TaskCreate: "Process and report results" (Step 5) - blockedBy: Step 4
```

### Gates

| Task | Gate Type | Cannot Proceed Until |
|------|-----------|---------------------|
| Step 2 | **SOFT GATE** | User selects mode; confirms installed/ignored for each missing pack |
| Step 3 | **SOFT GATE** | User approves query packs, model packs, and threat model selection |

**Auto-skip rule:** If the user already specified a choice in the invocation, skip the corresponding `AskUserQuestion` and use the provided value directly.

---

## Steps

### Step 1: Select Database and Detect Language

**Entry:** At least one CodeQL database exists in the working directory
**Exit:** `DB_NAME` and `LANG` variables set; database resolves successfully

```bash
DB_NAME=$(ls -dt codeql_*.db 2>/dev/null | head -1)
[[ -z "$DB_NAME" ]] && echo "ERROR: No CodeQL database found." && exit 1
LANG=$(codeql resolve database --format=json -- "$DB_NAME" | jq -r '.languages[0]')
echo "Using: $DB_NAME (language: $LANG)"
```

If multiple databases exist, use `AskUserQuestion` to let user select. If multi-language database, ask which language to analyze.

---

### Step 2: Select Scan Mode, Check Additional Packs

**Entry:** Step 1 complete (`DB_NAME` and `LANG` set)
**Exit:** Scan mode selected; all available packs (official, ToB, community) checked for installation status; model packs detected

#### 2a: Select Scan Mode

**Skip if user already specified.** Otherwise use `AskUserQuestion`:

```
header: "Scan Mode"
question: "Which scan mode should be used?"
options:
  - label: "Run all (Recommended)"
    description: "Maximum coverage — all queries from all installed packs"
  - label: "Important only"
    description: "Security vulnerabilities only — medium-high precision, security-severity threshold"
```

#### 2b: Query Packs

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

#### 2c: Detect Model Packs

Search three locations for data extension model packs:
1. **In-repo model packs** — `qlpack.yml`/`codeql-pack.yml` with `dataExtensions`
2. **In-repo standalone data extensions** — `.yml` files with `extensions:` key
3. **Installed model packs** — resolved by CodeQL

Record all detected packs for Step 3.

---

### Step 3: Select Query Packs and Model Packs

**Entry:** Step 2 complete (scan mode, pack availability, and model packs all determined)
**Exit:** User confirmed query packs, model packs, and threat model selection; all flags built (`THREAT_MODEL_FLAG`, `MODEL_PACK_FLAGS`, `ADDITIONAL_PACK_FLAGS`)

> **CHECKPOINT** — Present available packs to user for confirmation.
> **Skip if user already specified pack preferences.**

#### 3a: Confirm Query Packs

**Important-only mode:** Inform user all installed packs included with filtering. Proceed to 3b.

**Run-all mode:** Use `AskUserQuestion` to confirm "Use all" or "Select individually".

#### 3b: Select Model Packs (if any detected)

**Skip if no model packs detected in Step 2c.**

Use `AskUserQuestion`: "Use all (Recommended)" / "Select individually" / "Skip".

**Notes:**
- In-repo standalone extensions (`.yml`) are auto-discovered — pass source directory via `--additional-packs`
- In-repo model packs (with `qlpack.yml`) need parent directory via `--additional-packs`
- Installed model packs use `--model-packs`

#### 3c: Select Threat Models

Threat models control which input sources CodeQL treats as tainted. See [threat-models.md](../references/threat-models.md).

Use `AskUserQuestion`:

```
header: "Threat Models"
question: "Which input sources should CodeQL treat as tainted?"
options:
  - label: "Remote only (Recommended)"
    description: "Default — HTTP requests, network input"
  - label: "Remote + Local"
    description: "Add CLI args, local files"
  - label: "All sources"
    description: "Remote, local, environment, database, file"
  - label: "Custom"
    description: "Select specific threat models individually"
```

Build the flag: `THREAT_MODEL_FLAG=""` (remote only needs no flag), `--threat-model local`, etc.

---

### Step 4: Execute Analysis

**Entry:** Step 3 complete (all flags and pack selections finalized)
**Exit:** `$RESULTS_DIR/results.sarif` exists and contains valid SARIF output

#### Generate custom suite

**Important-only mode:** Generate the custom `.qls` suite using the template and script in [important-only-suite.md](../references/important-only-suite.md).

**Run-all mode:** Generate the custom `.qls` suite using the template in [run-all-suite.md](../references/run-all-suite.md).

```bash
RESULTS_DIR="${DB_NAME%.db}-results"
mkdir -p "$RESULTS_DIR"
SUITE_FILE="$RESULTS_DIR/<mode>.qls"

# Verify suite resolves correctly before running
codeql resolve queries "$SUITE_FILE" | wc -l
```

#### Run analysis

```bash
codeql database analyze $DB_NAME \
  --format=sarif-latest \
  --output="$RESULTS_DIR/results.sarif" \
  --threads=0 \
  $THREAT_MODEL_FLAG \
  $MODEL_PACK_FLAGS \
  $ADDITIONAL_PACK_FLAGS \
  -- "$SUITE_FILE"
```

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

**Entry:** Step 4 complete (`results.sarif` exists)
**Exit:** Findings summarized by severity, rule, and location; zero-finding results investigated; final report presented to user

Process the SARIF output using the jq commands in [sarif-processing.md](../references/sarif-processing.md): count findings, summarize by level, summarize by security severity, summarize by rule.

**Important-only mode:** Apply the post-analysis filter from [sarif-processing.md](../references/sarif-processing.md#important-only-post-filter) to remove medium-precision results with `security-severity` < 6.0.

---

## Final Output

Report to user:

```
## CodeQL Analysis Complete

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
- SARIF: $RESULTS_DIR/results.sarif
```
