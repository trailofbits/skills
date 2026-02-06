# Run Analysis Workflow

Execute CodeQL security queries on an existing database with ruleset selection and result formatting.

## Task System

Create these tasks on workflow start:

```
TaskCreate: "Select database and detect language" (Step 1)
TaskCreate: "Check additional query packs and detect model packs" (Step 2) - blockedBy: Step 1
TaskCreate: "Select query packs, model packs, and threat models" (Step 3) - blockedBy: Step 2
TaskCreate: "Execute analysis" (Step 4) - blockedBy: Step 3
TaskCreate: "Process and report results" (Step 5) - blockedBy: Step 4
```

### Mandatory Gates

| Task | Gate Type | Cannot Proceed Until |
|------|-----------|---------------------|
| Step 2 | **SOFT GATE** | User confirms installed/ignored for each missing pack |
| Step 3 | **HARD GATE** | User approves query packs, model packs, and threat model selection |

---

## Steps

### Step 1: Select Database and Detect Language

**Find available databases:**

```bash
# List all CodeQL databases
ls -dt codeql_*.db 2>/dev/null | head -10

# Get the most recent database
get_latest_db() {
  ls -dt codeql_*.db 2>/dev/null | head -1
}

DB_NAME=$(get_latest_db)
if [[ -z "$DB_NAME" ]]; then
  echo "ERROR: No CodeQL database found. Run build-database workflow first."
  exit 1
fi
echo "Using database: $DB_NAME"
```

**If multiple databases exist**, use `AskUserQuestion` to let user select:

```
header: "Database"
question: "Multiple databases found. Which one to analyze?"
options:
  - label: "codeql_3.db (latest)"
    description: "Created: <timestamp>"
  - label: "codeql_2.db"
    description: "Created: <timestamp>"
  - label: "codeql_1.db"
    description: "Created: <timestamp>"
```

**Verify and detect language:**

```bash
# Check database exists and get language(s)
codeql resolve database -- "$DB_NAME"

# Get primary language from database
LANG=$(codeql resolve database --format=json -- "$DB_NAME" \
  | jq -r '.languages[0]')
LANG_COUNT=$(codeql resolve database --format=json -- "$DB_NAME" \
  | jq '.languages | length')
echo "Primary language: $LANG"
if [ "$LANG_COUNT" -gt 1 ]; then
  echo "WARNING: Multi-language database ($LANG_COUNT languages)"
  codeql resolve database --format=json -- "$DB_NAME" \
    | jq -r '.languages[]'
fi
```

**Multi-language databases:** If more than one language is detected, ask the user which language to analyze or run separate analyses for each.

---

### Step 2: Check Additional Query Packs and Detect Model Packs

Check if recommended third-party query packs are installed and detect available model packs. For each missing pack, prompt user to install or ignore.

#### 2a: Query Packs

**Available packs by language** (see [ruleset-catalog.md](../references/ruleset-catalog.md)):

| Language | Trail of Bits | Community Pack |
|----------|---------------|----------------|
| C/C++ | `trailofbits/cpp-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-CPP` |
| Go | `trailofbits/go-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-Go` |
| Java | `trailofbits/java-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-Java` |
| JavaScript | - | `GitHubSecurityLab/CodeQL-Community-Packs-JavaScript` |
| Python | - | `GitHubSecurityLab/CodeQL-Community-Packs-Python` |
| C# | - | `GitHubSecurityLab/CodeQL-Community-Packs-CSharp` |
| Ruby | - | `GitHubSecurityLab/CodeQL-Community-Packs-Ruby` |

**For each pack available for the detected language:**

```bash
# Check if pack is installed
codeql resolve qlpacks | grep -i "<PACK_NAME>"
```

**If NOT installed**, use `AskUserQuestion`:

```
header: "<PACK_TYPE>"
question: "<PACK_NAME> for <LANG> is not installed. Install it?"
options:
  - label: "Install (Recommended)"
    description: "Run: codeql pack download <PACK_NAME>"
  - label: "Ignore"
    description: "Skip this pack for this analysis"
```

**On "Install":**
```bash
codeql pack download <PACK_NAME>
```

**On "Ignore":** Mark pack as skipped, continue to next pack.

#### 2b: Detect Model Packs

Model packs contain data extensions (custom sources, sinks, flow summaries) that improve CodeQL's data flow analysis for project-specific or framework-specific APIs. To create new extensions, run the [create-data-extensions](create-data-extensions.md) workflow first.

**Search three locations:**

**1. In-repo model packs** — `qlpack.yml` or `codeql-pack.yml` with `dataExtensions`:

```bash
# Find CodeQL pack definitions in the codebase
fd '(qlpack|codeql-pack)\.yml$' . --exclude codeql_*.db | while read -r f; do
  if grep -q 'dataExtensions' "$f"; then
    echo "MODEL PACK: $(dirname "$f") - $(grep '^name:' "$f")"
  fi
done
```

**2. In-repo standalone data extensions** — `.yml` files with `extensions:` key (auto-discovered by CodeQL):

```bash
# Find data extension YAML files in the codebase
rg -l '^extensions:' --glob '*.yml' --glob '!codeql_*.db/**' | head -20
```

**3. Installed model packs** — library packs resolved by CodeQL that contain models:

```bash
# List all resolved packs and filter for model/library packs
# Model packs typically have "model" in the name or are library packs
codeql resolve qlpacks 2>/dev/null | grep -iE 'model|extension'
```

**Record all detected model packs for presentation in Step 3.** If no model packs are found, note this and proceed — model packs are optional.

---

### Step 3: CRITICAL GATE - Select Query Packs and Model Packs

> **⛔ MANDATORY CHECKPOINT - DO NOT SKIP**
>
> Present all available packs as checklists. Query packs first, then model packs.

#### 3a: Select Query Packs

Use `AskUserQuestion` tool with `multiSelect: true`:

```
header: "Query Packs"
question: "Select query packs to run:"
multiSelect: false
options:
  - label: "Use all (Recommended)"
    description: "Run all installed query packs for maximum coverage"
  - label: "security-extended"
    description: "codeql/<lang>-queries - Core security queries, low false positives"
  - label: "security-and-quality"
    description: "Includes code quality checks - more findings, more noise"
  - label: "Select individually"
    description: "Choose specific packs from the full list"
```

**If "Use all":** Include all installed query packs: `security-extended` + Trail of Bits + Community Packs (whichever are installed).

**If "Select individually":** Follow up with a `multiSelect: true` question listing all installed packs:

```
header: "Query Packs"
question: "Select query packs to run:"
multiSelect: true
options:
  - label: "security-extended"
    description: "codeql/<lang>-queries - Core security queries, low false positives"
  - label: "security-and-quality"
    description: "Includes code quality checks - more findings, more noise"
  - label: "security-experimental"
    description: "Bleeding-edge queries - may have higher false positives"
  - label: "Trail of Bits"
    description: "trailofbits/<lang>-queries - Memory safety, domain expertise"
  - label: "Community Packs"
    description: "GitHubSecurityLab/CodeQL-Community-Packs-<Lang> - Additional security queries"
```

**Only show built-in and third-party packs that are installed (from Step 2a)**

**⛔ STOP: Await user selection**

#### 3b: Select Model Packs (if any detected)

**Skip this sub-step if no model packs were detected in Step 2b.**

Present detected model packs from Step 2b. Categorize by source:

Use `AskUserQuestion` tool:

```
header: "Model Packs"
question: "Model packs add custom data flow models (sources, sinks, summaries). Select which to include:"
multiSelect: false
options:
  - label: "Use all (Recommended)"
    description: "Include all detected model packs and data extensions"
  - label: "Select individually"
    description: "Choose specific model packs from the list"
  - label: "Skip"
    description: "Run without model packs"
```

**If "Use all":** Include all model packs and data extensions detected in Step 2b.

**If "Select individually":** Follow up with a `multiSelect: true` question:

```
header: "Model Packs"
question: "Select model packs to include:"
multiSelect: true
options:
  # For each in-repo model pack found in 2b:
  - label: "<pack-name>"
    description: "In-repo model pack at <path> - custom data flow models"
  # For each standalone data extension found in 2b:
  - label: "In-repo extensions"
    description: "<N> data extension files found in codebase (auto-discovered)"
  # For each installed model pack found in 2b:
  - label: "<pack-name>"
    description: "Installed model pack - <description if available>"
```

**Notes:**
- In-repo standalone data extensions (`.yml` files with `extensions:` key) are auto-discovered by CodeQL during analysis — selecting them here ensures the source directory is passed via `--additional-packs`
- In-repo model packs (with `qlpack.yml`) need their parent directory passed via `--additional-packs`
- Installed model packs are passed via `--model-packs`

**⛔ STOP: Await user selection**

---

### Step 3c: Select Threat Models

Threat models control which input sources CodeQL treats as tainted. The default (`remote`) covers HTTP/network input only. Expanding the threat model finds more vulnerabilities but may increase false positives. See [threat-models.md](../references/threat-models.md) for details on each model.

Use `AskUserQuestion`:

```
header: "Threat Models"
question: "Which input sources should CodeQL treat as tainted?"
multiSelect: false
options:
  - label: "Remote only (Recommended)"
    description: "Default — HTTP requests, network input. Best for web services and APIs."
  - label: "Remote + Local"
    description: "Add CLI args, local files. Use for CLI tools or desktop apps."
  - label: "All sources"
    description: "Remote, local, environment, database, file. Maximum coverage, more noise."
  - label: "Custom"
    description: "Select specific threat models individually"
```

**If "Custom":** Follow up with `multiSelect: true`:

```
header: "Threat Models"
question: "Select threat models to enable:"
multiSelect: true
options:
  - label: "remote"
    description: "HTTP requests, network input (always included)"
  - label: "local"
    description: "CLI args, local files — for CLI tools, batch processors"
  - label: "environment"
    description: "Environment variables — for 12-factor/container apps"
  - label: "database"
    description: "Database results — for second-order injection audits"
```

**Build the threat model flag:**

```bash
# Only add --threat-models when non-default models are selected
# Default (remote only) needs no flag
THREAT_MODEL_FLAG=""  # or "--threat-models=remote,local" etc.
```

---

### Step 4: Execute Analysis

Run analysis with **only** the packs selected by user in Step 3.

```bash
# Results directory matches database name
RESULTS_DIR="${DB_NAME%.db}-results"
mkdir -p "$RESULTS_DIR"

# Build pack list from user selections in Step 3a
PACKS="<USER_SELECTED_QUERY_PACKS>"

# Build model pack flags from user selections in Step 3b
# --model-packs for installed model packs
# --additional-packs for in-repo model packs and data extensions
MODEL_PACK_FLAGS=""
ADDITIONAL_PACK_FLAGS=""

# Threat model flag from Step 3c (empty string if default/remote-only)
# THREAT_MODEL_FLAG=""

codeql database analyze $DB_NAME \
  --format=sarif-latest \
  --output="$RESULTS_DIR/results.sarif" \
  --threads=0 \
  $THREAT_MODEL_FLAG \
  $MODEL_PACK_FLAGS \
  $ADDITIONAL_PACK_FLAGS \
  -- $PACKS
```

**Flag reference for model packs:**

| Source | Flag | Example |
|--------|------|---------|
| Installed model packs | `--model-packs` | `--model-packs=myorg/java-models` |
| In-repo model packs (with `qlpack.yml`) | `--additional-packs` | `--additional-packs=./lib/codeql-models` |
| In-repo standalone extensions (`.yml`) | `--additional-packs` | `--additional-packs=.` |

**Example (C++ with query packs and model packs):**

```bash
codeql database analyze codeql_1.db \
  --format=sarif-latest \
  --output=codeql_1-results/results.sarif \
  --threads=0 \
  --additional-packs=./codeql-models \
  -- codeql/cpp-queries:codeql-suites/cpp-security-extended.qls \
     trailofbits/cpp-queries \
     GitHubSecurityLab/CodeQL-Community-Packs-CPP
```

**Example (Python with installed model pack):**

```bash
codeql database analyze codeql_1.db \
  --format=sarif-latest \
  --output=codeql_1-results/results.sarif \
  --threads=0 \
  --model-packs=myorg/python-models \
  -- codeql/python-queries:codeql-suites/python-security-extended.qls
```

### Performance Flags

If codebase is large then read [../references/performance-tuning.md](../references/performance-tuning.md) and apply relevant optimizations.

### Step 5: Process and Report Results

**Count findings:**

```bash
jq '.runs[].results | length' "$RESULTS_DIR/results.sarif"
```

**Summary by SARIF level:**

```bash
jq -r '.runs[].results[] | .level' "$RESULTS_DIR/results.sarif" \
  | sort | uniq -c | sort -rn
```

**Summary by security severity** (more useful for triage):

```bash
jq -r '
  .runs[].results[] |
  (.properties["security-severity"] // "none") + " " +
  (.message.text // "no message" | .[0:80])
' "$RESULTS_DIR/results.sarif" | sort -rn | head -20
```

**Summary by rule:**

```bash
jq -r '.runs[].results[] | .ruleId' "$RESULTS_DIR/results.sarif" \
  | sort | uniq -c | sort -rn
```

---

## Final Output

Report to user:

```
## CodeQL Analysis Complete

**Database:** $DB_NAME
**Language:** <LANG>
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
