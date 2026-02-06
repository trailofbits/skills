# Create Data Extensions Workflow

Generate data extension YAML files to improve CodeQL's data flow coverage for project-specific APIs. Runs after database build and before analysis.

## Task System

Create these tasks on workflow start:

```
TaskCreate: "Check for existing data extensions" (Step 1)
TaskCreate: "Query known sources and sinks" (Step 2) - blockedBy: Step 1
TaskCreate: "Identify missing sources and sinks" (Step 3) - blockedBy: Step 2
TaskCreate: "Create data extension files" (Step 4) - blockedBy: Step 3
TaskCreate: "Validate with re-analysis" (Step 5) - blockedBy: Step 4
```

### Early Exit Points

| After Step | Condition | Action |
|------------|-----------|--------|
| Step 1 | Extensions already exist | Return found packs/files to run-analysis workflow, finish |
| Step 3 | No missing models identified | Report coverage is adequate, finish |

---

## Steps

### Step 1: Check for Existing Data Extensions

Search the project for existing data extensions and model packs.

**1. In-repo model packs** — `qlpack.yml` or `codeql-pack.yml` with `dataExtensions`:

```bash
fd '(qlpack|codeql-pack)\.yml$' . --exclude codeql_*.db | while read -r f; do
  if grep -q 'dataExtensions' "$f"; then
    echo "MODEL PACK: $(dirname "$f") - $(grep '^name:' "$f")"
  fi
done
```

**2. Standalone data extension files** — `.yml` files with `extensions:` key:

```bash
rg -l '^extensions:' --glob '*.yml' --glob '!codeql_*.db/**' | head -20
```

**3. Installed model packs:**

```bash
codeql resolve qlpacks 2>/dev/null | grep -iE 'model|extension'
```

**If any found:** Report to user what was found and finish. These will be picked up by the run-analysis workflow's model pack detection (Step 2b).

**If none found:** Proceed to Step 2.

---

### Step 2: Query Known Sources and Sinks

Run custom QL queries against the database to enumerate all sources and sinks CodeQL currently recognizes. This gives a direct inventory of what is modeled vs. what is not.

#### 2a: Select Database and Language

```bash
DB_NAME=$(ls -dt codeql_*.db 2>/dev/null | head -1)
LANG=$(codeql resolve database --format=json -- "$DB_NAME" | jq -r '.languages[0]')
echo "Database: $DB_NAME, Language: $LANG"

DIAG_DIR="${DB_NAME%.db}-diagnostics"
mkdir -p "$DIAG_DIR"
```

#### 2b: Write Source Enumeration Query

Use the `Write` tool to create `$DIAG_DIR/list-sources.ql` using the source template from [diagnostic-query-templates.md](../references/diagnostic-query-templates.md#source-enumeration-query). Pick the correct import block for `$LANG`.

#### 2c: Write Sink Enumeration Query

Use the `Write` tool to create `$DIAG_DIR/list-sinks.ql` using the language-specific sink template from [diagnostic-query-templates.md](../references/diagnostic-query-templates.md#sink-enumeration-queries). The Concepts API differs significantly across languages — use the exact template for the detected language.

**For Java:** Also create `$DIAG_DIR/qlpack.yml` with a `codeql/java-all` dependency and run `codeql pack install` before executing queries. See the Java section in the templates reference.

#### 2d: Run Queries

```bash
# Run sources query
codeql query run \
  --database="$DB_NAME" \
  --output="$DIAG_DIR/sources.bqrs" \
  -- "$DIAG_DIR/list-sources.ql"

codeql bqrs decode \
  --format=csv \
  --output="$DIAG_DIR/sources.csv" \
  -- "$DIAG_DIR/sources.bqrs"

# Run sinks query
codeql query run \
  --database="$DB_NAME" \
  --output="$DIAG_DIR/sinks.bqrs" \
  -- "$DIAG_DIR/list-sinks.ql"

codeql bqrs decode \
  --format=csv \
  --output="$DIAG_DIR/sinks.csv" \
  -- "$DIAG_DIR/sinks.bqrs"
```

#### 2e: Summarize Results

```bash
echo "=== Known Sources ==="
wc -l < "$DIAG_DIR/sources.csv"
# Show unique source types
cut -d',' -f2 "$DIAG_DIR/sources.csv" | sort -u

echo "=== Known Sinks ==="
wc -l < "$DIAG_DIR/sinks.csv"
# Show unique sink kinds
cut -d',' -f2 "$DIAG_DIR/sinks.csv" | sort -u
```

Read both CSV files and present a summary to the user:

```
## CodeQL Known Models

### Sources (<N> total):
- remote: <count> (HTTP handlers, request parsing)
- local: <count> (CLI args, file reads)
- ...

### Sinks (<N> total):
- sql-execution: <count>
- command-execution: <count>
- file-access: <count>
- ...
```

---

### Step 3: Identify Missing Sources and Sinks

This is the core analysis step. Cross-reference the project's API surface against CodeQL's known models.

#### 3a: Map the Project's API Surface

Read source code to identify security-relevant patterns. Look for:

| Pattern | What To Find | Likely Model Type |
|---------|-------------|-------------------|
| HTTP/request handlers | Custom request parsing, parameter access | `sourceModel` (kind: `remote`) |
| Database layers | Custom ORM methods, raw query wrappers | `sinkModel` (kind: `sql-injection`) |
| Command execution | Shell wrappers, process spawners | `sinkModel` (kind: `command-injection`) |
| File operations | Custom file read/write, path construction | `sinkModel` (kind: `path-injection`) |
| Template rendering | HTML output, response builders | `sinkModel` (kind: `xss`) |
| Deserialization | Custom deserializers, data loaders | `sinkModel` (kind: `unsafe-deserialization`) |
| HTTP clients | URL construction, request builders | `sinkModel` (kind: `ssrf`) |
| Sanitizers | Input validation, escaping functions | `neutralModel` |
| Pass-through wrappers | Logging, caching, encoding | `summaryModel` (kind: `taint`) |

Use `Grep` to search for these patterns in source code:

```bash
# Examples for Python - adapt patterns per language
rg -n 'def (get_param|get_header|get_body|parse_request)' --type py
rg -n '(execute|query|raw_sql|cursor\.)' --type py
rg -n '(subprocess|os\.system|popen|exec)' --type py
rg -n '(open|read_file|write_file|path\.join)' --type py
rg -n '(render|template|html)' --type py
rg -n '(requests\.|urlopen|fetch|http_client)' --type py
```

#### 3b: Cross-Reference Against Known Sources and Sinks

For each API pattern found in 3a, check if it appears in the source/sink CSVs from Step 2:

```bash
# Check if a specific file/function appears in known sources
grep -i "<function_or_file>" "$DIAG_DIR/sources.csv"

# Check if a specific file/function appears in known sinks
grep -i "<function_or_file>" "$DIAG_DIR/sinks.csv"
```

**An API is "missing" if:**
- It handles user input but does not appear in `sources.csv`
- It performs a dangerous operation but does not appear in `sinks.csv`
- It wraps/transforms tainted data but CodeQL has no summary model for it (these won't appear in either CSV — identify by reading the code for wrapper patterns around known sources/sinks)

#### 3c: Report Gaps

Present findings to user:

```
## Data Flow Coverage Gaps

### Missing Sources (user input not tracked):
- `myapp.http.Request.get_param()` — custom parameter access
- `myapp.auth.Token.decode()` — untrusted token data

### Missing Sinks (dangerous operations not checked):
- `myapp.db.Connection.raw_query()` — SQL execution wrapper
- `myapp.shell.Runner.execute()` — command execution

### Missing Summaries (taint lost through wrappers):
- `myapp.cache.Cache.get()` — taint not propagated through cache
- `myapp.utils.encode_json()` — taint lost in serialization

Proceed to create data extension files?
```

Use `AskUserQuestion`:

```
header: "Extensions"
question: "Create data extension files for the identified gaps?"
options:
  - label: "Create all (Recommended)"
    description: "Generate extensions for all identified gaps"
  - label: "Select individually"
    description: "Choose which gaps to model"
  - label: "Skip"
    description: "No extensions needed, proceed to analysis"
```

**If "Skip":** Finish workflow.

**If "Select individually":** Use `AskUserQuestion` with `multiSelect: true` listing each gap.

---

### Step 4: Create Data Extension Files

Generate YAML data extension files for the gaps confirmed by the user.

#### File Structure

Create files in a `codeql-extensions/` directory at project root:

```
codeql-extensions/
  sources.yml       # sourceModel entries
  sinks.yml         # sinkModel entries
  summaries.yml     # summaryModel and neutralModel entries
```

#### YAML Format

All extension files follow this structure:

```yaml
extensions:
  - addsTo:
      pack: codeql/<language>-all  # Target library pack
      extensible: <model-type>      # sourceModel, sinkModel, summaryModel, neutralModel
    data:
      - [<columns>]
```

#### Source Models

Columns: `[package, type, subtypes, name, signature, ext, output, kind, provenance]`

| Column | Description | Example |
|--------|-------------|---------|
| package | Module/package path | `myapp.auth` |
| type | Class or module name | `AuthManager` |
| subtypes | Include subclasses | `True` (Java: capitalized) / `true` (Python/JS/Go) |
| name | Method name | `get_token` |
| signature | Method signature (optional) | `""` (Python/JS), `"(String,int)"` (Java) |
| ext | Extension (optional) | `""` |
| output | What is tainted | `ReturnValue`, `Parameter[0]` (Java) / `Argument[0]` (Python/JS/Go) |
| kind | Source category | `remote`, `local`, `file`, `environment`, `database` |
| provenance | How model was created | `manual` |

**Java-specific format differences:**
- **subtypes**: Use `True` / `False` (capitalized, Python-style), not `true` / `false`
- **output for parameters**: Use `Parameter[N]` (not `Argument[N]`) to mark method parameters as sources
- **signature**: Required for disambiguation — use Java type syntax: `"(String)"`, `"(String,int)"`
- **Parameter ranges**: Use `Parameter[0..2]` to mark multiple consecutive parameters

Example (Python):

```yaml
# codeql-extensions/sources.yml
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sourceModel
    data:
      - ["myapp.http", "Request", true, "get_param", "", "", "ReturnValue", "remote", "manual"]
      - ["myapp.http", "Request", true, "get_header", "", "", "ReturnValue", "remote", "manual"]
```

Example (Java — note `True`, `Parameter[N]`, and signature):

```yaml
# codeql-extensions/sources.yml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      - ["com.myapp.controller", "ApiController", True, "search", "(String)", "", "Parameter[0]", "remote", "manual"]
      - ["com.myapp.service", "FileService", True, "upload", "(String,String)", "", "Parameter[0..1]", "remote", "manual"]
```

#### Sink Models

Columns: `[package, type, subtypes, name, signature, ext, input, kind, provenance]`

Note: column 7 is `input` (which argument receives tainted data), not `output`.

| Kind | Vulnerability |
|------|---------------|
| `sql-injection` | SQL injection |
| `command-injection` | Command injection |
| `path-injection` | Path traversal |
| `xss` | Cross-site scripting |
| `code-injection` | Code injection |
| `ssrf` | Server-side request forgery |
| `unsafe-deserialization` | Insecure deserialization |

Example (Python):

```yaml
# codeql-extensions/sinks.yml
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sinkModel
    data:
      - ["myapp.db", "Connection", true, "raw_query", "", "", "Argument[0]", "sql-injection", "manual"]
      - ["myapp.shell", "Runner", false, "execute", "", "", "Argument[0]", "command-injection", "manual"]
```

Example (Java — note `True` and `Argument[N]` for sink input):

```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      - ["com.myapp.db", "QueryRunner", True, "execute", "(String)", "", "Argument[0]", "sql-injection", "manual"]
```

#### Summary Models

Columns: `[package, type, subtypes, name, signature, ext, input, output, kind, provenance]`

| Kind | Description |
|------|-------------|
| `taint` | Data flows through, still tainted |
| `value` | Data flows through, exact value preserved |

Example:

```yaml
# codeql-extensions/summaries.yml
extensions:
  # Pass-through: taint propagates
  - addsTo:
      pack: codeql/python-all
      extensible: summaryModel
    data:
      - ["myapp.cache", "Cache", true, "get", "", "", "Argument[0]", "ReturnValue", "taint", "manual"]
      - ["myapp.utils", "JSON", false, "parse", "", "", "Argument[0]", "ReturnValue", "taint", "manual"]

  # Sanitizer: taint blocked
  - addsTo:
      pack: codeql/python-all
      extensible: neutralModel
    data:
      - ["myapp.security", "Sanitizer", "escape_html", "", "summary", "manual"]
```

**`neutralModel` vs no model:** If a function has no model at all, CodeQL may still infer flow through it. Use `neutralModel` to explicitly block taint propagation through known-safe functions.

#### Language-Specific Notes

**Python:** Use dotted module paths for `package` (e.g., `myapp.db`).

**JavaScript:** `package` is often `""` for project-local code. Use the import path for npm packages.

**Go:** Use full import paths (e.g., `myapp/internal/db`). `type` is often `""` for package-level functions.

**Java:** Use fully qualified package names (e.g., `com.myapp.db`).

**C/C++:** Use `""` for package, put the namespace in `type`.

#### Write the Files

Use the `Write` tool to create each file. Only create files that have entries — skip empty categories.

#### Deploy the Extensions

**Known limitation:** `--additional-packs` and `--model-packs` flags do not work with pre-compiled query packs (bundled CodeQL distributions that cache `java-all` inside `.codeql/libraries/`). Extensions placed in a standalone model pack directory will be resolved by `codeql resolve qlpacks` but silently ignored during `codeql database analyze`.

**Workaround — copy extensions into the library pack's `ext/` directory:**

> **Warning:** Files copied into the `ext/` directory live inside CodeQL's managed pack cache. They will be **lost** when packs are updated via `codeql pack download` or version upgrades. After any pack update, re-run this deployment step to restore the extensions.

```bash
# Find the java-all ext directory used by the query pack
JAVA_ALL_EXT=$(find "$(codeql resolve qlpacks 2>/dev/null | grep 'java-queries' | awk '{print $NF}' | tr -d '()')" \
  -path '*/.codeql/libraries/codeql/java-all/*/ext' -type d 2>/dev/null | head -1)

if [ -n "$JAVA_ALL_EXT" ]; then
  PROJECT_NAME=$(basename "$(pwd)")
  cp codeql-extensions/sources.yml "$JAVA_ALL_EXT/${PROJECT_NAME}.sources.model.yml"
  [ -f codeql-extensions/sinks.yml ] && cp codeql-extensions/sinks.yml "$JAVA_ALL_EXT/${PROJECT_NAME}.sinks.model.yml"
  [ -f codeql-extensions/summaries.yml ] && cp codeql-extensions/summaries.yml "$JAVA_ALL_EXT/${PROJECT_NAME}.summaries.model.yml"

  # Verify deployment — confirm files landed correctly
  DEPLOYED=$(ls "$JAVA_ALL_EXT/${PROJECT_NAME}".*.model.yml 2>/dev/null | wc -l)
  if [ "$DEPLOYED" -gt 0 ]; then
    echo "Extensions deployed to $JAVA_ALL_EXT ($DEPLOYED files):"
    ls -la "$JAVA_ALL_EXT/${PROJECT_NAME}".*.model.yml
  else
    echo "ERROR: Files were copied but verification failed. Check path: $JAVA_ALL_EXT"
  fi
else
  echo "WARNING: Could not find java-all ext directory. Extensions may not load."
  echo "Attempted path lookup from: codeql resolve qlpacks | grep java-queries"
  echo "Run 'codeql resolve qlpacks' manually to debug."
fi
```

**For Python/JS/Go:** The same limitation may apply. Locate the `<lang>-all` pack's `ext/` directory and copy extensions there.

**Alternative (if query packs are NOT pre-compiled):** Use `--additional-packs=./codeql-extensions` with a proper model pack `qlpack.yml`:

```yaml
# codeql-extensions/qlpack.yml
name: custom/<project>-extensions
version: 0.0.1
library: true
extensionTargets:
  codeql/<lang>-all: "*"
dataExtensions:
  - sources.yml
  - sinks.yml
  - summaries.yml
```

---

### Step 5: Validate with Re-Analysis

Run a full security analysis with and without extensions to measure the finding delta. This is more reliable than re-running source/sink enumeration queries, which may not reflect the `sourceModel` extensible being used by taint-tracking queries.

#### 5a: Run Baseline Analysis (without extensions)

```bash
RESULTS_DIR="${DB_NAME%.db}-results"
mkdir -p "$RESULTS_DIR"

# Baseline run (or skip if already run in a previous step)
codeql database analyze "$DB_NAME" \
  --format=sarif-latest \
  --output="$RESULTS_DIR/baseline.sarif" \
  --threads=0 \
  -- codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls
```

#### 5b: Run Analysis with Extensions

```bash
# Clean cache to force re-evaluation
codeql database cleanup "$DB_NAME"

codeql database analyze "$DB_NAME" \
  --format=sarif-latest \
  --output="$RESULTS_DIR/with-extensions.sarif" \
  --threads=0 \
  --rerun \
  -- codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls
```

Use `-vvv` flag to verify extensions are being loaded — look for `Loading data extensions in ... <your-extension-file>.yml` in stderr.

#### 5c: Compare Findings

```bash
BASELINE=$(python3 -c "import json; print(sum(len(r.get('results',[])) for r in json.load(open('$RESULTS_DIR/baseline.sarif')).get('runs',[])))")
WITH_EXT=$(python3 -c "import json; print(sum(len(r.get('results',[])) for r in json.load(open('$RESULTS_DIR/with-extensions.sarif')).get('runs',[])))")
echo "Findings: $BASELINE → $WITH_EXT (+$((WITH_EXT - BASELINE)))"
```

**If counts did not increase:** The extension YAML may have syntax errors or column values that don't match the code. Check:

| Issue | Solution |
|-------|----------|
| Extension not loaded | Run with `-vvv` and grep for your extension filename in output |
| Pre-compiled pack ignores extensions | Use the `ext/` directory workaround above |
| Java: No new findings | Verify `True`/`False` (capitalized) for subtypes, `Parameter[N]` for sources |
| No new sources/sinks | Verify column values match actual code signatures exactly |
| Type not found | Use exact type name as it appears in CodeQL database |
| Wrong argument index | Arguments are 0-indexed; `self` is `Argument[self]` (Python), `Parameter[0]` (Java) |

Fix the extension files, re-deploy to `ext/`, and re-run 5b until counts increase.

---

## Final Output

```
## Data Extensions Created

**Database:** $DB_NAME
**Language:** <LANG>

### Files Created:
- codeql-extensions/sources.yml — <N> source models
- codeql-extensions/sinks.yml — <N> sink models
- codeql-extensions/summaries.yml — <N> summary/neutral models

### Model Coverage:
- Sources: <BEFORE> → <AFTER> (+<DELTA>)
- Sinks: <BEFORE> → <AFTER> (+<DELTA>)

### Usage:
Extensions deployed to `<lang>-all` ext/ directory (auto-loaded).
Source files in `codeql-extensions/` for version control.
Run the run-analysis workflow to use them.
```

## References

- [Threat models reference](../references/threat-models.md) — control which source categories are active during analysis
- [CodeQL data extensions](https://codeql.github.com/docs/codeql-cli/using-custom-queries-with-the-codeql-cli/#using-extension-packs)
- [Customizing library models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-python/)
