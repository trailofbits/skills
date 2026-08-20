---
name: sarif-parsing
description: >-
  Parses and processes SARIF files from static analysis tools like CodeQL, Semgrep, or other
  scanners. Triggers on "parse sarif", "read scan results", "aggregate findings", "deduplicate
  alerts", or "process sarif output". Handles filtering, deduplication, format conversion, and
  CI/CD integration of SARIF data. Does NOT run scans — use the Semgrep or CodeQL skills for that.
allowed-tools: Bash Read Glob Grep
---

# SARIF Parsing Best Practices

You are a SARIF parsing expert. Your role is to help users effectively read, analyze, and process SARIF files from static analysis tools.

## When to Use

Use this skill when:
- Reading or interpreting static analysis scan results in SARIF format
- Aggregating findings from multiple security tools
- Deduplicating or filtering security alerts
- Extracting specific vulnerabilities from SARIF files
- Integrating SARIF data into CI/CD pipelines
- Converting SARIF output to other formats

## When NOT to Use

Do NOT use this skill for:
- Running static analysis scans (use CodeQL or Semgrep skills instead)
- Writing CodeQL or Semgrep rules (use their respective skills)
- Analyzing source code directly (SARIF is for processing existing scan results)
- Triaging findings without SARIF input (use variant-analysis or audit skills)

## SARIF Structure Overview

SARIF 2.1.0 is the current OASIS standard. Every SARIF file has this hierarchical structure:

```
sarifLog
├── version: "2.1.0"
├── $schema: (optional, enables IDE validation)
└── runs[] (array of analysis runs)
    ├── tool
    │   ├── driver
    │   │   ├── name (required)
    │   │   ├── version
    │   │   └── rules[] (rule definitions)
    │   └── extensions[] (plugins)
    ├── results[] (findings)
    │   ├── ruleId
    │   ├── ruleIndex (index into tool.driver.rules[])
    │   ├── level (OPTIONAL, inherited from the rule when absent)
    │   ├── message.text
    │   ├── locations[]
    │   │   └── physicalLocation
    │   │       ├── artifactLocation.uri
    │   │       └── region (startLine, startColumn, etc.)
    │   ├── fingerprints{}
    │   └── partialFingerprints{}
    └── artifacts[] (scanned files metadata)
```

### Severity Is Not Always on the Result

`result.level` is optional. CodeQL omits it on every result and records severity on the
rule as `defaultConfiguration.level`, which the result inherits. Read `result.level`
directly and a CodeQL run scores as clean however many errors it found, which is how a
severity gate ends up exiting 0 on a failing repo.

Resolve severity in this order (SARIF 2.1.0 section 3.27.10):

1. `kind` other than `"fail"` (a pass/notApplicable record), so `"none"`
2. `result.level`, when present
3. the matched rule's `defaultConfiguration.level`, joining `ruleIndex` into
   `runs[].tool.driver.rules[]`, or matching `ruleId` against `rules[].id` when the tool
   omits `ruleIndex`
4. `"warning"`, the SARIF default

Every severity query in this skill starts from that resolution. In jq it is the
`LEVEL_FN` definition in [{baseDir}/resources/jq-queries.md]({baseDir}/resources/jq-queries.md);
in Python it is `resolve_level(result, run)` in
[{baseDir}/resources/sarif_helpers.py]({baseDir}/resources/sarif_helpers.py).

### Why Fingerprinting Matters

Without stable fingerprints, you can't track findings across runs:

- **Baseline comparison**: "Is this a new finding or did we see it before?"
- **Regression detection**: "Did this PR introduce new vulnerabilities?"
- **Suppression**: "Ignore this known false positive in future runs"

Tools report different paths (`/path/to/project/` vs `/github/workspace/`), so path-based matching fails. Fingerprints hash the *content* (code snippet, rule ID, relative location) to create stable identifiers regardless of environment.

## Tool Selection Guide

| Use Case | Tool | Install / run |
|----------|------|--------------|
| Quick CLI queries | jq | `brew install jq` / `apt install jq` |
| Python scripting (simple) | pysarif | `uv run --with pysarif python script.py` |
| Python scripting (advanced) | sarif-tools | `uv run --with sarif-tools python script.py` |
| .NET applications | SARIF SDK | NuGet package |
| JavaScript/Node.js | sarif-js | npm package |
| Go applications | garif | `go get github.com/chavacava/garif` |
| Validation | SARIF Validator | sarifweb.azurewebsites.net |

## Strategy 1: Quick Analysis with jq

For rapid exploration and one-off queries:

```bash
# Pretty print the file
jq '.' results.sarif

# Count total findings
jq '[.runs[].results[]] | length' results.sarif

# List all rule IDs triggered
jq '[.runs[].results[].ruleId] | unique' results.sarif

# Severity resolution, needed by every query below that filters on level.
# See resources/jq-queries.md for the annotated version.
LEVEL_FN='
  def rule($run):
    . as $r
    | ($run.tool.driver.rules // []) as $rules
    | (if ($r.ruleIndex | type) == "number" and $r.ruleIndex >= 0
       then $rules[$r.ruleIndex] else null end)
      // first($rules[] | select(.id == $r.ruleId))
      // null;
  def level($run):
    . as $r
    | if ($r.kind // "fail") != "fail" then "none"
      else ($r.level // rule($run).defaultConfiguration.level // "warning") end;
'

# Extract errors only
jq "$LEVEL_FN"'.runs[] as $run | $run.results[] | select(level($run) == "error")' results.sarif

# Get findings with file locations
jq '.runs[].results[] | {
  rule: .ruleId,
  message: .message.text,
  file: .locations[0].physicalLocation.artifactLocation.uri,
  line: .locations[0].physicalLocation.region.startLine
}' results.sarif

# Filter by severity and get count per rule
jq "$LEVEL_FN"'[.runs[] as $run | $run.results[] | select(level($run) == "error")] | group_by(.ruleId) | map({rule: .[0].ruleId, count: length})' results.sarif

# Extract findings for a specific file
jq --arg file "src/auth.py" '.runs[].results[] | select(.locations[].physicalLocation.artifactLocation.uri | contains($file))' results.sarif
```

## Strategy 2: Python with pysarif

For programmatic access with full object model:

```python
from pysarif import load_from_file, save_to_file

# Load SARIF file
sarif = load_from_file("results.sarif")

# Iterate through runs and results
for run in sarif.runs:
    tool_name = run.tool.driver.name
    print(f"Tool: {tool_name}")

    for result in run.results:
        # pysarif fills a missing result.level with "warning", so .level here is NOT the
        # rule-inherited severity: a CodeQL error (no level on the result, severity on the
        # rule) reads as "warning". Gate severity with Strategy 1's level() or with
        # resolve_level() in resources/sarif_helpers.py, which resolve it from the rule.
        print(f"  {result.rule_id}: {result.message.text}")

        if result.locations:
            loc = result.locations[0].physical_location
            if loc and loc.artifact_location:
                print(f"    File: {loc.artifact_location.uri}")
                if loc.region:
                    print(f"    Line: {loc.region.start_line}")

# Save modified SARIF
save_to_file(sarif, "modified.sarif")
```

## Strategy 3: Python with sarif-tools

For aggregation, reporting, and CI/CD integration:

```python
from sarif import loader

# Load single file
sarif_data = loader.load_sarif_file("results.sarif")

# Or load multiple files
sarif_set = loader.load_sarif_files(["tool1.sarif", "tool2.sarif"])

# Get summary report
report = sarif_data.get_report()

# Get histogram by severity
errors = report.get_issue_type_histogram_for_severity("error")
warnings = report.get_issue_type_histogram_for_severity("warning")

# Filter by severity. sarif-tools hands back raw result dicts, and a result's level may
# live on its rule, so resolve it against the run instead of reading r["level"].
from sarif_helpers import extract_findings, filter_by_level, load_sarif

high_severity = filter_by_level(extract_findings(load_sarif("results.sarif")), "error")
```

**sarif-tools CLI commands:**

```bash
# Summary of findings
sarif summary results.sarif

# List all results with details
sarif ls results.sarif

# Get results by severity
sarif ls --level error results.sarif

# Diff two SARIF files (find new/fixed issues)
sarif diff baseline.sarif current.sarif

# Convert to other formats
sarif csv results.sarif > results.csv
sarif html results.sarif > report.html
```

## Strategy 4: Aggregating Multiple SARIF Files

When combining results from multiple tools:

```python
import json

from sarif_helpers import deduplicate, extract_findings

def aggregate_sarif_files(sarif_paths: list[str]) -> dict:
    """Combine multiple SARIF files into one."""
    aggregated = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": []
    }

    for path in sarif_paths:
        with open(path) as f:
            sarif = json.load(f)
            aggregated["runs"].extend(sarif.get("runs", []))

    return aggregated

unique = deduplicate(extract_findings(aggregate_sarif_files(["tool1.sarif", "tool2.sarif"])))
```

`deduplicate()` prefers whatever `fingerprints` or `partialFingerprints` the tool supplied
and falls back to hashing rule ID, the whole normalized path, line, and message. Keep the
directory in that key: the same rule at the same line in `auth/login.py` and
`admin/login.py` is two findings, and a basename-only key throws one of them away.

## Strategy 5: Extracting Actionable Data

`resources/sarif_helpers.py` covers this with the standard library alone.
`extract_findings()` returns `Finding` objects whose severity is already resolved, and
`filter_by_level()`, `sort_by_severity()`, `deduplicate()` and `diff_findings()` consume
those:

```python
from sarif_helpers import extract_findings, filter_by_level, load_sarif, sort_by_severity

findings = sort_by_severity(extract_findings(load_sarif("results.sarif")))
for f in filter_by_level(findings, "error"):
    print(f"{f.file_path}:{f.start_line} [{f.level}] {f.rule_id}: {f.message}")
```

Writing your own extractor, severity is the part that goes wrong silently:

```python
def resolve_level(result: dict, run: dict) -> str:
    """Severity of a result: its own level, else its rule's default, else "warning"."""
    if result.get("kind", "fail") != "fail":
        return "none"
    if result.get("level"):
        return result["level"]

    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    index = result.get("ruleIndex")
    rule = rules[index] if isinstance(index, int) and 0 <= index < len(rules) else next(
        (r for r in rules if r.get("id") == result.get("ruleId")), {}
    )
    return rule.get("defaultConfiguration", {}).get("level") or "warning"
```

Results carry `ruleIndex` on some tools and only `ruleId` on others, so a resolver that
joins one way alone silently returns the default for every result the other kind of tool
produces.

## Common Pitfalls and Solutions

### 1. Path Normalization Issues

Different tools report paths differently (absolute, relative, URI-encoded), so
`file:///src/a%20b.py` and `src/a b.py` can be the same file. Strip the `file://` scheme,
percent-decode, resolve against a base path, and normalize separators before comparing or
hashing anything: `normalize_path()` in `resources/sarif_helpers.py` does all four.

### 2. Fingerprint Mismatch Across Runs

Fingerprints may not match if:
- File paths differ between environments
- Tool versions changed fingerprinting algorithm
- Code was reformatted (changing line numbers)

**Solution:** Use multiple fingerprint strategies:

```python
def compute_stable_fingerprint(result: dict, file_content: str = None) -> str:
    """Compute environment-independent fingerprint."""
    import hashlib

    components = [
        result.get("ruleId", ""),
        result.get("message", {}).get("text", "")[:100],  # First 100 chars
    ]

    # Add code snippet if available
    if file_content and result.get("locations"):
        region = result["locations"][0].get("physicalLocation", {}).get("region", {})
        if region.get("startLine"):
            lines = file_content.split("\n")
            line_idx = region["startLine"] - 1
            if 0 <= line_idx < len(lines):
                # Normalize whitespace
                components.append(lines[line_idx].strip())

    return hashlib.sha256("".join(components).encode()).hexdigest()[:16]
```

### 3. Missing or Incomplete Data

SARIF allows many optional fields. Always use defensive access:

```python
def safe_get_location(result: dict) -> tuple[str, int]:
    """Safely extract file and line from result."""
    try:
        loc = result.get("locations", [{}])[0]
        phys = loc.get("physicalLocation", {})
        file_path = phys.get("artifactLocation", {}).get("uri", "unknown")
        line = phys.get("region", {}).get("startLine", 0)
        return file_path, line
    except (IndexError, KeyError, TypeError):
        return "unknown", 0
```

### 4. Large File Performance

For very large SARIF files (100MB+):

```python
import ijson  # run via: uv run --with ijson

def stream_results(sarif_path: str):
    """Stream results without loading entire file."""
    with open(sarif_path, "rb") as f:
        # Stream through results arrays
        for result in ijson.items(f, "runs.item.results.item"):
            yield result
```

### 5. Schema Validation

Validate before processing to catch malformed files:

```bash
# Using ajv-cli
npm install -g ajv-cli
ajv validate -s sarif-schema-2.1.0.json -d results.sarif

# Using Python jsonschema
uv run --with jsonschema python your_script.py   # e.g. the function below
```

```python
from jsonschema import validate, ValidationError
import json

def validate_sarif(sarif_path: str, schema_path: str) -> bool:
    """Validate SARIF file against schema."""
    with open(sarif_path) as f:
        sarif = json.load(f)
    with open(schema_path) as f:
        schema = json.load(f)

    try:
        validate(sarif, schema)
        return True
    except ValidationError as e:
        print(f"Validation error: {e.message}")
        return False
```

## CI/CD Integration Patterns

### GitHub Actions

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Check for high severity
  run: |
    # select(.level == "error") counts zero on CodeQL output, which records severity on
    # the rule instead. Resolve the level or the gate passes on a repo full of errors.
    HIGH_COUNT=$(jq '
      def rule($run):
        . as $r
        | ($run.tool.driver.rules // []) as $rules
        | (if ($r.ruleIndex | type) == "number" and $r.ruleIndex >= 0
           then $rules[$r.ruleIndex] else null end)
          // first($rules[] | select(.id == $r.ruleId))
          // null;
      def level($run):
        . as $r
        | if ($r.kind // "fail") != "fail" then "none"
          else ($r.level // rule($run).defaultConfiguration.level // "warning") end;
      [.runs[] as $run | $run.results[] | select(level($run) == "error")] | length
    ' results.sarif)
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "Found $HIGH_COUNT high severity issues"
      exit 1
    fi
```

### Fail on New Issues

```python
from sarif import loader

def check_for_regressions(baseline: str, current: str) -> int:
    """Return count of new issues not in baseline."""
    baseline_data = loader.load_sarif_file(baseline)
    current_data = loader.load_sarif_file(current)

    baseline_fps = {get_fingerprint(r) for r in baseline_data.get_results()}
    new_issues = [r for r in current_data.get_results()
                  if get_fingerprint(r) not in baseline_fps]

    return len(new_issues)
```

## Key Principles

1. **Validate first**: Check SARIF structure before processing
2. **Resolve severity, never read `result.level`**: it is optional, and CodeQL always omits it
3. **Handle optionals**: Many fields are optional; use defensive access
4. **Normalize paths**: Tools report paths differently; normalize early
5. **Fingerprint wisely**: Combine multiple strategies for stable deduplication
6. **Stream large files**: Use ijson or similar for 100MB+ files
7. **Aggregate thoughtfully**: Preserve tool metadata when combining files

## Skill Resources

For ready-to-use query templates, see [{baseDir}/resources/jq-queries.md]({baseDir}/resources/jq-queries.md):
- 40+ jq queries for common SARIF operations
- `LEVEL_FN` - the severity resolution every filtering query starts from
- Severity filtering, rule extraction, aggregation patterns

For Python utilities, see [{baseDir}/resources/sarif_helpers.py]({baseDir}/resources/sarif_helpers.py):
- `resolve_level()` - Severity from the result or the rule it inherits from
- `normalize_path()` - Handle tool-specific path formats
- `compute_fingerprint()` - Rule, normalized path, line, and message
- `deduplicate()` - Remove duplicates across runs

Two SARIF fixtures live in [{baseDir}/resources/fixtures]({baseDir}/resources/fixtures),
one with severity on the rules only and one with severity on the results. Each contains
exactly one error, so a gate can be checked against a known answer before it is trusted.

## Reference Links

- [OASIS SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [Microsoft SARIF Tutorials](https://github.com/microsoft/sarif-tutorials)
- [SARIF SDK (.NET)](https://github.com/microsoft/sarif-sdk)
- [sarif-tools (Python)](https://github.com/microsoft/sarif-tools)
- [pysarif (Python)](https://github.com/Kjeld-P/pysarif)
- [GitHub SARIF Support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
- [SARIF Validator](https://sarifweb.azurewebsites.net/)
