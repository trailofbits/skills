# SARIF jq Query Reference

Ready-to-use jq queries for common SARIF parsing tasks.

## Severity resolution (read this first)

`result.level` is optional in SARIF 2.1.0. CodeQL omits it on every result and stores
severity on the rule instead, as `defaultConfiguration.level`; the result inherits it.
So `select(.level == "error")` matches nothing on a CodeQL run no matter how many
errors it found, and a CI gate written that way exits 0 on a failing repo.

Resolve it instead: `result.level` when present, otherwise the matched rule's
`defaultConfiguration.level`, otherwise `"warning"` (the SARIF default). Join the rule
on `ruleIndex` when the tool populates it, on `ruleId` when it does not.

```bash
# Paste once per shell. `jq "$LEVEL_FN"'<query>'` concatenates the two into one filter.
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

# Severity of every result, whichever way the tool recorded it
jq -r "$LEVEL_FN"'.runs[] as $run | $run.results[] | "\(level($run))\t\(.ruleId)"' results.sarif

# The CI gate: count of error-level findings, however the tool recorded severity
jq "$LEVEL_FN"'[.runs[] as $run | $run.results[] | select(level($run) == "error")] | length' results.sarif
```

`kind` other than `"fail"` marks a pass/notApplicable record rather than a finding, and
resolves to `"none"`. Without that clause a compliance tool's passing checks inherit
their rule's `error` and fail the build. The `>= 0` guard matters as much: SARIF writes
`ruleIndex: -1` for "no rule", and `$rules[-1]` in jq is the *last* rule, so dropping it
labels those results with whatever severity the final rule in the array happens to have.

Two fixtures under `fixtures/` exercise both shapes: `codeql-no-level.sarif` (severity on
the rules only) and `levels-on-results.sarif` (severity on the results). Each holds exactly
one error, so any query below can be checked against a known answer.

## Basic Exploration

```bash
# Pretty print
jq '.' results.sarif

# Get SARIF version
jq '.version' results.sarif

# List tool names from all runs
jq '.runs[].tool.driver.name' results.sarif

# Count runs
jq '.runs | length' results.sarif
```

## Result Queries

```bash
# Total result count
jq '[.runs[].results[]] | length' results.sarif

# Count by severity level
jq "$LEVEL_FN"'reduce (.runs[] as $run | $run.results[] | level($run)) as $l ({}; .[$l] += 1)' results.sarif

# List unique rule IDs
jq '[.runs[].results[].ruleId] | unique | sort' results.sarif

# Count per rule
jq '[.runs[].results[]] | group_by(.ruleId) | map({rule: .[0].ruleId, count: length}) | sort_by(-.count)' results.sarif
```

## Filtering Results

```bash
# Only errors
jq "$LEVEL_FN"'.runs[] as $run | $run.results[] | select(level($run) == "error")' results.sarif

# Only warnings
jq "$LEVEL_FN"'.runs[] as $run | $run.results[] | select(level($run) == "warning")' results.sarif

# By specific rule ID
jq --arg rule "SQL_INJECTION" '.runs[].results[] | select(.ruleId == $rule)' results.sarif

# By file path (contains)
jq --arg file "auth" '.runs[].results[] | select(.locations[].physicalLocation.artifactLocation.uri | contains($file))' results.sarif

# By file extension
jq '.runs[].results[] | select(.locations[].physicalLocation.artifactLocation.uri | test("\\.py$"))' results.sarif

# Multiple conditions
jq "$LEVEL_FN"'.runs[] as $run | $run.results[] | select(level($run) == "error" and (.ruleId | startswith("SEC")))' results.sarif
```

## Extracting Locations

```bash
# File and line for each result
jq '.runs[].results[] | {
  rule: .ruleId,
  file: .locations[0].physicalLocation.artifactLocation.uri,
  line: .locations[0].physicalLocation.region.startLine
}' results.sarif

# Unique affected files
jq '[.runs[].results[].locations[].physicalLocation.artifactLocation.uri] | unique | sort' results.sarif

# Results grouped by file
jq '[.runs[].results[] | {file: .locations[0].physicalLocation.artifactLocation.uri, result: .}] | group_by(.file) | map({file: .[0].file, count: length})' results.sarif
```

## Rule Information

```bash
# List all rules with severity
jq '.runs[].tool.driver.rules[] | {id: .id, name: .name, level: .defaultConfiguration.level}' results.sarif

# Get rule description by ID
jq --arg id "RULE001" '.runs[].tool.driver.rules[] | select(.id == $id)' results.sarif

# Rules with help URLs
jq '.runs[].tool.driver.rules[] | select(.helpUri) | {id: .id, help: .helpUri}' results.sarif
```

## Fingerprints

```bash
# Results with fingerprints
jq '.runs[].results[] | select(.fingerprints or .partialFingerprints) | {rule: .ruleId, fp: (.fingerprints // .partialFingerprints)}' results.sarif

# Extract all partial fingerprints
jq '[.runs[].results[].partialFingerprints] | add' results.sarif
```

## Aggregation and Reporting

```bash
# Summary by severity and rule
jq "$LEVEL_FN"'[.runs[] as $run | $run.results[] | {level: level($run), ruleId}] | group_by(.level) | map({level: .[0].level, rules: (group_by(.ruleId) | map({rule: .[0].ruleId, count: length}))})' results.sarif

# Top 10 most frequent rules
jq '[.runs[].results[]] | group_by(.ruleId) | map({rule: .[0].ruleId, count: length}) | sort_by(-.count) | .[0:10]' results.sarif

# Files with most issues
jq '[.runs[].results[] | .locations[0].physicalLocation.artifactLocation.uri] | group_by(.) | map({file: .[0], count: length}) | sort_by(-.count) | .[0:10]' results.sarif
```

## Output Formatting

```bash
# CSV-like output
jq -r "$LEVEL_FN"'.runs[] as $run | $run.results[] | [.ruleId, level($run), .locations[0].physicalLocation.artifactLocation.uri, .locations[0].physicalLocation.region.startLine, .message.text] | @csv' results.sarif

# Tab-separated
jq -r "$LEVEL_FN"'.runs[] as $run | $run.results[] | [.ruleId, level($run), .locations[0].physicalLocation.artifactLocation.uri // "N/A"] | @tsv' results.sarif

# Markdown table
echo "| Rule | Level | File | Line |"
echo "|------|-------|------|------|"
jq -r "$LEVEL_FN"'.runs[] as $run | $run.results[] | "| \(.ruleId) | \(level($run)) | \(.locations[0].physicalLocation.artifactLocation.uri // "N/A") | \(.locations[0].physicalLocation.region.startLine // "N/A") |"' results.sarif
```

## Comparison and Diff

```bash
# Find rules in file1 not in file2
comm -23 <(jq -r '[.runs[].results[].ruleId] | unique | sort[]' file1.sarif) <(jq -r '[.runs[].results[].ruleId] | unique | sort[]' file2.sarif)

# Compare result counts
echo "File 1: $(jq '[.runs[].results[]] | length' file1.sarif)"
echo "File 2: $(jq '[.runs[].results[]] | length' file2.sarif)"
```

## Transformation

```bash
# Extract minimal SARIF (results only)
jq '{version: .version, runs: [.runs[] | {tool: {driver: {name: .tool.driver.name}}, results: .results}]}' results.sarif

# Filter and create new SARIF with only errors, per run: the rules a result
# inherits from live in its own run, so runs must not be flattened together
jq "$LEVEL_FN"'.runs |= map(. as $run | .results = [.results[] | select(level($run) == "error")])' results.sarif > errors-only.sarif

# Merge multiple SARIF files
jq -s '{version: "2.1.0", runs: [.[].runs[]]}' file1.sarif file2.sarif > merged.sarif
```

## Validation Checks

```bash
# Check if version is 2.1.0
jq -e '.version == "2.1.0"' results.sarif && echo "Valid version" || echo "Invalid version"

# Check for empty results
jq -e '[.runs[].results[]] | length > 0' results.sarif && echo "Has results" || echo "No results"

# Verify all results have locations
jq '[.runs[].results[] | select(.locations | length == 0)] | length' results.sarif
```
