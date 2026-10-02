# CI gate for SARIF severity

This preserves the severity gate from issue #262 and also rejects failed/incomplete scans.
It resolves SARIF 2.0 and 2.1 rules; tests execute this exact jq program.

For a regression gate (fail on findings absent from a baseline), use the helper instead of the
old pysarif snippet. Vendor this skill's `resources/sarif_helpers.py` from a reviewed,
pinned revision into your repository as `ci/sarif_helpers.py`. Retrieve a completed,
trusted baseline scan into `baseline.sarif` and the current scan into `results.sarif`.
Install uv and jq on the runner. A workflow runner does not expand `{baseDir}`.

```bash
set -euo pipefail
uv run --no-project ci/sarif_helpers.py diff baseline.sarif results.sarif > sarif-diff.json
jq -e '.new.total == 0' sarif-diff.json
```

## GitHub Actions

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Check for high severity
  run: |
    set -euo pipefail
    # select(.level == "error") counts zero on CodeQL output, which records severity on
    # the rule instead. Resolve the level or the gate passes on a repo full of errors.
    HIGH_COUNT=$(jq '
      def rule($run):
        . as $r
        | (($run.tool.driver.rules // $run.resources.rules // [])
           | if type == "object" then to_entries | map(.value + {id: (.value.id // .key)}) else . end) as $rules
        | (if ($r.ruleIndex | type) == "number" and $r.ruleIndex >= 0 and $r.ruleIndex == ($r.ruleIndex | floor)
           then $rules[$r.ruleIndex] else null end)
          // first($rules[] | select(.id == $r.ruleId))
          // null;
      def level($run):
        . as $r
        | if ($r.kind // "fail") != "fail" then "none"
          else ($r.level // rule($run).defaultConfiguration.level // rule($run).configuration.defaultLevel // "warning") end;
      if (.runs | type) != "array" then error("incomplete scan: missing runs")
      elif any(.runs[]; (.results | type) != "array" or any(.invocations[]?; .executionSuccessful == false))
      then error("failed or incomplete scan") else . end |
      [.runs[] as $run | $run.results[] | select(level($run) == "error")] | length
    ' results.sarif)
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "Found $HIGH_COUNT high severity issues"
      exit 1
    fi
```
