# CI gate for SARIF severity

Moved verbatim from the shipped SKILL.md ("CI/CD Integration Patterns"). This is the gate from
issue #262. It inlines its own copy of the severity resolver because a workflow step has no
shell variable to paste into; `test_sarif_helpers.py` runs this exact block against the fixtures.

For a regression gate (fail on findings absent from a baseline), use the helper instead of the
old pysarif snippet: `uv run --no-project {baseDir}/resources/sarif_helpers.py diff BASELINE CURRENT` and
fail when `.new.total` is greater than zero.

## GitHub Actions

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
