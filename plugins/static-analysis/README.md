# Static Analysis

A comprehensive static analysis toolkit with CodeQL, Semgrep, and SARIF parsing for security vulnerability detection.

CodeQL and Semgrep skills are based on the Trail of Bits Testing Handbook:

- [CodeQL Testing Handbook](https://appsec.guide/docs/static-analysis/codeql/)
- [Semgrep Testing Handbook](https://appsec.guide/docs/static-analysis/semgrep/)

**Author:** Axel Mierczuk & Paweł Płatek

## Skills Included

| Skill           | Purpose                                                  |
|-----------------|----------------------------------------------------------|
| `codeql`        | Deep security analysis with taint tracking and data flow |
| `semgrep`       | Fast pattern-based security scanning                     |
| `sarif-parsing` | Parse and process results from static analysis tools     |

## When to Use

Use this plugin when you need to:
- Perform security vulnerability detection on codebases
- Run CodeQL for interprocedural taint tracking and data flow analysis
- Use Semgrep for fast pattern-based bug detection
- Parse SARIF output from security scanners
- Aggregate and deduplicate findings from multiple tools

## What It Does

### CodeQL
- Create databases for Python, JavaScript, Go, Java, C/C++, and more
- Run security queries with SARIF/CSV output
- Generate data extension models for project-specific APIs
- Select and combine query packs (security-extended, Trail of Bits, Community)

### Semgrep
- Quick security scans using built-in rulesets (OWASP, CWE, Trail of Bits)
- Write custom YAML rules with pattern matching
- Taint mode for tracking data flow from sources to sinks
- CI/CD integration with baseline scanning

### SARIF Parsing
- Understand SARIF 2.1.0 structure
- Resolve a result's severity from the rule it inherits it from, which CodeQL relies on
- Quick analysis using jq for CLI queries
- Python scripting with pysarif and sarif-tools
- Aggregate and deduplicate results from multiple files
- CI/CD integration patterns

## Running a Semgrep scan

Two entry points over one implementation.

```
/static-analysis:semgrep-scan {"target": "/abs/path", "mode": "run-all"}
```

runs the scan end to end: detect languages and Pro, select rulesets, scan, merge, report. It
does not stop to have the ruleset list approved — invoking it with a target is the opt-in. That
is safe because the scan is read-only over the target: no `--autofix`, every write inside the
output directory, and it refuses to run when the output directory is the target.

Ask for the `semgrep` skill instead when the ruleset selection is the thing that matters. Its
five-step path presents the list and waits for approval before anything runs. Both paths read
the same `references/`, so a ruleset added to `rulesets.md` reaches both.

## Workflows Included

| Workflow | Purpose |
|----------|---------|
| `workflows/semgrep-scan.js` | Ships as `/static-analysis:semgrep-scan`. Four phases: Detect, Select, Scan, Report |
| `workflows/codeql-build.js` | Ships as `/static-analysis:codeql-build`. Three phases: Detect, Build, Assess. Walks the build-method ladder — autobuild, custom command, multi-step, no-build — diagnosing and retrying at each rung, then enforces the quality gate |

## Scripts Included

| Script | Purpose |
|--------|---------|
| `skills/semgrep/scripts/run-scans.sh` | Builds every semgrep command from the selected rulesets, clones the third-party rule repos, runs the scans in batches and writes `scans.json` |
| `skills/semgrep/scripts/merge_sarif.py` | Merges the per-scan SARIF into one `results.sarif` |

Generating the commands in one place is what makes `--metrics=off`, the `--include` scoping
rule, and the output-directory `--exclude` properties of the code rather than instructions a
model can drop.

No subagent runs any part of the scan — the workflow's Scan phase calls `run-scans.sh`. Exit
codes come from the semgrep processes and finding counts from the JSON they wrote, so nothing in
the result is a self-report that a later step has to go behind and verify.

## Tests

Both suites are hermetic, reach no network, and are discovered by CI's existing shell-suite step.

| Suite | Covers |
|-------|--------|
| `tests/run_scan_tests.sh` | `run-scans.sh`: command generation via `--dry-run`, plus execution, exit codes and clone failures against stub `semgrep` and `git` binaries |
| `tests/run_workflow_tests.sh` | `semgrep-scan.js`, via `tests/workflow-harness.js`, which compiles it with stubbed globals. `--self-test` mutates the workflow and requires every mutation to turn a scenario red |

## Installation

```
/plugin install trailofbits/skills/plugins/static-analysis
```

## Related Skills

- `variant-analysis` - Use CodeQL/Semgrep patterns to find bug variants
