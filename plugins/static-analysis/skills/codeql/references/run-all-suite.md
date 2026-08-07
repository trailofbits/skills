# Run-All Query Suite

In run-all mode, generate a custom `.qls` query suite file at runtime. It runs the `security-and-quality` and `security-experimental` suites of every installed pack, which is a much wider selection than the code-scanning default each pack would otherwise apply — but it is not every query in those packs. See [What "run all" does and does not cover](#what-run-all-does-and-does-not-cover) before reporting coverage to anyone.

## Why a Custom Suite

When you pass a pack name directly to `codeql database analyze` (e.g., `-- codeql/cpp-queries`), CodeQL uses the pack's `defaultSuiteFile` field from `qlpack.yml`. For official packs, this is typically `codeql-suites/<lang>-code-scanning.qls`, which applies strict precision and severity filters. This drops many queries and can produce zero results for small codebases.

The run-all suite explicitly imports both `security-and-quality` and `security-experimental` from official packs, plus third-party packs with minimal filtering.

> **Why both suites?** `security-and-quality` = stable security + code quality (excludes `experimental/` paths). `security-experimental` = stable security + experimental security (re-includes `experimental/` paths tagged `security`). They are complementary — importing both is safe since CodeQL deduplicates shared queries automatically.

## Suite Template

What the generation script writes, shown so the imports and filters are readable. Do not
hand-write this file — the script adds the installed third-party packs and verifies the
result, and `test_generation_scripts.py` fails if this block and the script disagree:

```yaml
- description: Run-all — the security-and-quality and security-experimental suites from all installed packs, not every query in them; see run-all-suite.md
# Official queries: import BOTH suites (they are complementary, not hierarchical)
# security-and-quality = stable security + code quality (excludes experimental/ paths)
# security-experimental = stable security + experimental security (re-includes experimental/ with security tag)
- import: codeql-suites/<CODEQL_LANG>-security-and-quality.qls
  from: codeql/<CODEQL_LANG>-queries
- import: codeql-suites/<CODEQL_LANG>-security-experimental.qls
  from: codeql/<CODEQL_LANG>-queries
# Third-party packs (include only if installed, one entry per pack)
# - queries: .
#   from: trailofbits/<CODEQL_LANG>-queries
# - queries: .
#   from: GitHubSecurityLab/CodeQL-Community-Packs-<CODEQL_LANG>
# Minimal filtering — only select alert-type queries
- include:
    kind:
      - problem
      - path-problem
- exclude:
    deprecated: //
- exclude:
    tags contain:
      - modeleditor
      - modelgenerator
```

## Generation Script

```bash
# `set -e` and the trailing script call are both load-bearing: an assignment placed last
# would overwrite the script's exit status, and the run would proceed to analysis with no
# suite — or with a stale one from an earlier run.
set -euo pipefail
SUITE_FILE="$OUTPUT_DIR/raw/run-all.qls"
CODEQL_LANG="${CODEQL_LANG:-}" OUTPUT_DIR="${OUTPUT_DIR:-}" \
  INSTALLED_THIRD_PARTY_PACKS="${INSTALLED_THIRD_PARTY_PACKS:-}" \
  {baseDir}/scripts/generate_suite.sh run-all
```

Run-all imports whole upstream suites. A typo in `$CODEQL_LANG` gives a suite that resolves
to nothing instead of one that errors, so without the script's `verify_query_suite.py` call
the run would continue and report no findings.

## What "run all" does and does not cover

Measured against `codeql/cpp-queries` 1.8.0 with CodeQL 2.25.6:

| | cpp queries |
|---|---|
| `cpp-security-and-quality.qls` | 182 |
| `cpp-security-experimental.qls` | 135 |
| This template (both imported) | **219** — the exact union |
| Alert queries in the whole pack | 515 |

Two consequences the mode name hides:

- **"Run all" is not every query in the pack.** Of its 219, only 208 raise alerts; the
  other 11 are `Diagnostics/`, `Summary/`, and `Telemetry/` queries about the extraction
  itself. So 307 of the pack's 515 alert queries never run. Most are the coding-standard
  packs the official suites deliberately exclude (`jsf` 137, `JPL_C` 42, `Power of 10`
  23), but 13 are `Security/CWE/` queries — `ArithmeticTainted`, `IntegerOverflowTainted`,
  and `ImproperArrayIndexValidation` among them — and 20 are `Critical/` resource-leak and
  initialization queries. Skipping the standards packs in a security scan is reasonable;
  it is still a choice, not total coverage.
- **important-only is not a subset of run-all.** The modes select differently: run-all
  `import:`s two official suites, while important-only takes `queries: .` (the whole pack)
  and filters on precision. So important-only selects a few queries run-all does not —
  three for cpp, including `SuspiciousCallToMemset.ql`.

Re-check on your own packs after a pack upgrade; these counts move:
`codeql resolve queries "$OUTPUT_DIR/raw/run-all.qls" --format=json | jq length`.

## How This Differs From Important-Only

| Aspect | Run all | Important only |
|--------|---------|----------------|
| Official pack suites | `security-and-quality` + `security-experimental` (stable security + code quality + experimental security) | All queries loaded, filtered by precision |
| Third-party packs | All `problem`/`path-problem` queries | Only `security`-tagged queries with precision metadata |
| Precision filter | None | high/very-high always; medium only if security-severity >= 6.0 |
| Post-analysis filter | None | Drops medium-precision results with security-severity < 6.0 |
