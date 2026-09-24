---
name: sarif-parsing
description: >-
  Read, filter, deduplicate, compare, and export SARIF findings from CodeQL, Semgrep, and
  other scanners. Use for SARIF scan results, severity counts, finding filters, alert
  deduplication, or SARIF comparison. Does not run scans.
allowed-tools: Bash Read Glob Grep
---

# SARIF Parsing

Use the bundled helper first. It resolves SARIF severity correctly and returns compact
output. Use `Read` only for a small file or a small extracted record that needs inspection.

The plugin blocks direct `Read` calls for SARIF files over 200 KiB, even with line limits:
one line of JSON can be huge. Use the helper's bounded commands or extract the needed record
to a small file with a custom query; leave the source file unchanged.

## Procedure

1. Find `*.sarif` files with `Glob`, then start with a summary:

   ```bash
   uv run --no-project {baseDir}/resources/sarif_helpers.py summary results.sarif
   ```

2. Choose the command that answers the request:

   | Request | Command |
   |---|---|
   | Count findings by severity or rule | `summary FILE` |
   | Show errors, a rule, or a path | `filter FILE --level error --rule RULE --path src/ --limit 100` |
   | Remove duplicates across files | `dedupe FILE... --limit 100` |
   | Compare a baseline and current run | `diff BASELINE CURRENT --limit 100` |
   | Export compact findings | `csv FILE > findings.csv` |

   `--limit 100` is the default for JSON output. Use `--limit 0` only when the user
   explicitly needs every matching record. `summary` lists only the top 20 rules by default;
   use `--top-rules 0` only when the user explicitly needs every rule count.

3. Report the command's counts and the relevant compact findings. The helper's JSON fields
   are `rule_id`, `level`, `file`, `line`, `message`, and `fingerprint`.

## Rules that must not change

- Never filter on `result.level` directly. It is optional: CodeQL commonly stores severity
  on the matching rule. The helper resolves severity in this order: non-failing `kind` →
  result level → rule default level → `warning`.
- `ruleIndex: -1` is not a valid rule index. The helper falls back to `ruleId` instead.
- Keep the full directory in a fallback deduplication key. Two findings at the same line in
  `auth/login.py` and `admin/login.py` are different findings.

## When to read references

- Read `resources/jq-queries.md` only for a custom jq query the helper cannot express.
- Read `resources/ci-gate.md` only when adding a severity gate to a CI workflow.
- The helper and its fixtures are the source of truth for severity and fingerprint behaviour.

This skill processes existing SARIF; it does not run CodeQL, Semgrep, or another scanner.
