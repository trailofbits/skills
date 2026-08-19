# Scan Modes Reference

## Mode: Run All

Full scan with all rulesets and severity levels. Current default behavior. No filtering applied — all findings are reported and triaged.

## Mode: Important Only

Focused on high-confidence security vulnerabilities. Excludes code quality, best practices, and low-confidence audit findings.

### Pre-Filter: CLI Severity Flag

Add these flags to every `semgrep` command:

```bash
--severity WARNING --severity ERROR
```

This excludes INFO findings at scan time, reducing output volume before post-filtering.

`--severity` takes `INFO`, `WARNING`, or `ERROR`, and nothing else. Anything else exits 2 before
scanning, with no output written. The `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` scale in the table below
belongs to the rule metadata, which the post-filter reads. The two are not interchangeable.

The two scales do not nest. A registry rule can carry CLI severity `INFO` and metadata
`impact: HIGH`, and this flag drops it at scan time before the post-filter sees it. The volume
reduction is why the pre-filter runs at scan time, but it makes important-only "WARNING and
above, then filtered on metadata" rather than "everything the metadata filter would keep".
Check a missing finding against a run-all scan before concluding the rule did not fire.

### Post-Filter: Metadata Criteria

After scanning, filter each JSON result file to keep only findings matching ALL of:

| Metadata Field | Accepted Values | Rationale |
|---|---|---|
| `extra.metadata.category` | `"security"` | Excludes correctness, best-practice, maintainability, performance |
| `extra.metadata.confidence` | `"MEDIUM"`, `"HIGH"` | Excludes low-precision rules (high false positive rate) |
| `extra.metadata.impact` | `"MEDIUM"`, `"HIGH"` | Excludes low-impact informational findings |

**Third-party rules** (Trail of Bits, 0xdea, Decurity, etc.) may not have `confidence`/`impact`/`category` metadata. Findings **without** these metadata fields are **kept by the post-filter** — we cannot filter what is not annotated, and third-party rules are typically security-focused.

This exemption applies only to findings that reach the post-filter. The pre-filter above runs first and on every command, including the cross-language unit that carries the cloned third-party repos, so an unannotated rule with CLI `severity: INFO` is dropped at scan time and never becomes a finding the exemption can keep. A third-party rule is exempt from the metadata filter, not from `--severity`.

### Semgrep Metadata Background

Semgrep security rules have these metadata fields (required for `category: security` in the official registry):

| Field | Purpose | Metadata values (never CLI `--severity` values) |
|---|---|---|
| `severity` (top-level) | Overall rule severity, derived from likelihood × impact | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `category` | Rule category | `security`, `correctness`, `best-practice`, `maintainability`, `performance` |
| `confidence` | True positive rate of the rule (precision) | `LOW`, `MEDIUM`, `HIGH` |
| `impact` | Potential damage if vulnerability is exploited | `LOW`, `MEDIUM`, `HIGH` |
| `likelihood` | How likely the vulnerability is exploitable | `LOW`, `MEDIUM`, `HIGH` |
| `subcategory` | Finding type | `vuln`, `audit`, `secure default` |

Key relationship: `severity = f(likelihood, impact)` while `confidence` is independent (describes rule quality, not vulnerability severity).

### Post-Filter jq Command

Apply to each JSON result file after scanning:

```bash
# Filter a single result file
jq '{
  results: [.results[] |
    ((.extra.metadata.category // "security") | ascii_downcase) as $cat |
    ((.extra.metadata.confidence // "HIGH") | ascii_upcase) as $conf |
    ((.extra.metadata.impact // "HIGH") | ascii_upcase) as $imp |
    select(
      ($cat == "security") and
      ($conf == "MEDIUM" or $conf == "HIGH") and
      ($imp == "MEDIUM" or $imp == "HIGH")
    )
  ],
  errors: .errors,
  paths: .paths
}' "$f" > "${f%.json}-important.json"
```

Default values (`// "security"`, `// "HIGH"`) handle third-party rules without metadata — they pass all filters by default.

### Filter All Result Files in a Directory

Raw scan output lives in `$OUTPUT_DIR/raw/`. The filter creates `*-important.json` files alongside the originals — the raw files are preserved unmodified.

```bash
# Apply important-only filter to all scan result JSON files in raw/
filter_failed=0
for f in "$OUTPUT_DIR/raw"/*-*.json; do
  [[ "$f" == *-triage.json || "$f" == *-important.json ]] && continue
  out="${f%.json}-important.json"
  # The redirect creates $out before jq runs, so a jq failure leaves a zero-byte file sitting
  # there. merge_sarif.py --important reads that as a corrupt filter and aborts the whole
  # merge, losing every other scan's findings to one bad file. Delete it and name the file.
  if ! jq '{
    results: [.results[] |
      ((.extra.metadata.category // "security") | ascii_downcase) as $cat |
      ((.extra.metadata.confidence // "HIGH") | ascii_upcase) as $conf |
      ((.extra.metadata.impact // "HIGH") | ascii_upcase) as $imp |
      select(
        ($cat == "security") and
        ($conf == "MEDIUM" or $conf == "HIGH") and
        ($imp == "MEDIUM" or $imp == "HIGH")
      )
    ],
    errors: .errors,
    paths: .paths
  }' "$f" >"$out"; then
    rm -f "$out"
    filter_failed=$((filter_failed + 1))
    echo "post-filter failed on $f" >&2
    continue
  fi
  BEFORE=$(jq '.results | length' "$f")
  AFTER=$(jq '.results | length' "$out")
  echo "$f: $BEFORE → $AFTER findings (filtered $(( BEFORE - AFTER )))"
done
[ "$filter_failed" -eq 0 ] ||
  echo "$filter_failed file(s) failed to filter; fix them before merging" >&2
```

### The Filter Does Not Apply to SARIF

Both filters above are written for semgrep's JSON shape and cannot be pointed at a `.sarif` file.
SARIF has no top-level `.results` and no `extra.metadata` — `category`, `confidence` and `impact`
are simply not in the format — so the filter exits with `Cannot iterate over null`, and
redirecting it over its own input truncates the file first.

The merged SARIF is filtered by `scripts/merge_sarif.py --important` instead, which keeps the
findings these filters kept by matching `(check_id, path, start.line)` against SARIF's
`(ruleId, uri, region.startLine)`. Run the JSON filter over every file in `raw/` first: the merge
fails rather than filtering if any scan has no `*-important.json` beside it, since a partial key
set would drop real findings from the primary deliverable with nothing downstream to notice.

### Scanner Command Modifications

`scripts/run-scans.sh` puts these on every command it generates; they are not yours to add.

- **Run all**: no severity flags
- **Important only**: `--severity WARNING --severity ERROR`

That pre-filter is applied by semgrep at scan time, before the metadata post-filter above. A
rule shipping with CLI severity INFO is dropped by the flag and never reaches the filter that
would have kept it.
