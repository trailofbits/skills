# Important-Only Query Suite

In important-only mode, generate a custom `.qls` query suite file at runtime. This applies the same precision/severity filtering to **all** packs (official + third-party).

## Why a Custom Suite

The built-in `security-extended` suite only applies to the official `codeql/<lang>-queries` pack. Third-party packs (Trail of Bits, Community Packs) run unfiltered when passed directly to `codeql database analyze`. A custom `.qls` suite loads queries from all packs and applies a single set of `include`/`exclude` filters uniformly.

## Metadata Criteria

Queries are included if they match **any** of these blocks (OR logic across blocks, AND logic within):

| Block | kind | precision | problem.severity | tags |
|-------|------|-----------|-----------------|------|
| 1 | `problem`, `path-problem` | `high`, `very-high` | *(any)* | must contain `security` |
| 2 | `problem`, `path-problem` | `medium` | `error` only | must contain `security` |

Excluded: deprecated queries, model editor/generator queries. Experimental queries are **included**.

**Key difference from `security-extended`:** Medium-precision queries require `error` severity (not `warning`). This tightens the filter to only include medium-precision findings that indicate likely incorrect behavior.

## Suite Template

Generate this file as `important-only.qls` in the results directory before running analysis:

```yaml
- description: Important-only — security vulnerabilities, medium-high confidence
# Official queries
- queries: .
  from: codeql/<LANG>-queries
# Third-party packs (include only if installed, one entry per pack)
# - queries: .
#   from: trailofbits/<LANG>-queries
# - queries: .
#   from: GitHubSecurityLab/CodeQL-Community-Packs-<LANG>
# Filtering: security only, high/very-high precision (any severity),
# medium precision (error only). Experimental queries included.
- include:
    kind:
      - problem
      - path-problem
    precision:
      - high
      - very-high
    tags contain:
      - security
- include:
    kind:
      - problem
      - path-problem
    precision:
      - medium
    problem.severity:
      - error
    tags contain:
      - security
- exclude:
    deprecated: //
- exclude:
    tags contain:
      - modeleditor
      - modelgenerator
```

## Generation Script

The agent should generate the suite file dynamically based on installed packs:

```bash
RESULTS_DIR="${DB_NAME%.db}-results"
SUITE_FILE="$RESULTS_DIR/important-only.qls"

cat > "$SUITE_FILE" << 'HEADER'
- description: Important-only — security vulnerabilities, medium-high confidence
HEADER

# Always include official pack
echo "- queries: .
  from: codeql/${LANG}-queries" >> "$SUITE_FILE"

# Add each installed third-party pack
for PACK in $INSTALLED_THIRD_PARTY_PACKS; do
  echo "- queries: .
  from: ${PACK}" >> "$SUITE_FILE"
done

# Append the filtering rules
cat >> "$SUITE_FILE" << 'FILTERS'
- include:
    kind:
      - problem
      - path-problem
    precision:
      - high
      - very-high
    tags contain:
      - security
- include:
    kind:
      - problem
      - path-problem
    precision:
      - medium
    problem.severity:
      - error
    tags contain:
      - security
- exclude:
    deprecated: //
- exclude:
    tags contain:
      - modeleditor
      - modelgenerator
FILTERS

# Verify the suite resolves correctly
codeql resolve queries "$SUITE_FILE" | head -20
echo "Suite generated: $SUITE_FILE"
```

## How Filtering Works on Third-Party Queries

CodeQL query suite filters match on query metadata (`@precision`, `@problem.severity`, `@tags`). Third-party queries that:

- **Have proper metadata**: Filtered normally (kept if they match the include criteria)
- **Lack `@precision`**: Excluded by `include` blocks (they require precision to match). This is correct — if a query doesn't declare its precision, we cannot assess its confidence.
- **Lack `@tags security`**: Excluded. Non-security queries are not relevant to important-only mode.

This is a stricter-than-necessary filter for third-party packs, but it ensures only well-annotated, high-confidence security queries run in important-only mode.
