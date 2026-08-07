# Reporting a Variant Hunt

Advice for the final stage. The report is written for a security engineer that is reviewing vulnerability variants.

## Structure

Fill `../resources/variant-report-template.md` — the path is relative to this file, so
from the skill root it is `resources/variant-report-template.md`. Every section earns its
place:

- **Summary** — original bug, date, codebase, count
- **Original vulnerability** — the root cause statement, the origin location, the code
- **Search methodology** — the patterns tried, at which level, with match and FP counts
- **Findings** — one block per confirmed variant, severity-ordered
- **False positive patterns** — grouped by reason, not one row per match
- **Recommendations** — immediate fixes, then preventive measures

## The Methodology Table

| Version | Pattern | Tool | Matches | TP | FP |
|---------|---------|------|---------|----|----|
| v1 | exact | ripgrep | 1 | 1 | 0 |
| v2 | abstract | semgrep | N | N | N |

This table makes the hunt reproducible. It records which abstractions worked, which
produced noise, and where the search stopped.

Record the patterns that failed alongside those that worked.

## Quote the Real Code

Read each confirmed location and quote what is actually there. A report that paraphrases
code loses the detail a reviewer needs to confirm the finding, and a wrong quote destroys
trust in every other finding in the document.

## Leave a Regression Guard

End with a CI-ready rule derived from whichever pattern found the most variants.
