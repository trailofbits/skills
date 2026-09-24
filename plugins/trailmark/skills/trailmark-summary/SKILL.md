---
name: trailmark-summary
description: "Summarizes a codebase with Trailmark: detected languages, entrypoint count, and dependencies. Use for a quick structural overview, including vivisect or galvanize preparation."
allowed-tools: Bash Read Grep Glob
---

# Trailmark Summary

Run the bundled helper on the target directory passed in `args`:

```bash
uv run --no-project {baseDir}/scripts/summary.py "{args}"
```

The helper checks the existing Trailmark installation, detects languages using
the parse API (including the v0.2 fallback), and runs
`trailmark analyze --language auto --summary`. It does not install Trailmark or
require version 0.4.0. An optional `--out PATH` saves the complete JSON payload.

Return `languages` and the complete `summary_text` without dropping any summary
fields. Include `version` in the returned metadata when available; a missing
version command is not a failure. `summary` also retains the complete API result
for downstream consumers.

If `languages` is empty, report "Trailmark found no supported languages under
target" and stop. If the helper fails, report the installation or analysis error
and stop. Do not install Trailmark or substitute manual analysis.

## Rationalizations to Reject

- Manual reading does not replace parser-based language detection and enumeration.
- Partial output omits required evidence: languages, entrypoints, and dependencies
  must all be present. Report gaps instead of inventing values.

Use `trailmark-structural` for all pre-analysis passes, hotspot scores, and taint
data; use the main `trailmark` skill for targeted graph queries.
