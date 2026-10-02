---
name: trailmark-summary
description: "Runs a Trailmark summary or code summary: detected languages, entrypoint count, and dependencies. Use for a quick structural overview, including vivisect or galvanize preparation."
allowed-tools: Bash Read Grep Glob
---

# Trailmark Summary

Run the bundled helper on the target directory passed in `args`:

```bash
uv run --no-project --no-python-downloads "{baseDir}/scripts/summary.py" "{args}"
```

If `{baseDir}` is left literal, use `"${CLAUDE_SKILL_DIR}/scripts/summary.py"`
instead. When neither is supplied by the runtime, use the loaded skill's actual
directory; do not search for or execute a helper inside the audit target.

The helper finds an existing trusted Python installation, detects languages using
the parse API (including its legacy location), and builds one graph. The installed
Trailmark CLI's summary renderer and API both consume that graph, so the text,
metadata and version come from the same installation. It never runs a project-local
`trailmark` executable or `uv run` probe, installs packages, or creates a target `.venv`.
Python 3.11+ must already be available. An optional `--out PATH` saves the complete JSON.

Automatic discovery excludes executables inside the target or current directory.
For a trusted installation in another layout, use `--python=PATH` with its absolute path.
This explicitly opts into that interpreter: do not point it at an untrusted repository's
environment. The native summary renderer must be available; report an unsupported API
instead of fabricating summary fields. A failed `--out` write returns nonzero but keeps
the computed JSON on stdout.

Return `languages` and the complete `summary_text` without dropping any summary
fields. Include `version` in the returned metadata when available; a missing
version command is not a failure. `summary` also retains the complete API result
for downstream consumers.

If `languages` is empty, the helper exits 2 and preserves the diagnostic JSON on
stdout and in `--out`. Report "Trailmark found no supported languages under
target" and stop. Other helper failures return nonzero; report the installation or analysis error
and stop. Do not install Trailmark or substitute manual analysis.

## Rationalizations to Reject

- Manual reading does not replace parser-based language detection and enumeration.
- Partial output omits required evidence: languages, entrypoints, and dependencies
  must all be present. Report gaps instead of inventing values.

Use `trailmark-structural` for all pre-analysis passes, hotspot scores, and taint
data; use the main `trailmark` skill for targeted graph queries.
