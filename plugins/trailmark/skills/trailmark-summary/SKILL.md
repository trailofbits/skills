---
name: trailmark-summary
description: "Runs a Trailmark summary analysis on a codebase. Returns auto-detected languages, entry point count, and dependency list. Use when vivisect or galvanize needs a quick structural overview. Triggers: trailmark summary, code summary, structural overview."
allowed-tools: Bash Read Grep Glob
---

# Trailmark Summary

Runs `trailmark analyze --language auto --summary` on a target directory.
The text-summary baseline works on older builds. On Trailmark 0.7+, prefer
`analyze --language auto --summary --json`: it includes selected languages,
inspected source-file counts, entrypoints, dependencies, and parse diagnostics.
The installed registry includes 39 languages, including the nine new frontends;
do not infer supported languages from a hardcoded extension list.

## When to Use

- Vivisect Phase 0 needs a quick structural overview before decomposition
- Galvanize Phase 1 needs detected languages and entry point count
- Quick orientation on an unfamiliar codebase before deeper analysis

## When NOT to Use

- Full structural analysis with all passes needed (use `trailmark-structural`)
- Detailed code graph queries (use the main `trailmark` skill directly)
- You need hotspot scores or taint data (use `trailmark-structural`)

## Rationalizations to Reject

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "I can read the code manually instead" | Manual reading misses parser-based language detection, dependency data, and entry point enumeration | Install and run trailmark |
| "Language detection doesn't matter" | Wrong language selection produces empty or partial analysis | Use Trailmark's parser-based detection or `--language auto` |
| "A clean summary proves complete coverage" | Source counts measure inspected files, and diagnostics do not model every language feature | Report counts, parse limitations, entrypoints, and dependencies together |
| "Tool isn't installed, I'll skip it" | This skill exists specifically to run trailmark | Report the installation gap instead of skipping |

## Usage

The target directory is passed via the `args` parameter.

## Execution

**Step 1: Check that trailmark is available.**

```bash
trailmark analyze --help 2>/dev/null || \
  uv run trailmark analyze --help 2>/dev/null
```

If neither command works, report "trailmark is not installed"
and return. Do NOT run `pip install`, `uv pip install`,
`git clone`, or any install command. The user must install
trailmark themselves.

Optionally record the version if the installed build supports it:

```bash
trailmark --version 2>/dev/null || uv run trailmark --version 2>/dev/null || true
```

Do not fail if the version command is missing; older v0.2.x builds may still
support the summary workflow.

**Step 2: Detect languages with Trailmark's parse API.**

```bash
python3 - "{args}" <<'PY'
import json
import sys

try:
    from trailmark.parse import detect_languages  # canonical location since 0.3.x
except ModuleNotFoundError:
    # v0.2.x predates trailmark.parse; the same function lives in query.api
    from trailmark.query.api import detect_languages

print(json.dumps(detect_languages(sys.argv[1])))
PY
```

If the import fails, rerun the same snippet with `uv run --with trailmark python - "{args}"`.
If the result is `[]`, report "Trailmark found no supported languages under
target" and return.

**Step 3: Run the summary with auto-detection.**

```bash
trailmark analyze --language auto --summary {args} 2>&1 || \
  uv run trailmark analyze --language auto --summary {args} 2>&1
```

On 0.7+, use `trailmark analyze --language auto --summary --json {args}` for
machine-readable output. Keep `languages`, `source_files`, `source_file_counts`,
`parse_diagnostics`, `entrypoints`, and `dependencies`. Missing roots and zero
matching files are failures unless the user deliberately requests an empty
selection; a comment-only inspected file is valid even with no declarations.
Use `--resolution` in a separate invocation when unresolved call counts matter.

**Step 4: Deliver the required summary fields.**

For 0.7 JSON output, return the selected languages, source counts, diagnostics,
entrypoint count, dependencies, and full summary. For older text output, include
the detected language list from Step 2 and the summary's `Entrypoints:` and
`Dependencies:` lines. Report unavailable fields rather than fabricating them.
Include the installed Trailmark version in the returned metadata when available.
