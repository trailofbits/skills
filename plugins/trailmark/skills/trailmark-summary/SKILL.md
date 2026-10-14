---
name: trailmark-summary
description: "Runs a Trailmark summary analysis on a codebase. Returns auto-detected languages, entry point count, and dependency list. Use when vivisect or galvanize needs a quick structural overview. Triggers: trailmark summary, code summary, structural overview."
allowed-tools: Bash Read Grep Glob
---

# Trailmark Summary

Runs `trailmark analyze --language auto --summary` on a target directory.
This is a v0.2-safe workflow; do not require Trailmark 0.4.0 just to produce a
summary.

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
| "Partial output is good enough" | Missing any of the three required outputs (detected languages, entry points, dependencies) means incomplete analysis | Verify all three are present |
| "Tool isn't installed, I'll skip it" | This skill exists specifically to run trailmark | Report the installation gap instead of skipping |

## Usage

The target directory is passed via the `args` parameter.

## Shortcut

Run the bundled helper first. It finds the Python that already has Trailmark
(the `trailmark` launcher's interpreter or a global one), installs nothing,
never runs a project-local `trailmark` or creates a `.venv`, and builds one
graph for both the language list and the summary:

```bash
uv run --no-project --no-python-downloads "{baseDir}/scripts/summary.py" "{args}"
```

- **Exit 0:** return `languages` and the complete `summary_text` (plus
  `version` when present). The helper has already checked that `Entrypoints:`
  and `Dependencies:` are present, so skip Steps 1-4.
- **Exit 2:** report "Trailmark found no supported languages under target" and
  return.
- **Any other result:** follow Steps 1-4 below, still without installing
  anything. Pass `--python=PATH` only for an interpreter you trust.

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

If the import fails (a `uv tool install` environment is not importable from
the system `python3`), rerun the same snippet with the interpreter from the
CLI's shebang, which needs no install:
`"$(head -1 "$(command -v trailmark)" | sed 's/^#!//')" - "{args}"`.
If that also fails, report "trailmark is not installed" and return.
If the result is `[]`, report "Trailmark found no supported languages under
target" and return.

**Step 3: Run the summary with auto-detection.**

```bash
trailmark analyze --language auto --summary "{args}" 2>&1 || \
  uv run trailmark analyze --language auto --summary "{args}" 2>&1
```

**Step 4: Verify the output.**

The output must include ALL THREE of:
1. Detected languages from Step 2
2. `Entrypoints:` line from the summary output
3. `Dependencies:` line from the summary output

If any are missing, report the gap. Do not fabricate output.

Return the detected language list plus the full Trailmark summary output.
If a version string was available, include it in the returned metadata.
