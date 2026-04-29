---
name: trailmark-summary
description: "Runs a Trailmark summary analysis on a codebase. Returns auto-detected languages, entry point count, and dependency list. Use when vivisect or galvanize needs a quick structural overview. Triggers: trailmark summary, code summary, structural overview."
allowed-tools: Bash Read Grep Glob
---

# Trailmark Summary

Runs `trailmark analyze --language auto --summary` on a target directory.

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

**Step 2: Detect languages with Trailmark's parse API.**

```bash
python3 - "{args}" <<'PY'
import json
import sys

from trailmark.parse import detect_languages

print(json.dumps(detect_languages(sys.argv[1])))
PY
```

If the import fails, rerun the same snippet with `uv run python - "{args}"`.
If the result is `[]`, report "Trailmark found no supported languages under
target" and return.

**Step 3: Run the summary with auto-detection.**

```bash
trailmark analyze --language auto --summary {args} 2>&1 || \
  uv run trailmark analyze --language auto --summary {args} 2>&1
```

**Step 4: Verify the output.**

The output must include ALL THREE of:
1. Detected languages from Step 2
2. `Entrypoints:` line from the summary output
3. `Dependencies:` line from the summary output

If any are missing, report the gap. Do not fabricate output.

Return the detected language list plus the full Trailmark summary output.
