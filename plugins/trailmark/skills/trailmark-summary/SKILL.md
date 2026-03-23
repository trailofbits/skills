---
name: trailmark-summary
description: "Runs a trailmark summary analysis on a codebase. Returns language detection, entry point count, and dependency graph shape. Use when vivisect or galvanize needs a quick structural overview. Triggers: trailmark summary, code summary, structural overview."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# Trailmark Summary

Runs `trailmark analyze --summary` on a target directory.

## When to Use

- Vivisect Phase 0 needs a quick structural overview before decomposition
- Galvanize Phase 1 needs language detection and entry point count
- Quick orientation on an unfamiliar codebase before deeper analysis

## When NOT to Use

- Full structural analysis with all passes needed (use `trailmark-structural`)
- Detailed code graph queries (use the main `trailmark` skill directly)
- You need hotspot scores or taint data (use `trailmark-structural`)

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

**Step 2: Detect the primary language.**

```bash
find {args} -type f \( -name '*.rs' -o -name '*.py' \
  -o -name '*.go' -o -name '*.js' -o -name '*.ts' \
  -o -name '*.sol' -o -name '*.c' -o -name '*.cpp' \
  -o -name '*.rb' -o -name '*.php' -o -name '*.cs' \
  -o -name '*.java' -o -name '*.hs' -o -name '*.erl' \
  -o -name '*.cairo' -o -name '*.circom' \) 2>/dev/null | \
  sed 's/.*\.//' | sort | uniq -c | sort -rn | head -5
```

Map the most common extension to a language flag:
- `.rs` -> `--language rust`
- `.py` -> (no flag, Python is default)
- `.go` -> `--language go`
- `.js`/`.ts` -> `--language javascript`
- `.sol` -> `--language solidity`
- `.c` -> `--language c`
- `.cpp` -> `--language cpp`
- `.rb` -> `--language ruby`
- `.php` -> `--language php`
- `.cs` -> `--language c_sharp`
- `.java` -> `--language java`
- `.hs` -> `--language haskell`
- `.erl` -> `--language erlang`
- `.cairo` -> `--language cairo`
- `.circom` -> `--language circom`

**Step 3: Run the summary.**

```bash
trailmark analyze --summary {language_flag} {args} 2>&1 || \
  uv run trailmark analyze --summary {language_flag} {args} 2>&1
```

**Step 4: Verify the output.**

The output must include ALL THREE of:
1. Language detection (at least one language name)
2. Entry point count (or "no entry points found")
3. Dependency graph shape (module count or "single module")

If any are missing, report the gap. Do not fabricate output.

Return the full trailmark output.
