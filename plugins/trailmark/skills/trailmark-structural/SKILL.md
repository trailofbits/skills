---
name: trailmark-structural
description: "Runs full trailmark structural analysis with all pre-analysis passes (blast radius, taint propagation, privilege boundaries, complexity hotspots). Use when vivisect needs detailed structural data for a target. Triggers: structural analysis, blast radius, taint analysis, complexity hotspots."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# Trailmark Structural Analysis

Runs `trailmark analyze` with all four pre-analysis passes.

## When to Use

- Vivisect Phase 1 needs full structural data (hotspots, taint, blast radius, privilege boundaries)
- Detailed pre-analysis passes for a specific target scope
- Generating complexity and taint data for audit prioritization

## When NOT to Use

- Quick overview only (use `trailmark-summary` instead)
- Ad-hoc code graph queries (use the main `trailmark` skill directly)
- Target is a single small file where structural analysis adds no value

## Rationalizations to Reject

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "Summary analysis is enough" | Summary skips taint, blast radius, and privilege boundary data | Run full structural analysis when detailed data is needed |
| "One pass is sufficient" | Passes cross-reference each other — taint without blast radius misses critical nodes | Run all four passes |
| "Tool isn't installed, I'll analyze manually" | Manual analysis misses what tooling catches | Report "trailmark is not installed" and return |
| "Empty pass output means the pass failed" | Some passes produce no data for some codebases (e.g., no privilege boundaries) | Return full output regardless |

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
  -o -name '*.go' -o -name '*.js' -o -name '*.jsx' \
  -o -name '*.ts' -o -name '*.tsx' -o -name '*.sol' \
  -o -name '*.c' -o -name '*.h' -o -name '*.cpp' \
  -o -name '*.hpp' -o -name '*.hh' -o -name '*.cc' \
  -o -name '*.cxx' -o -name '*.hxx' \
  -o -name '*.rb' -o -name '*.php' -o -name '*.cs' \
  -o -name '*.java' -o -name '*.hs' -o -name '*.erl' \
  -o -name '*.cairo' -o -name '*.circom' \) 2>/dev/null | \
  sed 's/.*\.//' | sort | uniq -c | sort -rn | head -5
```

Map the most common extension to a language flag:
- `.rs` -> `--language rust`
- `.py` -> (no flag, Python is default)
- `.go` -> `--language go`
- `.js`/`.jsx` -> `--language javascript`
- `.ts`/`.tsx` -> `--language typescript`
- `.sol` -> `--language solidity`
- `.c`/`.h` -> `--language c`
- `.cpp`/`.hpp`/`.hh`/`.cc`/`.cxx`/`.hxx` -> `--language cpp`
- `.rb` -> `--language ruby`
- `.php` -> `--language php`
- `.cs` -> `--language c_sharp`
- `.java` -> `--language java`
- `.hs` -> `--language haskell`
- `.erl` -> `--language erlang`
- `.cairo` -> `--language cairo`
- `.circom` -> `--language circom`

**Step 3: Run the full structural analysis.**

```bash
trailmark analyze \
  --passes blast_radius,taint,privilege_boundary,complexity \
  {language_flag} {args} 2>&1 || \
uv run trailmark analyze \
  --passes blast_radius,taint,privilege_boundary,complexity \
  {language_flag} {args} 2>&1
```

**Step 4: Verify the output.**

The output should include:
- Hotspot scores (complexity data)
- Tainted node list (taint propagation data)
- Blast radius data
- Privilege boundary information

Some passes may produce no data for some codebases (this is
normal). Return the full output regardless.
