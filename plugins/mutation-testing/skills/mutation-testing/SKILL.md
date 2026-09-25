---
name: mutation-testing
description: "Configures mewt or muton campaigns, analyzes surviving mutants, and investigates bugs exposed by testing gaps. Use when setting up mutation testing, reviewing campaign results, identifying equivalent mutants, or finding bugs from surviving mutations."
allowed-tools: Read Write Bash Grep

---

# Mutation Testing (mewt/muton)

Routes to the right mutation testing workflow and loads the references that workflow needs.

> **Note**: muton and mewt share identical interfaces. Examples use `mewt`; substitute `muton` and its file names (`muton.toml`, `muton.sqlite`) for muton projects.

`mewt --help` and `mewt <subcommand> --help` are the source of truth for command-line behavior. Examples below reflect the mewt 4.x API; run `--help` when a flag looks unfamiliar or a command fails.

## When to Use

Use this skill when the user:
- Mentions "mewt", "muton", or "mutation testing"
- Wants to configure, scope, or speed up a mutation testing campaign
- Wants to analyze mutation results — surviving/uncaught mutants, equivalent mutants, kill rate
- Wants to use mutation results to find bugs in the source code

## When NOT to Use

Do not use this skill when the user asks about tests or line coverage without any mutation testing context.

---

## Routing

Pick the workflow, then load it together with the references listed for it. Workflows and references do not load each other — that decision belongs here.

**Setting up, scoping, or speeding up a campaign**
→ [workflows/configuration.md](workflows/configuration.md)
→ Also load [references/optimization-strategies.md](references/optimization-strategies.md) when the campaign estimate is long enough to need trimming, or the user asks to make it faster.

**Campaign finished, hunting for bugs in untested code**
→ [workflows/bug-hunter.md](workflows/bug-hunter.md)

**Turning results into a formal analysis report**
→ [workflows/analyzing-results.md](workflows/analyzing-results.md), plus:
- [references/equivalent-mutants.md](references/equivalent-mutants.md) — equivalence catalog and verification procedure
- [references/severity-classification.md](references/severity-classification.md) — severity tier criteria
- [references/report-template.md](references/report-template.md) — report structure
- [references/blockchain-patterns.md](references/blockchain-patterns.md) — **only** for Solidity, Move, FunC/Tolk, Cairo, or Solana Rust targets
- [references/input-formats.md](references/input-formats.md) — unless the results came from mewt or muton. Foreign tool output may not be self-describing; this covers the parsing anchors for slither-mutate, mull, and dextool-mutate

Load the workflow and the references that apply first. Then, for mewt/muton results, run `uv run {baseDir}/scripts/survivors.py --results <results.json> --status <status.txt>` (or with no flags inside the campaign directory). One call prints the campaign totals, every uncaught mutant with its 1-based line, original and mutated text and the tests that passed against it, the numbered source around each site, and the test files. That output replaces reading the results JSON, the status file, the mutated files and the tests; Read only a function that runs past a window or a test file marked "not shown".

**Anything else** → run `mewt --help` or `mewt <subcommand> --help`, then assist directly.

---

## Essential Commands

```bash
# Set up and run
mewt init                    # Create config and database
mewt mutate [paths]          # Generate mutants without testing them
mewt run [paths]             # Generate mutants and run the campaign

# Read results
mewt status                  # Overview with per-file breakdown
mewt results                 # Uncaught mutants (default view)
mewt results --all           # Every outcome, not just uncaught
mewt results --format json   # json | sarif | ids | table

# Narrow down (these filters work on both `results` and `print mutants`)
mewt results --target 'src/auth/**'   # Quote globs so the shell does not expand them
mewt results --severity high,medium
mewt results --mutation-types ER,CR
mewt results --status Uncaught        # Uncaught | TestFail | Skipped | Timeout
mewt results --line 42

# Investigate and re-test
uv run {baseDir}/scripts/survivors.py    # Every survivor + source around each site, one call
mewt print mutant --id [id]              # View the mutated code
mewt test --ids [ids]                    # Re-test specific mutants
mewt test --ids-file uncaught_ids.txt    # Re-test IDs from a file, or '-' for stdin

# Inspect configuration
mewt print config                        # Effective config
mewt print targets                       # Files actually mutated
mewt print mutations --language [lang]   # Mutations and severities for a language
```

Language labels are canonical `family` or `family/dialect` values in mewt 4.x — for example `rust`, `javascript/ts`, `move/sui`, `move/iota`.

---

## What Results Mean

- **Caught/TestFail**: tests detected the mutation (good)
- **Uncaught**: tests did not detect the change. Inspect the code to distinguish a testing gap from an equivalent mutation.
- **Timeout**: tests took too long — inconclusive, not evidence of coverage
- **Skipped**: a less severe mutant was skipped because a more severe mutant on the same line was uncaught

---

## Interpreting Mutation Types

`mewt print mutations --language [lang]` lists every mutation slug, description, and severity for a language, and is authoritative — the operator set grows with each release. What that output does not tell you is what a survivor *means*, which is where prioritization comes from:

| Severity | Representative slugs | What an uncaught mutant tells you |
|----------|---------------------|-----------------------------------|
| High | `ER` (Error Replacement) | Tests tolerate the injected error. Investigate whether the path executes, whether error handling masks the change, and whether assertions check the outcome. |
| Medium | `CR` (Comment Replacement) | Removing the statement does not fail the tests. Check whether its effects matter and whether assertions observe them. |
| Medium | `IF`/`IT` (If False/True), `NR` (Negation Removal) | Tests do not distinguish the changed condition. Both constant replacements surviving can indicate an unexecuted condition or weak assertions on the branch outcomes. |
| Low | Operator shuffles (`AOS`, `COS`, `LOS`, `BOS`, shift/assignment variants), `BL`, `AS`, `LC`, `WF` | Check boundary inputs, arithmetic assertions, and semantic equivalence. The mutation result alone does not establish whether the code executed. |

Severity ranks the *mutation*, not the risk. A low-severity survivor in a fee calculation matters more than a high-severity survivor in a log line — weigh what the mutated code does. Filter with `--severity` to work through the results in priority order.
