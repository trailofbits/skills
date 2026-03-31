---
name: mutation-testing
description: "Configures mewt or muton mutation testing campaigns — scopes targets, tunes timeouts, and optimizes long-running runs. Use when the user mentions mewt, muton, mutation testing, or wants to configure or optimize a mutation testing campaign."
allowed-tools:
  - Read
  - Write
  - Bash
  - Grep
---

# Mutation Testing — Campaign Configuration (mewt/muton)

> **Note**: muton and mewt share identical interfaces but target different languages — mewt for general-purpose languages (Rust, Solidity, Go, TypeScript, JavaScript), muton for TON smart contracts (Tact, Tolk, FunC). All examples use `mewt` commands, but they work exactly the same with `muton`. File names change accordingly: `mewt.toml` → `muton.toml`, `mewt.sqlite` → `muton.sqlite`.

## When to Use

Use this skill when the user:
- Mentions "mewt", "muton", or "mutation testing"
- Needs to configure or optimize a mutation testing campaign
- Wants to run `mewt run` and needs help getting set up first

## When NOT to Use

Do not use this skill when the user:
- Wants to analyze or report on completed campaign results
- Asks about tests or coverage without mentioning mutation testing

---

## Quick Start

Load [workflows/configuration.md](workflows/configuration.md) — a 5-phase guide from `mewt init` to a validated, ready-to-run campaign.

**General question or unfamiliar command?**
Run `mewt --help` or `mewt <subcommand> --help`, then assist.

---

## Reference Index

| File | Content |
|------|---------|
| [workflows/configuration.md](workflows/configuration.md) | 5-phase guide: init, scope, optimize, validate, run |
| [references/optimization-strategies.md](references/optimization-strategies.md) | Per-file targeting, two-phase campaigns, mutation type filtering |

---

## Essential Commands

```bash
# Initialize and mutate
mewt init                    # Create mewt.toml and mewt.sqlite
mewt mutate [paths]          # Generate mutants without running tests
mewt run [paths]             # Run the full campaign

# Inspect configuration and scope
mewt print config            # View effective configuration
mewt print targets           # Table of all targeted files
mewt print mutations --language [lang]  # Available mutation types
mewt status                  # Mutant count and per-file breakdown

# Investigate specific mutants
mewt print mutants --target [path]   # All mutants for a file
mewt print mutants --severity high   # Filter by severity
mewt print mutant --id [id]          # View mutated code diff
mewt test --ids [ids]                # Re-test specific mutants
```

---

## What Results Mean

- **Caught/TestFail**: Tests detected the mutation (good)
- **Uncaught**: Mutation survived — indicates untested logic
- **Timeout**: Tests took too long, inconclusive
- **Skipped**: A more severe mutant already failed on the same line
