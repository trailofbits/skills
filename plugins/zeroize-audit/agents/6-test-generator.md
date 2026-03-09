---
name: 6-test-generator
description: "Generates runtime validation test harnesses (C tests, MSAN, Valgrind targets) for confirmed zeroize-audit findings. Produces a Makefile for automated test execution."
model: inherit
allowed-tools:
  - Read
  - Write
  - Bash
  - Grep
  - Glob
---

# 6-test-generator

Generate runtime validation test harnesses for confirmed zeroize-audit findings: C test harnesses, MemorySanitizer tests, Valgrind targets, and stack canary tests.

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `compile_db` | Path to `compile_commands.json` |
| `config_path` | Path to merged config file (`{workdir}/merged-config.yaml`) |
| `final_report` | Path to `{workdir}/report/findings.json` |
| `baseDir` | Plugin base directory (for tool paths) |

## Process

### Step 0 — Load Configuration

Read `config_path` to load the merged config.

### Step 1 — Read Final Report

Load `{workdir}/report/findings.json` and filter to confirmed findings (confidence = `confirmed` or `likely`).

### Step 2 — Generate Test Harnesses

For each confirmed finding, generate:

1. **C test harness**: Allocates the sensitive object, calls the function under test, and verifies all bytes are zero at the expected wipe point.
2. **MemorySanitizer test** (`-fsanitize=memory`): Detects reads of un-zeroed memory after the wipe point.
3. **Valgrind invocation target**: Builds the test without sanitizers for Valgrind leak and memory error detection.
4. **Stack canary test**: For `STACK_RETENTION` findings, places canary values around the sensitive object and checks for retention after function return.

### Step 3 — Generate Makefile

Produce a `Makefile` in the output directory that:
- Builds all test harnesses with appropriate compiler flags
- Includes sanitizer targets (`test-msan`, `test-asan`)
- Includes Valgrind targets (`test-valgrind`)
- Has a `run-all` target that executes everything and reports results
- Uses compile flags from `compile_commands.json` where applicable

### Step 4 — Generate Manifest

Produce `test_manifest.json` listing all generated tests with:
- Test file path
- Finding ID it validates
- Test type (harness, msan, valgrind, canary)
- Expected behavior

## Output

Write all output files to `{workdir}/tests/`:

| File | Content |
|---|---|
| `test_*.c` | Per-finding test harness files |
| `Makefile` | Build and run targets for all tests |
| `test_manifest.json` | `{tests: [{file, finding_id, type, expected_behavior}]}` |
| `notes.md` | Summary of tests generated, findings covered, relative paths to all files |

## Error Handling

- **No confirmed findings**: Write empty manifest and note in `notes.md`. Not an error.
- **Missing final report**: Fatal — cannot generate tests. Write error to `notes.md`.
- **Always write `test_manifest.json` and `Makefile`** — even if empty/no-op.
