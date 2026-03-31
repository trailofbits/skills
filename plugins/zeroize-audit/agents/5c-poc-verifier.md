---
name: 5c-poc-verifier
description: "Verifies that each zeroize-audit PoC actually proves the vulnerability it claims to demonstrate. Reads PoC source code, finding details, and original source to check alignment between the PoC and the finding. Produces poc_verification.json consumed by the orchestrator."
model: inherit
allowed-tools:
  - Read
  - Write
  - Grep
  - Glob
---

# 5c-poc-verifier

Verify that each PoC actually proves the vulnerability it claims to demonstrate. This agent performs semantic verification — not just "does it compile and run?" but "does it test the right thing?" A PoC that compiles, runs, and exits 0 is worthless if it's testing the wrong variable, using the wrong technique, or compiled at the wrong optimization level.

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `config_path` | Path to `{workdir}/merged-config.yaml` |
| `validation_results` | Path to `{workdir}/poc/poc_validation_results.json` (compilation/run results) |

## Process

### Step 0 — Load Context

1. Read `config_path` for PoC-related settings.
2. Read `{workdir}/poc/poc_manifest.json` for the list of PoCs and their claimed targets.
3. Read `{workdir}/report/findings.json` for the full finding details.
4. Read `validation_results` for compilation and exit code results.

### Step 1 — Verify Each PoC

For each PoC in the manifest:

#### 1a — Read the PoC Source

Use `Read` to load the PoC source file (`{workdir}/poc/<poc_file>`). Parse it to understand:
- What function does the PoC call?
- What variable does the PoC check after the call?
- What verification technique does it use (volatile read, stack probe, heap residue)?
- What optimization level is it compiled at (from the Makefile or manifest)?

#### 1b — Read the Finding

Look up the finding by `finding_id` in `findings.json`. Extract:
- `category`: the type of vulnerability claimed
- `location.file` and `location.line`: where the vulnerability is
- `object.name`, `object.type`, `object.size_bytes`: the sensitive variable
- `evidence`: what evidence supports the finding
- `compiler_evidence`: IR/ASM evidence (if applicable)

#### 1c — Read the Original Source

Use `Read` to examine the original source code at the finding's location. Read enough context to understand the function's behavior around the sensitive variable.

#### 1d — Run Verification Checks

Apply all of the following checks. Each check produces a `pass`/`fail`/`warn` result:

**Check 1 — Target Variable Match**
Does the PoC operate on the same variable identified in the finding? The PoC should reference `finding.object.name` (or a pointer to it). If the PoC checks a different variable than the one in the finding, this is a verification failure.
- `pass`: PoC clearly operates on the finding's target variable
- `fail`: PoC operates on a different variable
- `warn`: Variable name differs but could be an alias or pointer to the same memory

**Check 2 — Target Function Match**
Does the PoC call the function identified in the finding (`finding.location.file` at or near `finding.location.line`)? The PoC should exercise the specific function where the vulnerability was found.
- `pass`: PoC calls the function from the finding
- `fail`: PoC calls a different function
- `warn`: PoC calls a wrapper that eventually calls the target function

**Check 3 — Technique Appropriateness**
Does the PoC use an appropriate technique for the finding category?

For C/C++ PoCs, check for `volatile` reads, `stack_probe()`, and `heap_residue_check()` calls.
For Rust PoCs, check for `std::ptr::read_volatile` or `core::ptr::read_volatile` (not C `volatile` keyword), used inside an `unsafe { }` block within a `#[test]` function.

| Category | Expected Technique (C/C++) | Expected Technique (Rust) |
|---|---|---|
| `MISSING_SOURCE_ZEROIZE` | Volatile read of target buffer after return | `ptr::read_volatile` after `drop()` |
| `OPTIMIZED_AWAY_ZEROIZE` | Volatile read at the opt level where wipe disappears | N/A (Rust excluded) |
| `STACK_RETENTION` | Stack probe after function return | N/A (Rust excluded) |
| `REGISTER_SPILL` | Stack probe targeting spill offset | N/A (Rust excluded) |
| `SECRET_COPY` | Volatile read of copy destination (not original) | `ptr::read_volatile` of copy; original dropped first |
| `MISSING_ON_ERROR_PATH` | Error-path triggering + volatile read | N/A (Rust excluded) |
| `PARTIAL_WIPE` | Volatile read of *tail* beyond wipe region | `ptr::read_volatile` of tail bytes only (`wiped_size..full_size`) |
| `NOT_ON_ALL_PATHS` | Path-forcing input + volatile read | N/A (Rust excluded) |
| `INSECURE_HEAP_ALLOC` | Heap residue check (malloc/free/re-malloc cycle) | N/A (Rust excluded) |
| `LOOP_UNROLLED_INCOMPLETE` | Volatile read of tail beyond unrolled region at `-O2` | N/A (Rust excluded) |
| `NOT_DOMINATING_EXITS` | Non-dominated exit path + volatile read | N/A (Rust excluded) |

- `pass`: Technique matches the category (using language-appropriate primitive)
- `fail`: Technique is wrong (e.g., C `volatile` in a Rust PoC, or heap residue check for MISSING_SOURCE_ZEROIZE)
- `warn`: Technique is related but not the standard approach

**Check 4 — Optimization Level**
Is the PoC compiled at the correct optimization level for the finding category?

For Rust PoCs, optimization level maps to cargo profile:
- `"debug"` build (default, no `--release`) corresponds to `-O0`
- `"release"` build (`--release`) corresponds to `-O2`

| Category | Required Opt Level (C/C++) | Required Opt Level (Rust) |
|---|---|---|
| `MISSING_SOURCE_ZEROIZE` | `-O0` | debug (no `--release`) |
| `OPTIMIZED_AWAY_ZEROIZE` | Level from `compiler_evidence.diff_summary` | N/A (Rust excluded) |
| `STACK_RETENTION` | `-O2` | N/A (Rust excluded) |
| `REGISTER_SPILL` | `-O2` | N/A (Rust excluded) |
| `SECRET_COPY` | `-O0` | debug (no `--release`) |
| `MISSING_ON_ERROR_PATH` | `-O0` | N/A (Rust excluded) |
| `PARTIAL_WIPE` | `-O0` | debug (no `--release`) |
| `NOT_ON_ALL_PATHS` | `-O0` | N/A (Rust excluded) |
| `INSECURE_HEAP_ALLOC` | `-O0` | N/A (Rust excluded) |
| `LOOP_UNROLLED_INCOMPLETE` | `-O2` | N/A (Rust excluded) |
| `NOT_DOMINATING_EXITS` | `-O0` | N/A (Rust excluded) |

- `pass`: Correct optimization level (or Rust cargo profile)
- `fail`: Wrong optimization level (could cause false positive/negative)

**Check 5 — Exit Code Interpretation** (updated for Rust)
Does the PoC correctly map outcomes to exit codes?

- C/C++ PoCs: Exit 0 = exploitable (secret persists), Exit 1 = not exploitable (secret wiped)
- Rust PoCs: `assert!` holds → test passes → cargo exits 0 → exploitable; `assert!` panics → test fails → cargo exits non-zero → not exploitable

Check that the PoC doesn't invert this logic. For Rust PoCs specifically: verify the `assert!` condition is `secret_persists` (not `!secret_persists`), and the failure message says "wiped — not exploitable" (not vice versa).

- `pass`: Exit code mapping is correct
- `fail`: Exit code mapping is inverted or wrong

**Check 6 — Result Plausibility**
Cross-reference the PoC's runtime result (from `validation_results`) against the finding:
- If the PoC says "exploitable" (exit 0) but the finding shows an approved wipe call was detected at the same location → suspicious, flag for review
- If the PoC says "not exploitable" (exit 1) but the finding has strong compiler evidence (IR diff showing wipe removed) → suspicious, the PoC may be testing the wrong thing
- If the PoC had a compile failure, check whether the failure is due to PoC code issues (missing includes, wrong types) vs. target code issues

- `pass`: Result is plausible given the finding evidence
- `warn`: Result seems surprising given the evidence — may still be correct
- `fail`: Result contradicts strong evidence — PoC likely tests the wrong thing

### Step 2 — Write Verification Results

Write `{workdir}/poc/poc_verification.json`:

```json
{
  "timestamp": "<ISO-8601>",
  "results": [
    {
      "finding_id": "ZA-0001",
      "poc_file": "poc_za_0001_missing_source_zeroize.c",
      "verified": true,
      "checks": {
        "target_variable_match": "pass",
        "target_function_match": "pass",
        "technique_appropriate": "pass",
        "optimization_level": "pass",
        "exit_code_interpretation": "pass",
        "result_plausibility": "pass"
      },
      "notes": "PoC correctly targets session_key in handle_key(), uses volatile read at -O0."
    },
    {
      "finding_id": "ZA-0003",
      "poc_file": "poc_za_0003_optimized_away_zeroize.c",
      "verified": false,
      "checks": {
        "target_variable_match": "pass",
        "target_function_match": "pass",
        "technique_appropriate": "pass",
        "optimization_level": "fail",
        "exit_code_interpretation": "pass",
        "result_plausibility": "fail"
      },
      "notes": "PoC compiled at -O0 but the finding's compiler_evidence.diff_summary shows the wipe disappears at -O2. PoC result (not exploitable) is expected at -O0 where the wipe is still present."
    }
  ],
  "summary": {
    "total": 5,
    "verified": 3,
    "failed": 1,
    "warnings": 1
  }
}
```

A PoC is `verified: true` only if all checks are `pass` or `warn`. Any `fail` check sets `verified: false`.

## Verification Principles

1. **Err on the side of flagging**: A false alarm from verification is far less costly than a false PoC result influencing the final report. If in doubt, flag for review.
2. **Read the source, don't guess**: Always read both the PoC and the original source code. Don't rely on the manifest description alone.
3. **Check the full chain**: A PoC might call the right function but check the wrong variable. Verify the entire chain from setup through function call to verification read.
4. **Optimization level matters enormously**: A PoC for `OPTIMIZED_AWAY_ZEROIZE` compiled at `-O0` will almost always show "not exploitable" — the wipe hasn't been optimized away yet. This is the most common verification failure.
5. **Plausibility is a heuristic, not proof**: The plausibility check can flag suspicious results but cannot definitively prove a PoC is wrong. When flagging, explain WHY the result seems implausible.

## Output

Write to `{workdir}/poc/`:

| File | Content |
|---|---|
| `poc_verification.json` | Per-PoC verification results with check details |

## Error Handling

- **PoC file missing**: Record as `verified: false` with note "PoC file not found".
- **Finding not found**: Record as `verified: false` with note "Finding ID not in findings.json".
- **Source file unreadable**: Record all checks as `warn` with note "Could not read original source for verification".
- **Always write `poc_verification.json`** — even if empty.
