---
name: 5b-poc-validator
description: "Compiles and runs all PoCs for zeroize-audit findings. Produces poc_validation_results.json consumed by the verification agent and the orchestrator."
model: inherit
allowed-tools:
  - Read
  - Write
  - Bash
  - Grep
---

# 5b-poc-validator

Compile and run all PoCs listed in the manifest. This agent handles bulk compilation and execution, producing runtime results that are subsequently checked by the verification agent (5c-poc-verifier) for semantic correctness.

## Input

You receive these values from the orchestrator:

| Parameter | Description |
|---|---|
| `workdir` | Run working directory (e.g. `/tmp/zeroize-audit-{run_id}/`) |
| `config_path` | Path to `{workdir}/merged-config.yaml` |

## Process

### Step 0 — Load Configuration

Read `config_path` to access PoC-related settings.

### Step 1 — Read Manifest

Read `{workdir}/poc/poc_manifest.json`. Collect all PoC entries.

If no PoCs exist, write an empty results file and exit.

### Step 2 — Compile and Run Each PoC

Dispatch on `poc_entry.language`:

#### C/C++ PoCs (`language` is absent or `"c"`)

1. Compile:
   ```bash
   cd {workdir}/poc && make <makefile_target>
   ```

2. If compilation succeeds, run and record exit code:
   ```bash
   cd {workdir}/poc && ./<makefile_target>
   echo "Exit code: $?"
   ```

3. Record result: `{finding_id, category, language: "c", poc_file, compile_success, exit_code}`.

#### Rust PoCs (`language == "rust"`)

Rust PoCs use `cargo test`. The exit code convention maps directly: a passing `assert!` → test passes → cargo exits 0 → exploitable; a failing `assert!` (panic) → test fails → cargo exits non-zero → not exploitable.

1. Compile check (no run):
   ```bash
   <poc_entry.compile_cmd>
   # e.g. cargo test --manifest-path {workdir}/poc/Cargo.toml --no-run --test za_0001_missing_source_zeroize
   ```

2. If compilation succeeds, run the specific test and record exit code:
   ```bash
   <poc_entry.run_cmd>
   # e.g. cargo test --manifest-path {workdir}/poc/Cargo.toml --test za_0001_missing_source_zeroize -- --nocapture
   echo "Exit code: $?"
   ```

3. Capture stdout/stderr from the cargo test run and include in the result for the verifier.

4. Record result: `{finding_id, category, language: "rust", poc_file, compile_success, exit_code, stdout, stderr}`.

For Rust PoCs where `poc_supported: false`: skip compilation and execution; record `{compile_success: false, exit_code: null, validation_result: "no_poc"}` with the `reason` from the manifest.

### Step 3 — Write Results

Write `{workdir}/poc/poc_validation_results.json`:

```json
{
  "timestamp": "<ISO-8601>",
  "results": [
    {
      "finding_id": "ZA-0001",
      "category": "MISSING_SOURCE_ZEROIZE",
      "poc_file": "poc_za_0001_missing_source_zeroize.c",
      "compile_success": true,
      "exit_code": 0,
      "validation_result": "exploitable"
    }
  ]
}
```

Validation result mapping (applies to both C/C++ and Rust PoCs):

- `compile_success=true, exit_code=0` → `"exploitable"` (binary exited 0 or cargo test passed)
- `compile_success=true, exit_code=1` → `"not_exploitable"` (C binary exited 1)
- `compile_success=true, exit_code≠0 and ≠1 (Rust)` → `"not_exploitable"` (cargo test failed due to assert panic)
- `compile_success=false` → `"compile_failure"`
- `poc_supported=false` → `"no_poc"`

## Output

Write to `{workdir}/poc/`:

| File | Content |
|---|---|
| `poc_validation_results.json` | Results for all PoCs |

## Error Handling

- **Manifest missing**: Fatal — write error and exit.
- **Individual compile failure**: Record `compile_failure` in results, continue with next PoC.
- **Individual runtime failure**: Record exit code, continue with next PoC.
- **Always write `poc_validation_results.json`** — even if empty (`{"timestamp": "...", "results": []}`).
