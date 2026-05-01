# Phase 5 — PoC Validation & Verification

## Preconditions

- Phase 4 complete: `{workdir}/poc/poc_manifest.json` exists

## Instructions

### Step 5a — Compile and Run All PoCs (agent)

Spawn agent `5b-poc-validator` via `Task` with:

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `config_path` | `{workdir}/merged-config.yaml` |

**After completion**: Read `{workdir}/poc/poc_validation_results.json`.

If the agent fails, fall back to compiling and running PoCs inline:

```bash
cd {workdir}/poc && make <makefile_target>
./<makefile_target>
echo "Exit code: $?"
```

### Step 5b — Verify PoCs Prove Their Claims (agent)

Spawn agent `5c-poc-verifier` via `Task` with:

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `validation_results` | `{workdir}/poc/poc_validation_results.json` |

The verifier reads each PoC source file, the corresponding finding, and the original source code to check that the PoC actually tests the claimed vulnerability. It verifies:
- Target variable and function match the finding
- Verification technique is appropriate for the finding category
- Optimization level is correct
- Exit code interpretation is not inverted
- Results are plausible given the finding evidence

**After completion**: Read `{workdir}/poc/poc_verification.json`.

### Step 5c — Present Verification Failures to User

Read `{workdir}/poc/poc_verification.json`. For any PoC with `verified: false`:

1. Use `Read` to show the PoC source file.
2. Present to the user via `AskUserQuestion` with:
   - Finding ID and category
   - PoC file path
   - Which verification checks failed and why
   - The verifier's notes
   - The PoC's runtime result (from `poc_validation_results.json`)

3. Ask the user whether to:
   - **Accept anyway**: Trust the PoC result despite verification failure
   - **Reject**: Discard the PoC result (treat as `no_poc` for this finding)

**Block until the user responds for each failed PoC.**

### Step 5d — Merge Results

Combine validation results (from `poc_validation_results.json`), verification results (from `poc_verification.json`), and user decisions (from Step 5c).

Write `{workdir}/poc/poc_final_results.json`:

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
      "validation_result": "exploitable",
      "verification": {
        "verified": true,
        "checks": { "...": "pass" },
        "notes": "PoC correctly targets session_key in handle_key()"
      }
    },
    {
      "finding_id": "ZA-0003",
      "category": "OPTIMIZED_AWAY_ZEROIZE",
      "poc_file": "poc_za_0003_optimized_away_zeroize.c",
      "compile_success": true,
      "exit_code": 1,
      "validation_result": "rejected",
      "verification": {
        "verified": false,
        "checks": { "optimization_level": "fail" },
        "notes": "Compiled at -O0 but wipe disappears at -O2. User rejected PoC result."
      }
    }
  ]
}
```

Validation result mapping:

- `compile_success=true, exit_code=0, verified=true` → `"exploitable"`
- `compile_success=true, exit_code=1, verified=true` → `"not_exploitable"`
- `compile_success=true, verified=false, user accepted` → original result (`"exploitable"` or `"not_exploitable"`)
- `compile_success=true, verified=false, user rejected` → `"rejected"`
- `compile_success=false` → `"compile_failure"`

## State Update

Update `orchestrator-state.json`:

```json
{
  "current_phase": 5,
  "phases": {
    "5": {"status": "complete", "output": "poc/poc_final_results.json"}
  }
}
```

## Error Handling

| Failure | Behavior |
|---|---|
| Validator agent fails | Fall back to inline compilation for all PoCs |
| Verifier agent fails | Skip verification, use validation results only (warn in report) |
| Individual PoC compile failure | Record in results, continue with others |

## Next Phase

Phase 6 — Final Report
