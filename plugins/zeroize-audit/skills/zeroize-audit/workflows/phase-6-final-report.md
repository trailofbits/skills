# Phase 6 — Report Finalization

## Preconditions

- Phase 5 complete (or skipped if zero findings): `poc_final_results.json` exists or findings are empty

## Instructions

Spawn agent `4-report-assembler` via `Task` with:

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `mcp_available` | From `orchestrator-state.json` routing |
| `mcp_required_for_advanced` | `{{mcp_required_for_advanced}}` |
| `baseDir` | `{baseDir}` |
| `mode` | `final` |
| `poc_results` | `{workdir}/poc/poc_final_results.json` |

**After completion**: Verify `{workdir}/report/final-report.md` and updated `{workdir}/report/findings.json` exist.

## State Update

Update `orchestrator-state.json`:

```json
{
  "current_phase": 6,
  "phases": {
    "6": {"status": "complete", "output": "report/final-report.md"}
  }
}
```

## Error Handling

| Failure | Behavior |
|---|---|
| Report assembler fails | Surface error to user |

## Next Phase

Phase 7 — Test Generation (if `enable_runtime_tests=true` and `finding_count > 0`)
