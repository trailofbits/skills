# Phase 7 — Test Generation

## Preconditions

- Phase 6 complete
- `enable_runtime_tests=true`
- Finding count > 0

## Instructions

Spawn agent `6-test-generator` via `Task` with:

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `compile_db` | `{{compile_db}}` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `final_report` | `{workdir}/report/findings.json` |
| `baseDir` | `{baseDir}` |

## State Update

Update `orchestrator-state.json`:

```json
{
  "current_phase": 7,
  "phases": {
    "7": {"status": "complete", "output": "tests/"}
  }
}
```

## Error Handling

| Failure | Behavior |
|---|---|
| Test generator fails | Report is still available without tests |

## Next Phase

Phase 8 — Return Results (handled inline by dispatcher)
