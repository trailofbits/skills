# Phase 3 — Interim Finding Collection

## Preconditions

- Phase 2 complete (or skipped if no compiler analysis needed)

## Instructions

Spawn agent `4-report-assembler` via `Task` with:

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `mcp_available` | From `orchestrator-state.json` routing |
| `mcp_required_for_advanced` | `{{mcp_required_for_advanced}}` |
| `baseDir` | `{baseDir}` |
| `mode` | `interim` |

**After completion**: Verify `{workdir}/report/findings.json` exists. Count findings. If the findings array is empty, skip to Phase 6 for an empty report.

## State Update

Update `orchestrator-state.json`:

```json
{
  "current_phase": 3,
  "routing": {
    "finding_count": "<count from findings.json>"
  },
  "phases": {
    "3": {"status": "complete", "output": "report/findings.json"}
  }
}
```

## Error Handling

| Failure | Behavior |
|---|---|
| Report assembler fails | Surface error to user |

## Next Phase

Phase 4 — PoC Generation (if `finding_count > 0`)
