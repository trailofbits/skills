# Phase 4 — PoC Generation

## Preconditions

- Phase 3 complete: `{workdir}/report/findings.json` exists with at least one finding

## Instructions

Spawn agent `5-poc-generator` via `Task` with:

| Parameter | Value |
|---|---|
| `workdir` | `{workdir}` |
| `compile_db` | `{{compile_db}}` |
| `config_path` | `{workdir}/merged-config.yaml` |
| `final_report` | `{workdir}/report/findings.json` |
| `poc_categories` | `{{poc_categories}}` |
| `poc_output_dir` | `{{poc_output_dir}}` or `{workdir}/poc/` |
| `baseDir` | `{baseDir}` |

The agent reads each finding and the corresponding source code, then crafts a bespoke PoC program tailored to the specific vulnerability. Each PoC is individually written — not generated from templates.

**After completion**: Verify `{workdir}/poc/poc_manifest.json` exists and contains an entry for each finding.

## State Update

Update `orchestrator-state.json`:

```json
{
  "current_phase": 4,
  "phases": {
    "4": {"status": "complete", "output": "poc/poc_manifest.json"}
  }
}
```

## Error Handling

| Failure | Behavior |
|---|---|
| PoC generator fails | Pipeline stalls — surface error to user |

## Next Phase

Phase 5 — PoC Validation & Verification
