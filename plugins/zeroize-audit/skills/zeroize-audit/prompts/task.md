Task: Run zeroize-audit.

Inputs:
- path: {{path}}
- compile_db: {{compile_db}}
- cargo_manifest: {{cargo_manifest}}
- config: {{config}}
- opt_levels: {{opt_levels}}
- languages: {{languages}}
- max_tus: {{max_tus}}
- mcp_mode: {{mcp_mode}}
- mcp_required_for_advanced: {{mcp_required_for_advanced}}
- mcp_timeout_ms: {{mcp_timeout_ms}}
- enable_semantic_ir: {{enable_semantic_ir}}
- enable_cfg: {{enable_cfg}}
- enable_runtime_tests: {{enable_runtime_tests}}
- enable_asm: {{enable_asm}}
- poc_categories: {{poc_categories}}
- poc_output_dir: {{poc_output_dir}}

---

## Execution Protocol

### Recovery

If a `workdir` is known from prior context, read `{workdir}/orchestrator-state.json` to recover state after context compression:

- `current_phase`: resume from this phase
- `workdir`, `run_id`: working directory and run identifier
- `inputs`: original input values
- `routing`: key booleans (`mcp_available`, `tu_count`, `finding_count`)
- `phases`: completion status and output file paths for each phase
- `key_file_paths`: paths to all inter-phase artifacts

If no state exists, start at Phase 0.

### Phase Loop

Execute phases sequentially. Before each phase, read its workflow file from `{baseDir}/workflows/phase-{N}-{name}.md`. Follow the workflow's Preconditions, Instructions, State Update, and Error Handling sections.

| Phase | Workflow File | Skip Condition |
|---|---|---|
| 0 | `phase-0-preflight.md` | Never |
| 1 | `phase-1-source-analysis.md` | Never |
| 2 | `phase-2-compiler-analysis.md` | No sensitive objects (`tu-map.json` empty) |
| 3 | `phase-3-interim-report.md` | No sensitive objects |
| 4 | `phase-4-poc-generation.md` | Zero findings in interim report |
| 5 | `phase-5-poc-validation.md` | Zero findings or no PoCs generated |
| 6 | `phase-6-final-report.md` | Never (always produce a report) |
| 7 | `phase-7-test-generation.md` | `enable_runtime_tests=false` or zero findings |

### Early Termination

Skip directly to Phase 6 (produce empty/partial report) when:

- Phase 1 source analyzer finds zero sensitive objects
- Phase 3 interim report contains zero findings

### Phase 8 — Return Results (inline)

Read `{workdir}/report/final-report.md` and return its contents as the skill output.

The markdown report is the primary human-readable output. It contains:
- Executive summary with finding counts by severity, confidence, and category
- PoC validation summary with exploitable/not-exploitable counts
- Sensitive objects inventory
- Detailed findings grouped by severity and confidence, each with evidence, PoC validation result, and recommended fix
- Superseded findings and confidence gate summary
- Analysis coverage and evidence file appendix

The structured `{workdir}/report/findings.json` (matching `{baseDir}/schemas/output.json`) is also available for machine consumption.

---

## Error Handling Summary

| Failure | Behavior |
|---|---|
| Preflight fails (Phase 0) | Stop immediately, report failure |
| Config load fails (Phase 0) | Stop immediately |
| PoC generator agent fails (Phase 4) | Surface error to user — PoC generation is mandatory |
| MCP resolver fails + `mcp_mode=require` | Stop immediately (C/C++ only) |
| MCP resolver fails + `mcp_mode=prefer` | Continue with `mcp_available=false` (C/C++ only) |
| Source analyzer (C/C++) fails | Stop C/C++ analysis — no sensitive object list for C/C++ TUs |
| Rust source analyzer fails | Stop Rust analysis — log failure, continue if C/C++ analysis is also running |
| No sensitive objects found | Skip Phases 2–5, jump to Phase 6 for empty report |
| One TU compiler-analyzer fails | Continue with remaining TUs |
| All TU compiler-analyzers fail | Report assembler produces source-only report |
| Rust compiler analyzer (Wave 3R) fails | Log failure, continue — report assembler handles missing rust-compiler-analysis/ |
| `cargo +nightly` not available (Rust preflight) | Stop the run — nightly is required for MIR/IR emission |
| Python script missing (Rust preflight) | Warn and skip that sub-step — do not fail the run |
| Report assembler fails (interim) | Surface error to user |
| PoC generator fails | Pipeline stalls — cannot proceed to validation. Surface error to user |
| PoC compilation failure | Record in validation results, continue with other PoCs |
| Report assembler fails (final) | Surface error to user |
| Test generator fails | Report is still available without tests |
