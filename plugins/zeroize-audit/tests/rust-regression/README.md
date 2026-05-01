## Rust Regression Fixtures

This directory contains lightweight fixtures and a smoke runner to validate
Rust-specific detector behavior for:

- `check_mir_patterns.py`
- `check_llvm_patterns.py`
- `check_rust_asm.py`
- `semantic_audit.py`

### Run

```bash
bash plugins/zeroize-audit/tests/rust-regression/run_smoke.sh
bash plugins/zeroize-audit/tests/rust-regression/run_mixed_language_smoke.sh
```

### What is validated

- MIR: closure/async capture and error-path coverage heuristics
- LLVM IR: per-symbol volatile-store drops, optional multi-level handling, return/register exposure
- ASM: caller-saved and callee-saved spill detection with x86-64 guardrails
- Semantic audit: Drop body field-zeroing evidence, alias/resolved-path conversion escapes, confidence/evidence tags
- Mixed-language orchestration sanity checks (Wave 2a/2b, Wave 3/3R, Rust report ingestion mappings)
