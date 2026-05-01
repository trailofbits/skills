# Detection Strategy

Read this during execution to guide per-step analysis. Steps 1–6 are Phase 1 (source-level); Steps 7–12 are Phase 2 (compiler-level).

---

## Phase 1 — Source-Level Analysis

### Step 1 — Preflight Build Context (mandatory)
- Verify `compile_db` exists and is readable.
- Verify compile database entries point to existing files/working directories.
- Verify the codebase is compilable with the captured commands (or equivalent build invocation).
- Fail fast if preflight fails; do not continue with partial/source-only analysis.

### Step 2 — Identify Sensitive Objects

Scan all TUs for objects matching these heuristics. Each heuristic has a confidence level that propagates to findings.

**Name patterns (low confidence)** — match substrings case-insensitively:
`key`, `secret`, `seed`, `priv`, `sk`, `shared_secret`, `nonce`, `token`, `pwd`, `pass`

**Type hints (medium confidence)** — byte buffers, fixed-size arrays, or structs whose names or fields match name patterns above.

**Explicit annotations (high confidence)**:
- Rust: `#[secret]`, `Secret<T>` patterns (configurable)
- C/C++: `__attribute__((annotate("sensitive")))`, `SENSITIVE` macro (configurable via `explicit_sensitive_markers` in `{baseDir}/configs/default.yaml`)

Record each sensitive object with: name, type, location (file:line), confidence level, and the heuristic that matched.

### Step 3 — Detect Zeroization Attempts

For each sensitive object identified in Step 2, check whether a call to an approved wipe API (see Approved Wipe APIs in SKILL.md) exists within the same scope or a cleanup function reachable from that scope.

Record: wipe API used, location, and whether the wipe was found at all.

### Step 4 — MCP Semantic Pass (when available)

Run this step **before** correctness validation so that resolved types, aliases, and cross-file references are available to Steps 5 and 6. Skip and continue if MCP is unavailable in `prefer` mode (see Confidence Gating in SKILL.md).

- Run `{baseDir}/tools/mcp/check_mcp.sh` to confirm MCP is live. If it fails and `mcp_mode=require`, stop the run.
- Activate the project with `activate_project` (pass the repository root path). This must succeed before any other Serena tool can be used. If activation fails, treat MCP as unavailable.
- For each sensitive object and wipe call, resolve symbol definitions using `find_symbol` (by name, with `include_body: true` for type details) and collect cross-file references using `find_referencing_symbols`.
- Trace callers and cleanup paths using `find_referencing_symbols` on wipe wrapper functions. For outgoing calls, read the function body from `find_symbol` output and resolve called symbols.
- Use `get_symbols_overview` to get a high-level view of symbols in a file when exploring unfamiliar TUs.
- Normalize all MCP output: `python {baseDir}/tools/mcp/normalize_mcp_evidence.py`.

Prioritize `find_symbol` queries by sensitive-object name first, then wipe wrapper names. Score confidence: name match alone → `needs_review`; name + type resolved → `likely`; name + type + call chain confirmed → `confirmed`.

### Step 5 — Validate Correctness

For each sensitive object with a detected wipe, use type and alias data from Step 4 (if available) to validate:
- **Size correct**: wipe length matches `sizeof(object)`, not `sizeof(pointer)`. MCP-resolved typedefs and array sizes take precedence over source-level estimates.
- **All exits covered** (heuristic): wipe is present on normal exit, early return, and error paths visible in source. Flag `NOT_ON_ALL_PATHS` if any path appears uncovered.
- **Ordering correct**: wipe occurs before `free()` or scope end, not after.

Emit `PARTIAL_WIPE` for incorrect size. Emit `NOT_ON_ALL_PATHS` for missing paths (heuristic; CFG analysis in Step 10 provides definitive results).

### Step 6 — Data-Flow and Heap Checks

Use cross-file reference data from Step 4 (if available) to extend tracking beyond the current TU.

**Data-flow (produces `SECRET_COPY`):**
- Detect `memcpy()`/`memmove()` copying sensitive buffers.
- Track struct assignments and array copies of sensitive objects.
- Flag function arguments passed by value (copies on stack).
- Flag secrets returned by value.
- Emit `SECRET_COPY` when any of the above copies exist and no approved wipe is tracked for the copy destination.

**Heap (produces `INSECURE_HEAP_ALLOC`):**
- Detect `malloc`/`calloc`/`realloc` used to allocate sensitive objects.
- Check for `mlock()`/`madvise(MADV_DONTDUMP)` — note absence as a warning.
- Recommend secure allocators: `OPENSSL_secure_malloc`, `sodium_malloc`.

---

## Phase 2 — Compiler-Level Analysis

All steps in Phase 2 require a valid compile DB and a working `clang` installation. Skip Phase 2 findings if Phase 1 preflight failed.

### Step 7 — IR Comparison (produces `OPTIMIZED_AWAY_ZEROIZE`)

For each TU containing sensitive objects:

```bash
FLAGS=()
while IFS= read -r flag; do FLAGS+=("$flag"); done < <(
  python {baseDir}/tools/extract_compile_flags.py \
    --compile-db <compile_db> --src <file> --format lines)

{baseDir}/tools/emit_ir.sh --src <file> \
  --out /tmp/zeroize-audit/<tu_hash>.O0.ll --opt O0 -- "${FLAGS[@]}"

{baseDir}/tools/emit_ir.sh --src <file> \
  --out /tmp/zeroize-audit/<tu_hash>.O1.ll --opt O1 -- "${FLAGS[@]}"

{baseDir}/tools/emit_ir.sh --src <file> \
  --out /tmp/zeroize-audit/<tu_hash>.O2.ll --opt O2 -- "${FLAGS[@]}"

{baseDir}/tools/diff_ir.sh \
  /tmp/zeroize-audit/<tu_hash>.O0.ll \
  /tmp/zeroize-audit/<tu_hash>.O1.ll \
  /tmp/zeroize-audit/<tu_hash>.O2.ll
```

Use `<tu_hash>` (a hash of the source path) to avoid collisions when processing multiple TUs.
`diff_ir.sh` outputs a unified diff to stdout; a non-zero exit code means divergence was detected.
Clean up `/tmp/zeroize-audit/` on completion or failure.

**Interpretation:**
- Wipe present at O0, absent at O1 → simple dead-store elimination. Flag `OPTIMIZED_AWAY_ZEROIZE`.
- Wipe present at O1, absent at O2 → aggressive optimization. Flag `OPTIMIZED_AWAY_ZEROIZE`.
- Include the IR diff as mandatory evidence in the finding.

Key IR patterns: `store volatile i8 0` is the primary wipe signal; its absence at O2 when present at O0 is DSE. `@llvm.memset` without the volatile flag is elidable. `alloca` with `@llvm.lifetime.end` and no `store volatile` in the same function indicates stack retention.

### Step 8 — Assembly Analysis (produces `STACK_RETENTION`, `REGISTER_SPILL`)

Skip if `enable_asm=false`.

```bash
{baseDir}/tools/emit_asm.sh --src <file> \
  --out /tmp/zeroize-audit/<tu_hash>.O2.s --opt O2 -- "${FLAGS[@]}"

{baseDir}/tools/analyze_asm.sh \
  --asm /tmp/zeroize-audit/<tu_hash>.O2.s \
  --out /tmp/zeroize-audit/<tu_hash>.asm-analysis.json
```

`analyze_asm.sh` outputs annotated findings to stdout.

Check for:
- **Register spills**: `movq`/`movdqa` of secret values to stack offsets → flag `REGISTER_SPILL`.
- **Callee-saved registers**: `rbx`, `r12`–`r15` (x86-64) pushed to stack containing secret values → flag `REGISTER_SPILL`.
- **Stack retention**: stack frame size and whether secret bytes are cleared before `ret` → flag `STACK_RETENTION`.

Include the relevant assembly excerpt as mandatory evidence.

### Step 9 — Semantic IR Analysis (produces `LOOP_UNROLLED_INCOMPLETE`)

Skip if `enable_semantic_ir=false`.

Parse LLVM IR structurally (do not use regex on raw IR text):
- Build function and basic block representations.
- Track memory operations in SSA form after the `mem2reg` pass.
- Detect loop-unrolled zeroization: 4 or more consecutive zero stores.
- Verify unrolled stores target the correct addresses and cover the full object size.
- Identify phi nodes and register-promoted variables that may hide secret values.

Flag `LOOP_UNROLLED_INCOMPLETE` when unrolling is detected but does not cover the full object.

### Step 10 — Control-Flow Graph Analysis (produces `MISSING_ON_ERROR_PATH`, `NOT_DOMINATING_EXITS`)

Skip if `enable_cfg=false`.

Build a CFG from source or LLVM IR:
- Enumerate all execution paths from function entry to exits.
- Compute dominator sets for all nodes.
- Verify that a wipe node dominates all exit nodes. If not, flag `NOT_DOMINATING_EXITS`.
- Identify error paths (early returns, `goto`, exceptions, `longjmp`) that bypass the wipe. Flag `MISSING_ON_ERROR_PATH` for each such path.

This step produces definitive results replacing the heuristic `NOT_ON_ALL_PATHS` finding from Step 5. If both are emitted for the same object, keep only the CFG-backed finding.

### Step 11 — Runtime Validation Test Generation

Skip if `enable_runtime_tests=false`.

For each confirmed finding, generate:
- A C test harness that allocates the sensitive object and verifies all bytes are zero after the expected wipe point.
- A MemorySanitizer test (`-fsanitize=memory`) to detect reads of uninitialized or un-zeroed memory.
- A Valgrind invocation target for leak and memory error detection.
- A stack canary test to detect stack retention after function return.

Output a `Makefile` in `{baseDir}/generated_tests/` that builds and runs all tests with appropriate sanitizer flags.

### Step 12 — PoC Generation (mandatory)

Generate proof-of-concept C programs for all findings regardless of confidence. Each PoC exits 0 (exploitable) or 1 (not exploitable):

```bash
python {baseDir}/tools/generate_poc.py \
  --findings <findings_json> \
  --compile-db <compile_db> \
  --out <poc_output_dir> \
  --categories <poc_categories> \
  --config <config> \
  --no-confidence-filter
```

After generation, review PoCs for `// TODO` comments and fill them in using source context. Compilation and validation are handled by the orchestrator in Phase 5 (interactive).

Key PoC strategies: `OPTIMIZED_AWAY_ZEROIZE` — compile with and without `-O2`, compare memory dumps; `STACK_RETENTION` — call the target function, read stack memory after return; `MISSING_SOURCE_ZEROIZE` — verify bytes are non-zero at function exit. C/C++ findings support all categories. Rust findings support `MISSING_SOURCE_ZEROIZE`, `SECRET_COPY`, and `PARTIAL_WIPE` via `cargo test`; all other Rust categories are marked `poc_supported: false`.
