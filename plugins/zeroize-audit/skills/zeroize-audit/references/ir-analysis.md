# LLVM IR Analysis for Zeroization Auditing

This reference covers multi-level IR analysis for detecting compiler-optimized zeroization (dead-store elimination of wipes) and interpreting results. Read this during Step 7 (IR comparison) and Step 9 (semantic IR analysis) in `task.md`. For flag extraction and pipeline setup, refer to the compile-commands reference (loaded separately from SKILL.md).

---

## Optimization Level Semantics

| Level | What changes | Relevance to zeroization |
|---|---|---|
| **O0** | No optimization. All stores kept. | Baseline — wipe always present if written in source |
| **O1** | Basic optimizations. Simple dead-store elimination begins. | Diagnostic level: if wipe vanishes here, it's simple DSE. Fix is straightforward. |
| **O2** | Full DSE, inlining, SROA, alias analysis. | Most production builds. Most non-volatile wipes removed here. |
| **O3** | Aggressive vectorization, loop transforms, more inlining. | Rarely removes more wipes than O2, but can for loop-based wipes. |
| **Os/Oz** | Size-optimized. May collapse wipe loops into `memset`. | Verify wipe survives after size optimization; collapsed `memset` may become DSE-vulnerable. |

**Always include O0 as the unoptimized baseline**, regardless of the `opt_levels` input. O1 is the diagnostic level — if the wipe disappears there, the cause is simple DSE and the fix is straightforward. If the wipe only disappears at O2 or O3, proceed to the multi-level root cause analysis below.

---

## Emitting IR at Multiple Levels

Extract flags once, then emit IR for each level in `opt_levels`. Use `<tu_hash>` (a hash of the source path) to avoid collisions during parallel TU processing. Always clean up temp files on completion or failure.

```bash
mkdir -p /tmp/zeroize-audit/

FLAGS=()
while IFS= read -r flag; do FLAGS+=("$flag"); done < <(
  python {baseDir}/tools/extract_compile_flags.py \
    --compile-db build/compile_commands.json \
    --src src/crypto.c --format lines)

# Emit IR for each level in opt_levels (O0 always included as baseline)
for OPT in O0 O1 O2; do
  {baseDir}/tools/emit_ir.sh \
    --src src/crypto.c \
    --out /tmp/zeroize-audit/<tu_hash>.${OPT}.ll \
    --opt ${OPT} -- "${FLAGS[@]}"
done

# Diff all levels — prints pairwise diffs and a WIPE PATTERN SUMMARY
{baseDir}/tools/diff_ir.sh \
  /tmp/zeroize-audit/<tu_hash>.O0.ll \
  /tmp/zeroize-audit/<tu_hash>.O1.ll \
  /tmp/zeroize-audit/<tu_hash>.O2.ll

# Cleanup
rm -f /tmp/zeroize-audit/<tu_hash>.*.ll
```

For Rust TUs, `emit_ir.sh` does not apply. Use `cargo rustc -- --emit=llvm-ir -C opt-level=N` instead and pass the resulting `.ll` files directly to `diff_ir.sh`. Use `bear -- cargo build` to generate `compile_commands.json` for Rust projects.

---

## LLVM IR Zeroization Patterns

### DSE-safe patterns (survive optimization)

These indicate a secure wipe the compiler cannot remove.

**Volatile memset intrinsic** — the `i1 true` (volatile) flag prevents DSE:
```llvm
call void @llvm.memset.p0i8.i64(i8* volatile %ptr, i8 0, i64 32, i1 true)
```

**Volatile zero stores** — volatile side effects must be preserved:
```llvm
store volatile i8 0, i8* %ptr, align 1
store volatile i64 0, i64* %ptr, align 8
```

**Opaque wipe function calls** — DSE cannot remove calls to external functions with unknown side effects:
```llvm
call void @explicit_bzero(i8* %key, i64 32)
call void @sodium_memzero(i8* %key, i64 32)
call void @OPENSSL_cleanse(i8* %key, i64 32)
call void @SecureZeroMemory(i8* %key, i64 32)
```

**`memset_s`** — defined by C11 to be non-optimizable:
```llvm
call i32 @memset_s(i8* %key, i64 32, i32 0, i64 32)
```

**Rust `zeroize` crate** — emits volatile stores via the `Zeroize` trait; look for:
```llvm
store volatile i8 0, i8* %ptr, align 1   ; repeated per byte, or as unrolled loop
```

---

### DSE-vulnerable patterns (may be removed at O1 or O2)

**Non-volatile memset intrinsic** — `i1 false` is the most common `OPTIMIZED_AWAY_ZEROIZE` pattern:
```llvm
call void @llvm.memset.p0i8.i64(i8* %ptr, i8 0, i64 32, i1 false)
```

**Non-volatile zero stores** — any non-volatile store to a dead location is DSE-eligible:
```llvm
store i8 0, i8* %ptr, align 1
store i64 0, i64* %ptr, align 8
store i32 0, i32* %ptr, align 4
```

**Standard `memset` inlined to non-volatile intrinsic** — `memset(key, 0, 32)` in source is lowered by Clang to `@llvm.memset ... i1 false`. The source used `memset` but the IR form is DSE-vulnerable. This is the most frequent source of confusion.

---

## Reading an IR Diff: Concrete Before/After Example

**Source (C):**
```c
void handle_request(uint8_t session_key[32]) {
    // ... use session_key ...
    memset(session_key, 0, 32);  // intended cleanup
}
```

**O0 IR — wipe present:**
```llvm
define void @handle_request(i8* %session_key) {
entry:
  ; ... computation uses session_key ...
  call void @llvm.memset.p0i8.i64(i8* %session_key, i8 0, i64 32, i1 false)
  ret void
}
```

**O2 IR — wipe removed by DSE:**
```llvm
define void @handle_request(i8* %session_key) {
entry:
  ; ... computation ...
  ; llvm.memset REMOVED — no read from session_key after the store;
  ; optimizer treats it as a dead store and eliminates it.
  ret void
}
```

**`diff_ir.sh` output:**
```
=== DIFF: O0.ll vs O2.ll ===
-  call void @llvm.memset.p0i8.i64(i8* %session_key, i8 0, i64 32, i1 false)

=== WIPE PATTERN SUMMARY ===
O0.ll: WIPE PRESENT
O1.ll: WIPE PRESENT
O2.ll: WIPE ABSENT  <-- first disappearance
```

Lines starting with `-` are present in the lower-opt file but absent in the higher-opt file. A `-` line containing any of the following tokens is direct evidence of `OPTIMIZED_AWAY_ZEROIZE`:

`llvm.memset`, `store i8 0`, `store i64 0`, `store i32 0`, `@explicit_bzero`, `@sodium_memzero`, `@OPENSSL_cleanse`, `@SecureZeroMemory`

---

## Multi-Level Root Cause Analysis

The level at which the wipe first disappears narrows the root cause and determines the appropriate fix:

```
O0 → WIPE PRESENT   (baseline — wipe was written in source)
O1 → WIPE ABSENT    → Simple dead-store elimination (basic DSE pass)
                       Fix: replace memset with explicit_bzero or volatile wipe loop
O2 → WIPE ABSENT    → One or more of:
(first disappearance)    • DSE + inlining: wipe is in a helper inlined into caller,
                           becomes dead store in caller's context
                         • SROA: struct/array promoted to scalars; individual
                           zero stores become DSE-eligible
                         • Alias analysis: proves no live uses after the wipe
                       Fix: use explicit_bzero; ensure wipe is not inside
                       an inlined callee (see Inlining section below)
O3 → WIPE ABSENT    → Aggressive loop transforms or vectorization eliminated
(only here)            a loop-based wipe
                       Fix: replace wipe loop with explicit_bzero or volatile loop
```

If the wipe disappears at O1, a simple `explicit_bzero` or `volatile` qualifier is sufficient. If it only disappears at O2 due to inlining, also ensure the wipe is not inside a callee that gets inlined at the call site.

---

## Advanced IR Analysis Scenarios

### Inlining and cross-function DSE

When a cleanup wrapper (e.g., `zeroize_key()`) is inlined into a caller, the wipe may become a dead store in the caller's context even if it survives in the callee's IR. Always emit IR for the **calling** TU — this is where inlining occurs:

```bash
# zeroize_key() defined in utils.c, called from crypto.c
# Emit IR for the caller — inlining happens here:
FLAGS=()
while IFS= read -r flag; do FLAGS+=("$flag"); done < <(
  python {baseDir}/tools/extract_compile_flags.py \
    --compile-db build/compile_commands.json --src src/crypto.c --format lines)

{baseDir}/tools/emit_ir.sh \
  --src src/crypto.c \
  --out /tmp/zeroize-audit/<tu_hash>.O2.ll --opt O2 -- "${FLAGS[@]}"
```

If the wipe is present in `utils.c` IR but absent in `crypto.c` IR at O2, the cause is cross-function DSE after inlining. Mark the `OPTIMIZED_AWAY_ZEROIZE` finding on the call site in `crypto.c`, not on `utils.c`.

### SROA (Scalar Replacement of Aggregates)

At O1+, SROA promotes small structs and arrays to individual scalar SSA values (registers). A `memset` of a struct may become a series of individual `store i32 0` / `store i8 0` instructions per field — each then eligible for DSE independently. In the diff, look for:
- O0: single `llvm.memset` covering the struct
- O1/O2: the `memset` is replaced by per-field zero stores, then those stores are removed

This means the wipe may partially survive SROA (some fields zeroed, others eliminated). Check that **all** fields of a sensitive struct are covered, not just the first.

### Loop unrolling of wipe loops

A manual wipe loop:
```c
for (int i = 0; i < 32; i++) key[i] = 0;
```
may be unrolled at O2 into 32 consecutive `store i8 0` instructions. If unrolling is incomplete (e.g., only 16 of 32 iterations unrolled and the remainder is a DSE-eligible tail), flag `LOOP_UNROLLED_INCOMPLETE`. Use `{baseDir}/tools/analyze_ir_semantic.py` for automated detection — do not use regex on raw IR text. The semantic tool builds a proper basic block representation and counts consecutive zero stores with address verification.

### Phi nodes and register-promoted secrets

After `mem2reg`, secret values that were stack-allocated may be promoted to SSA values tracked through phi nodes. A wipe of the original stack slot may not reach all SSA uses. Look for:
```llvm
%key.0 = phi i64 [ %loaded_key, %entry ], [ 0, %cleanup ]
```
If `%key.0` is used after the phi but the `0` arm is only reached on one path, the secret may persist in the non-zero arm. Flag as `NOT_DOMINATING_EXITS` if CFG analysis confirms it.

---

## Populating `compiler_evidence` in the Report

For each `OPTIMIZED_AWAY_ZEROIZE` finding, populate the output schema fields as follows. `OPTIMIZED_AWAY_ZEROIZE` is **never valid without IR diff evidence** — do not emit this finding from source-level analysis alone.

```json
{
  "category": "OPTIMIZED_AWAY_ZEROIZE",
  "compiler_evidence": {
    "opt_levels": ["O0", "O1", "O2"],
    "o0": "call void @llvm.memset.p0i8.i64(i8* %session_key, i8 0, i64 32, i1 false) present at line 88.",
    "o1": "WIPE PRESENT at O1.",
    "o2": "llvm.memset call absent at O2 — dead store eliminated after SROA promotes session_key to registers.",
    "diff_summary": "Wipe first disappears at O2. Non-volatile memset(session_key, 0, 32) eliminated by DSE after SROA. Fix: replace memset with explicit_bzero."
  }
}
```

Field usage notes:
- `opt_levels`: list every level that was emitted, not just the levels where the wipe changed.
- `o0` through `o2` (and `o1`, `o3` if analyzed): state explicitly whether the wipe is PRESENT or ABSENT at each level, with a short IR excerpt if present.
- If the wipe only disappears at O3 but is present at O2: set `o2` to `"WIPE PRESENT at O2"` and document the O3 removal in `diff_summary`.
- `diff_summary`: always identify the first disappearance level and the most likely optimization pass responsible (DSE, inlining, SROA, alias analysis, loop transform).
