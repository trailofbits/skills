# PoC Crafting Reference

## Overview

Each zeroize-audit finding is demonstrated with a bespoke proof-of-concept program
crafted from the finding details and the actual source code. PoCs are individually
written, not generated from templates — they use the real function signatures,
variable names, types, and sizes from the audited codebase. Each PoC exits 0 if the
secret persists (exploitable) or 1 if the data was properly wiped (not exploitable).

## Exit Code Convention

| Exit code | Meaning |
|-----------|---------|
| 0 | Secret persists after the operation — finding is exploitable |
| 1 | Secret was wiped — finding is not exploitable in this configuration |

The `POC_PASS()` and `POC_FAIL()` macros in `poc_common.h` enforce this convention.

## Common Techniques

### Volatile Reads

The core verification technique is reading through a `volatile` pointer after the
function under test returns. This prevents the compiler from optimizing away the
read, ensuring we observe the actual memory state:

```c
static int volatile_read_nonzero(const void *ptr, size_t len) {
    const volatile unsigned char *p = (const volatile unsigned char *)ptr;
    int found = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0) found = 1;
    }
    return found;
}
```

### Stack Probing

For `STACK_RETENTION` and `REGISTER_SPILL` findings, the PoC calls the target
function then immediately calls `stack_probe()` — a `noinline`/`noclone` function
that reads uninitialized local variables to detect whether the prior call frame left
secret data on the stack:

```c
__attribute__((noinline, noclone))
static int stack_probe(size_t frame_size) {
    volatile unsigned char probe[STACK_PROBE_MAX];
    /* Read uninitialized stack — check for secret fill pattern */
    int count = 0;
    for (size_t i = 0; i < frame_size; i++) {
        if (probe[i] == SECRET_FILL_BYTE) count++;
    }
    return count >= (int)(frame_size / 4);
}
```

### Source Inclusion

For static functions and small files (<=5000 lines by default), PoCs include the
source file directly via `#include "../../src/crypto.c"`. This handles both static
and extern functions without requiring separate compilation. For large files with
non-static functions, the Makefile uses object-file linking instead.

### Secret Fill Pattern

Buffers are initialized with `0xAA` (configurable via `secret_fill_byte` in config)
before calling the target function. After the call, the PoC checks whether the fill
pattern persists — indicating the secret was not wiped.

## Per-Category Strategies

### MISSING_SOURCE_ZEROIZE

**Opt level:** `-O0`
**Technique:** Call the function that handles the secret, then volatile-read the
buffer after it returns. At `-O0` there are no optimization passes that could
accidentally wipe the buffer, so if the secret persists, it confirms the source
code lacks a wipe call.

**Crafting guidance:**
- Read the function signature and determine minimal valid arguments
- Identify the exact sensitive variable from the finding — use its real name and type
- If the function takes the sensitive buffer as a parameter, allocate it in `main()`,
  fill with `SECRET_FILL_BYTE`, pass it to the function, then check after return
- If the sensitive variable is a local, include the source file and examine the buffer
  via a global pointer or by modifying the function to expose it

**Pitfalls:**
- The buffer must be the actual sensitive variable, not a local copy
- Stack-allocated secrets may be overwritten by subsequent function calls even
  without explicit zeroization — run immediately after the function returns

### OPTIMIZED_AWAY_ZEROIZE

**Opt level:** The level where the wipe disappears (from `compiler_evidence.diff_summary`)
**Technique:** Same as `MISSING_SOURCE_ZEROIZE`, but compiled at the optimization
level where the compiler removes the wipe. The finding's `compiler_evidence` field
indicates which level this is (typically `-O1` for simple DSE, `-O2` for aggressive
optimization).

**Crafting guidance:**
- Read the `compiler_evidence.diff_summary` to determine the exact optimization level
- The wipe IS present at `-O0` — compiling the PoC at `-O0` will show "not exploitable"
  which would be misleading. Always use the opt level from the evidence.
- Include the source file to ensure the compiler can apply the same optimizations

**Pitfalls:**
- The opt level must match what `diff_ir.sh` reported — compiling at a different
  level may give false negatives
- LTO can change behavior; PoCs use single-TU compilation by default

### STACK_RETENTION

**Opt level:** `-O2`
**Technique:** Call the function, then immediately call `stack_probe()` with a
frame size matching the target function's stack allocation. The probe reads
uninitialized locals that overlap the prior call frame.

**Crafting guidance:**
- Extract the stack frame size from the ASM evidence in the finding
- The probe function MUST be called immediately after the target function returns,
  with no intervening function calls that could overwrite the stack
- Use `noinline` and `noclone` on the probe to prevent frame reuse

**Pitfalls:**
- Stack layout varies between compiler versions and optimization levels
- The probe function must be `noinline` to prevent the compiler from reusing
  the same frame
- Frame size is estimated from ASM evidence; verify against the actual assembly
- Address Space Layout Randomization (ASLR) does not affect stack frame reuse
  within a single thread

### REGISTER_SPILL

**Opt level:** `-O2`
**Technique:** Similar to stack retention, but targets the specific stack offset
where the register spill occurs (extracted from the ASM evidence showing
`movq %reg, -N(%rsp)`).

**Crafting guidance:**
- Extract the exact spill offset from the finding's ASM evidence
- Target the probe at that specific region of the stack
- The same `noinline` probe approach applies

**Pitfalls:**
- Spill offsets are compiler-specific and may change with minor code changes
- Different register allocation strategies produce different spill patterns
- The probe must target the exact offset region to be reliable

### SECRET_COPY

**Opt level:** `-O0`
**Technique:** Call the function that copies the secret, verify the original may
be wiped, then volatile-read the copy destination to confirm the copy persists
without zeroization.

**Crafting guidance:**
- Identify the copy destination from the source code: `memcpy` target, struct
  assignment LHS, return value receiver, or pass-by-value parameter
- The PoC must check the COPY, not the original — the original may be wiped
- If the copy is to a struct field, allocate the struct and check that specific field

**Pitfalls:**
- The copy destination must be identified from the source code
- Multiple copies may exist; each needs separate verification

### MISSING_ON_ERROR_PATH

**Opt level:** `-O0`
**Technique:** Force the error path by providing controlled inputs that trigger
the error return, then volatile-read the secret buffer to confirm it was not
wiped before the error exit.

**Crafting guidance:**
- Read the source code to understand what conditions trigger the error return
- Common error triggers: NULL pointer arguments, invalid key sizes, allocation
  failure (can use `malloc` interposition), invalid magic numbers
- After the function returns with an error code, check both the return value
  (to confirm the error path was taken) AND the secret buffer (to confirm it persists)
- Comment the choice of error-triggering input with a reference to the source line

**Pitfalls:**
- Triggering the error path may require domain knowledge (invalid keys, NULL
  pointers, allocation failures)
- Some error paths involve signals or `longjmp` that are hard to trigger from
  a simple test harness
- Error codes must be checked to confirm the error path was actually taken

### PARTIAL_WIPE

**Opt level:** `-O0`
**Technique:** Fill the full buffer with the secret fill pattern, call the function,
then volatile-read the *tail* beyond the incorrectly-sized wipe region. If the
function wipes only N bytes of an M-byte object (N < M), the tail
`buf[N..M]` still contains the secret.

**Crafting guidance:**
- Extract the wiped size and full object size from the finding evidence
- The PoC must check `buf[wiped_size .. full_size]`, not the entire buffer
- If both sizes are uncertain, read the source to verify `sizeof()` calls

**Pitfalls:**
- The wiped vs. full sizes must be verified against source
- At `-O0` the compiler won't add extra zeroing, so this is a pure source-level bug
- Struct padding may cause false positives if the wipe intentionally skips padding

### NOT_ON_ALL_PATHS

**Opt level:** `-O0`
**Technique:** Force execution down the control-flow path that lacks the wipe,
then volatile-read the secret buffer. This is structurally identical to
`MISSING_ON_ERROR_PATH` but covers *any* uncovered path, not just error paths.

**Crafting guidance:**
- Read the function's control flow to identify which branch lacks the wipe
- Determine what input values force execution through that branch
- Comment the input choice and reference the specific branch condition

**Pitfalls:**
- Requires understanding the function's branching logic
- The heuristic finding from source analysis may be superseded by CFG-backed
  `NOT_DOMINATING_EXITS` — check for duplicates
- Multiple uncovered paths may exist; the PoC demonstrates only one

### INSECURE_HEAP_ALLOC

**Opt level:** `-O0`
**Technique:** Demonstrate heap residue using the `heap_residue_check()` helper:
allocate with `malloc()`, fill with secret, free, re-allocate the same size,
then check if the secret persists in the new allocation. This proves that
standard allocators do not scrub freed memory.

**Crafting guidance:**
- Use the exact allocation size from the finding
- For a function-specific proof, call the target function (which does the
  malloc/use/free), then immediately malloc the same size and check
- Add a comment explaining that this demonstrates the general vulnerability

**Pitfalls:**
- Do **not** compile with AddressSanitizer (`-fsanitize=address`) — ASan poisons
  freed memory, hiding the vulnerability
- Heap allocator behavior varies: glibc `malloc` reuses freed chunks predictably,
  but jemalloc or tcmalloc may not — the PoC may give false negatives on
  non-standard allocators
- The PoC demonstrates the general vulnerability; for function-level proof,
  call the actual target function

### LOOP_UNROLLED_INCOMPLETE

**Opt level:** `-O2`
**Technique:** Like `PARTIAL_WIPE` but compiled at `-O2` where incomplete loop
unrolling occurs. The compiler unrolls the wipe loop for N bytes but the object
is M bytes (N < M). Fill the buffer, call the function, check the tail beyond
the unrolled region.

**Crafting guidance:**
- Extract the covered bytes and object size from the IR semantic analysis evidence
- Compile at `-O2` — at `-O0` the loop executes correctly
- Check `buf[covered_bytes .. object_size]`

**Pitfalls:**
- Must compile at `-O2` (or the level where unrolling occurs) — at `-O0` the
  loop executes correctly
- Covered bytes and object size are extracted from IR semantic analysis evidence;
  if the IR evidence is unavailable, values may be inaccurate
- Different compilers (GCC vs. Clang) and versions unroll differently; the PoC
  is compiler-specific

### NOT_DOMINATING_EXITS

**Opt level:** `-O0`
**Technique:** Force execution through an exit path that bypasses the wipe, as
identified by CFG dominator analysis. The wipe node does not dominate all exit
nodes, meaning some return paths leave the secret in memory.

**Crafting guidance:**
- Read the finding evidence to identify which exit path bypasses the wipe
- Determine what inputs reach the non-dominated exit
- Comment the input choice and reference the CFG evidence (exit line or path count)

**Pitfalls:**
- Requires understanding of the function's CFG; the finding evidence identifies
  the exit line or path count
- Similar to `NOT_ON_ALL_PATHS` but backed by CFG evidence rather than
  source-level heuristics

## Pipeline Integration

PoC crafting and validation is mandatory for every finding, regardless of
confidence level. The pipeline flow is:

1. **Phase 3 — Interim Finding Collection**: Agent 4 produces `findings.json`
   with all gated findings. No final report yet.

2. **Phase 4 — PoC Crafting**: Agent 5 reads each finding and the corresponding
   source code, then writes bespoke PoC programs. Each PoC is individually
   tailored — using real function names, variable names, types, and sizes.

3. **Phase 5 — PoC Validation & Verification**:
   - Agent 5b compiles and runs all PoCs, recording exit codes.
   - Agent 5c verifies each PoC proves its claimed finding by checking:
     target variable match, target function match, technique appropriateness,
     optimization level, exit code interpretation, and result plausibility.
   - Orchestrator presents verification failures to user via `AskUserQuestion`.
   - Orchestrator merges all results into `poc_final_results.json`.

4. **Phase 6 — Report Finalization**: Agent 4 is re-invoked in final mode.
   It merges PoC validation and verification results into findings:
   - Exit 0 + verified → `exploitable` — strong evidence, can upgrade confidence.
   - Exit 1 + verified → `not_exploitable` — downgrade severity to `low`.
   - Verified=false + user rejected → `rejected` — no confidence change.
   - Verified=false + user accepted → use result but note as weaker signal.
   - Compile failure → annotate, no confidence change.
   - Produces the final `final-report.md` with PoC validation and verification summary.

### Validation Result Mapping

| Exit Code | Compile | Verified | Result | Finding Impact |
|-----------|---------|----------|--------|---------------|
| 0 | success | yes | `exploitable` | Confirm finding; can upgrade `likely` → `confirmed` |
| 1 | success | yes | `not_exploitable` | Downgrade severity to `low` (informational) |
| 0/1 | success | no (user accepted) | original | Weaker confidence signal; note verification failure |
| 0/1 | success | no (user rejected) | `rejected` | No confidence change |
| — | failure | — | `compile_failure` | Annotate; no confidence change |
| — | — | — | `no_poc` | No PoC generated; annotate; no confidence change |

## Rust PoC Generation

Rust PoCs are enabled for three categories where a simple volatile-read after drop is sufficient to prove the vulnerability. All other categories remain excluded.

**Exit code convention (cargo test):**
- `assert!` passes → cargo exits 0 → `"exploitable"` (secret persists)
- `assert!` panics → cargo exits non-zero → `"not_exploitable"` (secret wiped)

**Verification primitive:** Use `std::ptr::read_volatile` inside `unsafe { }`. Never use the C `volatile` keyword in Rust PoCs.

**Pointer validity:** `read_volatile` after `drop()` is only safe for heap-backed data. If the sensitive type is stack-only, force heap allocation: `let boxed = Box::new(obj); let raw = boxed.as_ref().as_ptr(); drop(boxed);`. For types with `Vec`/`Box` fields, the raw pointer to the field's backing allocation remains valid after drop (the heap page is not scrubbed by the allocator).

---

### MISSING_SOURCE_ZEROIZE (Rust)

**Opt level:** debug (no `--release`)
**Technique:** Construct the sensitive type with `[0xAAu8; N]` fill. Capture a raw pointer to the backing buffer **before** drop. Drop the type (or let scope end). Volatile-read the buffer to check persistence.

```rust
#[test]
fn poc_za_NNNN_missing_source_zeroize() {
    let key = SensitiveKey::new([0xAAu8; 32]);
    let raw: *const u8 = key.as_slice().as_ptr();
    drop(key);
    let secret_persists = (0..32usize).any(|i| unsafe {
        std::ptr::read_volatile(raw.add(i)) == 0xAA
    });
    assert!(secret_persists, "Secret was wiped — not exploitable");
}
```

**Pitfalls:**
- The raw pointer must point to heap-backed storage — stack pointers become dangling after drop.
- If the type does not expose `as_slice()` or similar, use a field accessor (`key.key_bytes.as_ptr()`).
- At debug build, the compiler does not add extra zeroing — a positive result confirms the source lacks a wipe call.

---

### SECRET_COPY (Rust)

**Opt level:** debug (no `--release`)
**Technique:** Perform the identified copy operation (`.clone()`, `Copy` assignment, `From::from()`, `Debug` formatting). Drop the **original**. Volatile-read the **copy** — not the original.

```rust
#[test]
fn poc_za_NNNN_secret_copy() {
    let original = SensitiveKey::new([0xAAu8; 32]);
    let copy = original.clone();                        // or Copy assignment / From::from()
    let raw: *const u8 = copy.as_slice().as_ptr();
    drop(original);                                      // original may be wiped; copy is not
    let secret_persists = (0..32usize).any(|i| unsafe {
        std::ptr::read_volatile(raw.add(i)) == 0xAA
    });
    drop(copy);
    assert!(secret_persists, "Copy was wiped — not exploitable");
}
```

**Pitfalls:**
- Read the copy, not the original. The original may be properly wiped; the copy is the vulnerability.
- For `#[derive(Debug)]` findings: format via `format!("{:?}", &original)` and check the resulting `String` for the fill pattern bytes (hex or decimal representations of `0xAA`).
- For `From`/`Into` findings: call the conversion and check the target type's buffer.

---

### PARTIAL_WIPE (Rust)

**Opt level:** debug (no `--release`)
**Technique:** Construct the type with `[0xAAu8; full_size]` fill. Trigger drop. Volatile-read **only the tail** (`wiped_size..full_size`). The head (`0..wiped_size`) may be correctly zeroed; only the tail proves the partial wipe.

```rust
#[test]
fn poc_za_NNNN_partial_wipe() {
    // full_size = 64, wiped_size = 32 (from finding evidence)
    let obj = SensitiveStruct { key: [0xAAu8; 64], ..Default::default() };
    let raw: *const u8 = obj.key.as_ptr();
    drop(obj);
    // Only check the tail bytes beyond the wipe region
    let tail_persists = (32usize..64).any(|i| unsafe {
        std::ptr::read_volatile(raw.add(i)) == 0xAA
    });
    assert!(tail_persists, "Tail was wiped — not exploitable");
}
```

**Pitfalls:**
- Must check `buf[wiped_size..full_size]`, not the entire buffer — checking from 0 may hit correctly-wiped bytes and produce a false negative.
- Extract `wiped_size` and `full_size` from the finding evidence. Verify against `sizeof()` calls in the Drop impl.
- Struct padding may occupy bytes beyond the last field — be aware of layout differences with `#[repr(C)]` vs. default `#[repr(Rust)]`.

---

## Excluded Rust Categories

The following Rust finding categories remain `poc_supported=false`. Each requires techniques not yet implemented for Rust.

| Category | Reason |
|---|---|
| `OPTIMIZED_AWAY_ZEROIZE` | Requires compiling at `--release` and confirming the wipe existed at debug level; no PoC harness for opt-level switching |
| `STACK_RETENTION` | Stack probe requires unsafe inline assembly intrinsics; frame layout is not stable across Rust versions |
| `REGISTER_SPILL` | Register allocation in Rust depends on monomorphization; spill offsets from ASM analysis don't map reliably to test code |
| `NOT_ON_ALL_PATHS` | Requires driving async Future state machine through suspension; no implemented harness for Rust async |
| `MISSING_ON_ERROR_PATH` | Requires forcing `Result::Err` or `panic!` paths with domain knowledge of the error conditions |
| `NOT_DOMINATING_EXITS` | CFG dominator analysis results require source-level forcing of specific control-flow paths |
| `INSECURE_HEAP_ALLOC` | Rust's allocator trait system does not support the `malloc`-interposition approach used for C |
| `LOOP_UNROLLED_INCOMPLETE` | Requires `--release` compilation and extracting the covered-byte count from IR evidence |

## Limitations

1. **Stack probe is probabilistic:** Frame layout varies between compiler versions,
   optimization levels, and even minor source changes. A negative result does not
   prove the stack is clean — only that the probe did not find the fill pattern at
   the expected offset.

2. **Register spill offsets are compiler-specific:** The offset extracted from
   ASM evidence (e.g., `-48(%rsp)`) may differ when compiled on a different system
   or with a different compiler version.

3. **Error path triggers may need domain knowledge:** Determining what inputs cause
   a function to take its error path may require understanding the application's
   protocol or data format.

4. **Source inclusion may cause conflicts:** Including a `.c` file that defines
   `main()` or has conflicting global symbols will cause compilation errors. In
   these cases, use object-file linking instead.

5. **Single-TU compilation:** PoCs compile a single translation unit. Cross-TU
   optimizations (LTO) may produce different behavior in production builds.

6. **No dynamic analysis:** PoCs are static programs. They do not use sanitizers,
   Valgrind, or other runtime instrumentation (those are covered by Step 11's
   runtime test generation).

7. **Heap residue is allocator-dependent:** The `heap_residue_check()` helper
   relies on the allocator reusing a recently-freed chunk. This works reliably
   with glibc `malloc` but may produce false negatives with jemalloc, tcmalloc,
   or custom allocators. Do not compile with ASan (it poisons freed memory).

8. **Verification is heuristic:** The PoC verifier checks alignment between the
   PoC and the finding, but cannot prove that a PoC is correct in all cases.
   Suspicious results are flagged for user review.
