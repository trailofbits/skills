---
name: vector-forge
description: "Mutation-driven test vector generation. Finds implementations of a cryptographic algorithm or protocol, runs mutation testing to identify escaped mutants, then generates new test vectors that deliberately exercise the uncovered code paths. Compares before/after mutation kill rates to prove vector effectiveness. Use when generating cryptographic test vectors, measuring Wycheproof coverage gaps, finding escaped mutants via mutation testing, creating cross-implementation test suites, or improving test vector coverage for crypto primitives."
---

# Vector Forge

Uses mutation testing to systematically identify gaps in test vector
coverage, then generates new test vectors that close those gaps.
Measures effectiveness by comparing mutation kill rates before and after.

## When to Use

- Generating test vectors for cryptographic algorithms or protocols
- Evaluating how well existing test vectors cover an implementation
- Finding implementation code paths that no test vector exercises
- Creating Wycheproof-style cross-implementation test vectors
- Measuring the concrete coverage value of a test vector suite

## When NOT to Use

- No implementations exist yet (need code to mutate)
- Single trivial implementation with no edge cases
- Testing application logic rather than algorithm implementations
- The algorithm has no public test vectors to compare against

## Prerequisites

- **trailmark** installed — if `uv run trailmark` fails, run:
  ```bash
  uv pip install trailmark
  ```
- At least one implementation of the target algorithm in a
  language with mutation testing support
- A test harness that consumes test vectors and exercises
  the implementation
- A mutation testing framework for the target language

---

## Rationalizations (Do Not Skip)

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "We have enough test vectors" | Mutation testing proves otherwise | Run the baseline first |
| "The implementation's own tests are sufficient" | Own tests often share blind spots with the impl | Cross-impl vectors catch different bugs |
| "FFI crates can be mutation tested at the binding layer" | Mutations to wrappers don't affect the underlying impl | Mutate the actual implementation language |
| "Timeouts mean the mutation was caught" | Timeouts are ambiguous — could be killed or alive | Resolve timeouts before drawing conclusions |
| "All mutants are equivalent" | Most aren't — verify by reading the mutation | Classify each escaped mutant individually |
| "Checking valid vectors is enough" | Permissive mutations survive without negative assertions | Assert rejection for every invalid vector |
| "Manual analysis is fine" | Manual analysis misses what tooling catches | Install and run the tools |

---

## Workflow Overview

```
Phase 1: Discovery       → Find implementations to test
      ↓
Phase 2: Harness         → Write/adapt test vector harness for each impl
      ↓
Phase 3: Baseline        → Run mutation testing with existing vectors
      ↓
Phase 4: Escape Analysis → Classify escaped mutants by code path
      ↓
Phase 5: Vector Gen      → Create test vectors targeting escapes
      ↓
Phase 6: Validation      → Re-run mutation testing, compare before/after
      ↓
Output: Coverage Report + New Test Vectors
```

---

## Phase 1: Discovery

Find implementations of the target algorithm. Look for:

1. **Pure implementations** in high-level languages (Go, Rust, Python)
   — these are the best mutation testing targets
2. **FFI wrapper crates** — identify these early so you don't waste
   time mutating wrapper glue code
3. **Reference implementations** — useful for cross-verification but
   may not be the best mutation targets

For each implementation, note:
- Language and mutation testing framework
- Whether it's pure code or FFI wrappers
- Existing test suite size and coverage
- Which API surface the test vectors will exercise

### Implementation Type Classification

| Type | Mutation Value | Example |
|------|---------------|---------|
| Pure implementation | High | zkcrypto/bls12_381 (Rust), gnark-crypto (Go) |
| FFI bindings to C/asm | Low at binding layer | blst Rust crate |
| C/C++ implementation | High (use Mull) | blst C library |
| Generated code | Medium (mutations may be equivalent) | gnark-crypto generated field arithmetic |

**Key insight:** If an implementation delegates to another language
via FFI, you must mutate the *underlying* implementation, not the
bindings. For C/C++ underneath Rust/Go/Python, use Mull or similar.

---

## Phase 2: Harness

For each implementation, create a test harness that:

1. Reads test vectors from JSON files (Wycheproof format recommended)
2. Exercises the implementation's API for each vector
3. Asserts **both acceptance and rejection**:
   - Valid vectors: deserialization succeeds, output matches expected
   - Invalid vectors: deserialization fails or verification rejects
4. Adds **roundtrip assertions** for valid deserialization vectors:
   `serialize(deserialize(bytes)) == bytes`
5. Reports pass/fail per vector with test IDs

**Critical:** A harness that only checks valid vectors will miss all
permissive mutations (e.g., `&` → `|` in validation). See
[references/lessons-learned.md](references/lessons-learned.md) §7.

The harness must be runnable by the mutation testing framework.
For most frameworks this means:
- **Go:** A `_test.go` file in the same package as the implementation
- **Rust:** An integration test in `tests/` or inline `#[test]` functions
- **Python:** A pytest test file
- **C/C++:** A test binary linked against the implementation

### Harness Placement

The harness must live *inside the implementation's package* so the
mutation framework can see it. This usually means:

```bash
# Go: add test file to the package being mutated
cp wycheproof_test.go /path/to/impl/package/

# Rust: add integration test
cp wycheproof.rs /path/to/crate/tests/

# Python: add test to the test directory
cp test_wycheproof.py /path/to/package/tests/
```

### Handling Existing Vectors

If the implementation already has test vectors:
1. Run mutation testing with ONLY the existing vectors (baseline)
2. Run mutation testing with ONLY your new vectors
3. Run mutation testing with BOTH combined
4. The delta between (1) and (3) shows the new vectors' value

---

## Phase 3: Baseline

Run mutation testing with existing test vectors only.

### Framework Selection

See [references/mutation-frameworks.md](references/mutation-frameworks.md)
for language-specific setup.

| Language | Framework | Command |
|----------|-----------|---------|
| Go | gremlins | `gremlins unleash ./path/to/package` |
| Rust | cargo-mutants | `cargo mutants -j N --timeout T` |
| Python | mutmut | `mutmut run --paths-to-mutate src/` |
| C/C++ | Mull | `mull-runner -test-framework=GoogleTest binary` |

### Parallelism

Always use parallel execution for large codebases:
- `cargo mutants -j 8` (Rust, 8 parallel workers)
- `gremlins unleash --timeout-coefficient 3` (Go, increase timeouts)
- `mutmut run --runner "pytest -x -q"` (Python, fail-fast)

### Recording Baseline Results

Capture these metrics per implementation:

| Metric | Description |
|--------|-------------|
| Total mutants | Number of mutations generated |
| Killed | Mutants caught by tests |
| Survived/Lived | Mutants NOT caught (these are the targets) |
| Not covered | Code paths no test reaches at all |
| Timed out | Ambiguous — resolve before comparing |
| Efficacy % | Killed / (Killed + Survived) |
| Coverage % | (Total - Not covered) / Total |

Save the full mutation log for Phase 4 analysis.

---

## Phase 4: Escape Analysis (Graph-Informed Triage)

Classify each escaped (survived + not covered) mutant using the
Trailmark call graph for reachability and blast radius analysis.

**This phase MUST use the genotoxic skill's triage methodology.**
The call graph transforms mutation results from a flat list of
survived mutants into an actionable, prioritized set of vector
targets.

### Step 1: Build the Call Graph

Build a Trailmark code graph for each implementation before
triaging mutations:

```bash
# Go
uv run trailmark analyze --language go --summary {targetDir}

# Rust
uv run trailmark analyze --language rust --summary {targetDir}
```

The graph provides:
- **Caller chains** — trace from public API entry points to
  mutated functions to determine reachability
- **Cyclomatic complexity** — prioritize high-CC functions
- **Blast radius** — functions with many callers have wider
  impact if their mutations survive

### Step 2: Filter to Relevant Code

Mutation frameworks test the entire package. Filter results to
only the files/functions that test vectors should exercise:

```bash
# Go (gremlins)
grep -E "(LIVED|NOT COVERED)" baseline.log \
  | grep -E " at (relevant|files)" \
  | sort

# Rust (cargo-mutants)
cat mutants.out/missed.txt | grep "src/relevant"
```

### Step 3: Graph-Informed Classification

For each escaped mutant, map it to its containing function in the
call graph and apply the genotoxic triage criteria:

| Graph Signal | Classification | Action |
|--------------|----------------|--------|
| No callers in graph | **False Positive** | Dead code, skip |
| Only test callers | **False Positive** | Test infrastructure |
| Logging/display/formatting | **False Positive** | Cosmetic |
| Cross-package callers but NOT COVERED | **Cross-Package Gap** | See below |
| Reachable from public API, low CC | **Missing Vector** | Design targeted vector |
| Reachable from public API, high CC (>10) | **Fuzzing Target** | Both vector + fuzz harness |
| Validation/error-handling path | **Negative Vector** | Craft invalid input that triggers path |
| Optimization path (GLV, SIMD, batch) | **Edge-Case Vector** | Input that triggers optimization threshold |
| `\|`→`^` after left shift (e.g. `(t<<1) \| carry`) | **Equivalent Mutant** | Skip — bit 0 always 0, OR=XOR |
| ct_eq `&`→`\|` on Montgomery limbs | **API-Unreachable** | Needs library-internal tests, not vectors |
| Equivalent mutation (behavior unchanged) | **False Positive** | Skip |

### Step 4: Identify Cross-Package Test Gaps

**Critical pitfall:** Mutation frameworks often only run tests
within the same package as the mutation. For Go (gremlins) and
Rust (cargo-mutants), this means:

- A mutation in `hash_to_curve/g2.go` only runs tests in the
  `hash_to_curve` package, NOT tests in the parent `bls12381`
  package that imports it
- Functions that are fully exercised by cross-package tests
  will appear as NOT COVERED — these are **false positives**
- To confirm: check if the mutated function is called from a
  test in a *different* package that wouldn't be run

To resolve cross-package gaps:
1. Add a thin test in the sub-package that calls through the
   same code path as the cross-package test
2. Or run gremlins with `--test-pkg ./...` (if supported)
3. Or document as a framework limitation in the report

### Step 5: Prioritize by Security Impact

Using the call graph, rank surviving mutants by impact:

| Priority | Criteria | Example |
|----------|----------|---------|
| **P0 — Critical** | Mutant weakens validation/equality/authentication | `ct_eq`: `&` → `\|` makes equality permissive |
| **P1 — High** | Mutant in deserialization flag parsing | `from_compressed`: `&` → `\|` accepts invalid flags |
| **P2 — Medium** | Mutant in field arithmetic internals | `Fp::square`: `\|` → `^` corrupts computation |
| **P3 — Low** | Mutant in optimization path | `phi` endomorphism: only affects performance path |
| **Skip** | Formatting, display, equivalent mutation | `Debug::fmt` return value replacement |

### Step 6: Group by Vector Strategy

Group escaped mutants by the code path they represent and the
type of test vector needed:

```
Deserialization flag validation (P1):
  - g1.rs:339,363-365,384 — from_compressed_unchecked flags
  → Need: valid-point-wrong-flag vectors

Field arithmetic (P2):
  - fp.rs:371-376,406,635-643 — subtract_p, neg, square
  → Need: field arithmetic KATs with edge-case values

Optimization thresholds (P3):
  - g1.go:68, g2.go:75 — GLV vs windowed multiplication
  → Need: scalar multiplication with large scalars

Cross-package (framework limitation):
  - hash_to_curve/g2.go:242-278 — isogeny, sgn0
  → Document as false positive or add sub-package test
```

Each group becomes a target for new test vectors in Phase 5.

---

## Phase 5: Vector Generation

For each escaped code path group, design test vectors that
force execution through that path.

### Vector Design Patterns

| Code Path Type | Vector Strategy |
|----------------|----------------|
| Point deserialization | Malformed points: wrong length, invalid field elements, off-curve, wrong subgroup, identity point |
| Signature verification | Valid sig + all single-bit corruptions of sig, pk, msg |
| Hash-to-curve | Known answer tests (KATs) with edge-case inputs: empty, single byte, max length |
| Aggregate operations | 1 signer, many signers, duplicate signers, mixed valid/invalid |
| Error handling | Every error path should have a vector that triggers it |
| Arithmetic edge cases | Zero, one, field modulus - 1, points at infinity |
| Serialization flags | Every valid flag combination + every invalid flag combination |
| Roundtrip integrity | For every valid deser vector, assert `serialize(deserialize(b)) == b` |
| Carry/reduction faults | Reimplement at reduced limb widths, inject faults, extract distinguishing inputs |

### Single-Fault Negative Vectors

Each negative vector should have **exactly one defect** with
everything else valid — this isolates which validation check is
being tested. See [references/vector-patterns.md](references/vector-patterns.md)
for per-flag construction examples.

### Fault Simulation (Limb-Width Reimplementation)

When mutation testing only applies local operator swaps, deeper
architectural bugs (carry propagation, reduction overflow) go
untested. To close this gap, reimplement the target algorithm
at reduced limb widths (8, 16, 25, 32 bits) and deliberately
inject faults — then generate vectors that catch them.

See [references/fault-simulation.md](references/fault-simulation.md)
for the full methodology: limb-width selection, fault injection
catalog, vector extraction, and validation workflow.

### Cross-Implementation Verification

Every new test vector MUST be verified against at least two
independent implementations before being added to the suite:

1. Generate the vector using implementation A
2. Verify with implementation B (different codebase, ideally different language)
3. If B disagrees, investigate — one implementation has a bug

### Vector Format

Use Wycheproof JSON format (`algorithm`, `testGroups[].tests[]`
with `tcId`, `comment`, `result`, `flags`). See
[references/vector-patterns.md](references/vector-patterns.md)
for the full schema.

**JSON encoding:** Wycheproof canonicalizes vectors with
`reformat_json.py`, which unescapes HTML entities. Generate vectors
with literal characters, not HTML-escaped sequences:

- **Go:** Use `json.NewEncoder` + `enc.SetEscapeHTML(false)` —
  never `json.Marshal`/`json.MarshalIndent`, which silently escape
  `>` → `\u003e`, `<` → `\u003c`, `&` → `\u0026`
- **Python:** `json.dumps` is safe by default
- **Node.js:** `JSON.stringify` is safe by default

See [references/lessons-learned.md](references/lessons-learned.md)
§14 for details.

---

## Phase 6: Validation

Re-run mutation testing with the new test vectors included.

**Tip:** Use per-file mutation testing for fast iteration during
vector development (see [references/lessons-learned.md](references/lessons-learned.md) §12).
Only run full-crate tests for the final comparison.

### Before/After Comparison

| Metric | Baseline | With New Vectors | Delta |
|--------|----------|------------------|-------|
| Killed | X | Y | Y - X |
| Survived | A | B | A - B (should decrease) |
| Not Covered | C | D | C - D (should decrease) |
| Efficacy % | E% | F% | F - E |

### Success Criteria

Vectors have both **retroactive** value (killing mutants in
existing code) and **proactive** value (catching bugs in future
implementations). Generate both kinds — boundary-condition vectors
may not improve kill rates in mature libraries but will catch bugs
in new implementations. See
[references/lessons-learned.md](references/lessons-learned.md) §13.

**Retroactive (measurable):** previously survived/uncovered mutants
become killed, no regressions.

**If kill rates don't change:** the implementation's own tests
likely already cover those paths. The vectors still add
cross-implementation verification value. Document which case
applies.

---

## Output Format

Write `VECTOR_FORGE_REPORT.md` covering: target algorithm,
implementations tested, baseline results, escape analysis,
new vectors generated, after results, before/after delta, and
conclusions. See
[references/report-template.md](references/report-template.md)
for the full template.

---

## Quality Checklist

Before delivering:

- [ ] At least one pure implementation mutation-tested (not just FFI wrappers)
- [ ] Baseline run completed with existing vectors
- [ ] Trailmark call graph built for each implementation
- [ ] All escaped mutants triaged using graph-informed classification
- [ ] Cross-package false positives identified and documented
- [ ] Security-critical mutations (ct_eq, validation, auth) prioritized as P0/P1
- [ ] Fault simulation and mutation-derived vectors cross-verified against 2+ implementations
- [ ] After run completed with new vectors included
- [ ] Before/after delta computed and explained
- [ ] Report written to `VECTOR_FORGE_REPORT.md`
- [ ] New test vectors saved in standard format (Wycheproof JSON)

---

## Integration

| Skill | Relationship |
|-------|-------------|
| **genotoxic** (required for Phase 4) | Provides graph-informed triage — call graph cuts actionable mutants by 30-50% |
| **mutation-testing** (mewt/muton) | Use for Solidity; Vector Forge is language-agnostic |
| **property-based-testing** | Better than hand-crafted vectors for bitwise mutations in field arithmetic |
| **testing-handbook-skills** (fuzzing) | Functions with CC > 10 and surviving mutants need both vectors and fuzz harnesses |

---

## Supporting Documentation

- **[references/mutation-frameworks.md](references/mutation-frameworks.md)** -
  Language-specific mutation testing framework setup
- **[references/vector-patterns.md](references/vector-patterns.md)** -
  Common test vector patterns for cryptographic primitives
- **[references/fault-simulation.md](references/fault-simulation.md)** -
  Limb-width reimplementation for carry, reduction, and overflow faults
- **[references/report-template.md](references/report-template.md)** -
  Full markdown template for the Vector Forge report
- **[references/lessons-learned.md](references/lessons-learned.md)** -
  BLS12-381 case study: FFI kill rates, timeout masking, cross-package
  false positives, bitwise mutation gaps, and security-critical priorities
