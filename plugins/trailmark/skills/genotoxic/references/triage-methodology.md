# Triage Methodology

Detailed criteria for classifying survived mutants into actionable buckets.

## Contents

- False positive detection
- Missing test coverage identification
- Fuzzing target selection
- Edge cases and ambiguous mutants
- Worked examples
- Necessist removal triage

---

## False Positive Detection

A mutant is a false positive when killing it would not improve code
quality or catch real bugs. Classify as false positive when ANY of
these conditions hold:

### Dead Code

The mutated function has zero callers in the trailmark graph.

```python
callers = engine.callers_of(node_id)
if not callers:
    # Dead code. The mutant is unreachable in production.
    # Action: flag function for removal, not testing.
```

**Subtlety:** A function with no *direct* callers may still be reachable
via dynamic dispatch (reflection, callbacks, decorators). Check edge
confidence: if all edges to the function are `uncertain`, investigate
before dismissing.

### Test-Only Code

The function is only called from test files.

```python
callers = engine.callers_of(node_id)
prod_callers = [
    c for c in callers
    if "test" not in c["location"]["file_path"].lower()
]
if not prod_callers:
    # Only tests call this. Mutant in test infrastructure.
```

### Equivalent Mutants

The mutation produces identical behavior. Common patterns:

| Mutation | Why Equivalent |
|----------|---------------|
| `x > 0` → `x >= 1` | Identical for integers |
| `x != 0` → `x > 0` | Identical for unsigned types |
| `return x` → `return +x` | Unary plus is a no-op |
| String literal change in log message | No behavioral impact |
| Reorder of commutative operations | `a + b` == `b + a` |

**Detection strategy:** Check if the mutation is in a logging call,
display string, comment-adjacent code, or assertion message. These
are cosmetic and do not affect program behavior.

### Redundant Checks

The mutation weakens a condition, but another check in the same call
path enforces the same constraint:

```python
# Caller validates x > 0 before calling this function.
# Mutating this function's own x > 0 check is redundant.
callers = engine.callers_of(node_id)
# Inspect caller source for equivalent preconditions.
```

Use trailmark annotations to track this:

```python
from trailmark.models import AnnotationKind

engine.annotate(
    node_id,
    AnnotationKind.PRECONDITION,
    "x > 0 enforced by all callers",
    source="llm",
)
```

---

## Missing Test Coverage

A mutant indicates missing test coverage when:

1. The function is reachable in production (has callers)
2. The mutated behavior *should* be caught by tests
3. A unit test is the appropriate testing strategy

### Criteria

| Signal | Why Unit Test | Priority |
|--------|--------------|----------|
| Pure function, no side effects | Deterministic, easy to test | HIGH |
| Low CC (<5) | Few paths to cover | HIGH |
| Error/exception handling path | Negative tests needed | HIGH |
| Boundary condition (off-by-one) | Property-based test | MEDIUM |
| Return value mutation | Assert on return values | MEDIUM |
| State transition logic | State machine tests | MEDIUM |
| Configuration/flag handling | Parameter variation tests | LOW |

### Suggested Test Types

Map the mutation type to a test strategy:

| Mutation Type | Suggested Test |
|---------------|---------------|
| Arithmetic operator (`+` → `-`) | Value assertion on known inputs |
| Comparison operator (`<` → `<=`) | Boundary value test |
| Boolean negation (`True` → `False`) | Branch coverage test |
| Return value (`return x` → `return None`) | Return value assertion |
| Removed statement | Side effect verification |
| Exception removal | Negative test (expect failure) |

### When to Prefer Property-Based Testing

If the survived mutant involves:

- Serialization/deserialization (roundtrip property)
- Idempotent operations (applying twice = applying once)
- Ordering invariants (sorted output)
- Numeric ranges or bounds

Use the **property-based-testing** skill for guidance.

---

## Fuzzing Target Selection

A survived mutant is a fuzzing target when unit testing alone is
insufficient due to complexity, input space, or exposure to untrusted
data.

### Criteria

| Signal | Threshold | Why Fuzzing |
|--------|-----------|-------------|
| Cyclomatic complexity | CC > 10 | Too many paths for manual tests |
| Entrypoint reachable | Any path from untrusted input | Attacker-controlled data |
| Caller count | > 10 callers | High blast radius |
| Input parsing | Handles structured data | Fuzzers generate diverse inputs |
| Binary/wire protocol | Processes byte sequences | Coverage-guided exploration |
| Recursive logic | Processes nested structures | Depth/stack exhaustion |
| State machine | Multiple state transitions | State space exploration |

### Prioritization

Combine signals for priority assignment:

```
CRITICAL: Entrypoint reachable + CC > 15 + parser/validator
HIGH:     Entrypoint reachable + CC > 10
HIGH:     CC > 10 + caller count > 20
MEDIUM:   CC > 10 OR (entrypoint reachable + caller count > 10)
LOW:      Moderate complexity, not entrypoint reachable
```

### Framework Selection

Based on target language, recommend the appropriate fuzzer:

| Language | Fuzzer | Skill Reference |
|----------|--------|-----------------|
| Python | Atheris | `testing-handbook-skills:atheris` |
| Rust | cargo-fuzz | `testing-handbook-skills:cargo-fuzz` |
| C/C++ | libFuzzer or AFL++ | `testing-handbook-skills:libfuzzer` |
| Go | go-fuzz (native) | Built-in `go test -fuzz` |
| Ruby | Ruzzy | `testing-handbook-skills:ruzzy` |
| Java | Jazzer | JUnit integration |
| JavaScript | jsfuzz | npm package |

---

## Edge Cases and Ambiguous Mutants

Some mutants don't cleanly fit one bucket. Resolution rules:

### Mutant in Validation Code

If the mutant weakens input validation:

- **Entrypoint reachable?** → Fuzzing target (attacker can exploit)
- **Internal only?** → Missing test (regression risk)

### Mutant in Error Path

If the mutant changes error handling behavior:

- **Error path tested?** → Check if test expects specific error
- **Error path untested?** → Missing test (negative test case)
- **Error in parser?** → Fuzzing target (malformed input testing)

### Mutant Straddles Complexity Threshold

CC is near the threshold (8-12 range):

- **Has entrypoint path?** → Fuzzing target (exposure wins)
- **No entrypoint path?** → Missing test (unit test is feasible)

### Tie-Breaking Rule

When signals conflict, prefer the higher-assurance category:

```
Fuzzing Target > Missing Test > False Positive
```

A function that *could* be unit tested but is also entrypoint-reachable
and complex should be fuzzed. Fuzzing subsumes the unit test goal while
providing broader coverage.

---

## Worked Example

**Scenario:** Python web application, `mutmut` reports 47 survived mutants.

**Graph context (from trailmark):**
- 312 nodes, 1,847 edges
- 8 entrypoints (Flask route handlers)
- 14 functions with CC > 10

**Triage results:**

| Category | Count | Examples |
|----------|-------|---------|
| False Positive | 12 | 5 logging strings, 3 dead utils, 4 equivalent |
| Missing Tests | 23 | 8 error paths, 7 return values, 5 boundary, 3 config |
| Fuzzing Targets | 12 | 4 request parsers, 3 validators, 3 query builders, 2 serializers |

**Key decisions:**
- `parse_query_params` (CC=14, entrypoint-reachable via `/search`) → **Fuzzing**
- `format_error_response` (CC=3, 2 callers, string formatting) → **False positive** (cosmetic)
- `validate_email` (CC=6, 4 callers, no entrypoint path) → **Missing test** (boundary cases)
- `build_sql_filter` (CC=12, entrypoint-reachable via `/api/filter`) → **Fuzzing** (injection risk)

---

## Necessist Removal Triage

Necessist findings differ from mutation testing: they identify test
statements whose removal doesn't cause test failure. Triage maps each
removal to a production function using the graph analysis algorithm
and then classifies it.

### False Positive Detection (Necessist)

Classify a necessist removal as false positive when:

| Signal | Reason |
| ------ | ------ |
| Redundant setup | Same call made elsewhere in the test or fixture |
| Debug/logging call | `println`, `console.log`, `dbg!` in test code |
| Teardown/cleanup | Removal of resource cleanup that doesn't affect assertions |
| Dead production code | Production function has no callers in graph |
| Unmappable statement | Cannot identify which production function is exercised |

### Missing Test Coverage (Necessist)

A removal indicates missing coverage when the test *should* fail but
doesn't — meaning the test has weak or missing assertions:

| Signal | Action |
| ------ | ------ |
| Function call removed, no assertion checks its effect | Add assertion on the function's return value or side effect |
| Assertion removed, remaining assertions still pass | The removed assertion covered unique behavior — restore and strengthen |
| Setup step removed with no downstream impact | Setup should affect test outcome; add assertions that depend on it |
| State mutation removed, test still passes | Test doesn't verify state changes — add state assertions |

### Fuzzing Target Selection (Necessist)

After mapping to a production function, apply the same graph-based
criteria as mutation testing:

- CC > 10 and entrypoint reachable → **Fuzzing Target**
- High blast radius and CC > 5 → **Fuzzing Target**
- On a privilege boundary → **Fuzzing Target**

The reasoning is identical: if a production function is complex, exposed,
and its test coverage is demonstrably weak (necessist proved a test
statement was unnecessary), fuzzing is the appropriate response.

### Edge Cases (Necessist)

**Async/await removals:** Removing an `await` may cause a test to pass
because the assertion runs before the async operation completes. This
is a genuine test weakness (race condition in test), not a false positive.
Classify as missing test coverage — the test needs to properly await
and assert.

**Macro expansions (Foundry/Anchor):** Cheatcodes like `vm.prank`,
`vm.expectRevert`, `vm.warp` are setup-critical. If removing one causes
the test to still pass, the test likely doesn't exercise the behavior
the cheatcode was supposed to enable. Classify as missing test coverage
unless the cheatcode is purely cosmetic (`vm.label`).

**Chained method calls:** `foo.bar().baz()` — necessist may remove
the entire chain. Map to the outermost call (`foo.bar`) for triage.
If the chain involves multiple production functions, triage against
the one with highest blast radius.

**Solidity `assert` vs `require`:** Removing a `require` check in a
test helper is different from removing an `assert` in a test body.
`require` removals in test helpers are usually false positives (guard
conditions). `assert` removals in test bodies are missing coverage.

### Worked Example: Foundry Project

**Scenario:** Foundry DeFi lending protocol, necessist reports 31
removals that passed.

**Graph context (from trailmark):**
- 89 nodes, 412 edges
- 5 entrypoints (external functions)
- 6 functions with CC > 10

**Triage results:**

| Category | Count | Examples |
| -------- | ----- | ------- |
| False Positive | 8 | 3 `vm.label` calls, 2 `console.log`, 3 redundant `vm.deal` |
| Missing Tests | 16 | 5 missing return value checks, 4 state assertions, 4 event assertions, 3 removed `assertEq` with redundant coverage |
| Fuzzing Targets | 7 | 3 liquidation path functions, 2 interest calculation, 2 oracle price handling |

**Key decisions:**
- `calculateInterest` (CC=11, reachable via `borrow()`) → **Fuzzing** — test removed `assertApproxEqRel` and still passed, meaning the interest calculation has untested edge cases in a complex, exposed function
- `vm.label(address(pool), "pool")` → **False positive** — cosmetic labeling for trace output
- `assertEq(token.balanceOf(user), expectedBalance)` removed and test passes → **Missing test** — the balance check was the only assertion verifying the transfer succeeded
