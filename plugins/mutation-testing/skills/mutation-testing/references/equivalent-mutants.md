# Equivalent Mutant Catalog

Equivalent mutants are mutations that produce semantically identical behavior to the original code. They are false positives in mutation testing: no test can kill them because no observable difference exists. Correctly identifying equivalent mutants prevents inflating the count of real testing gaps.

This file covers general equivalence checks and patterns. Blockchain-specific equivalence patterns are loaded separately by `SKILL.md` for blockchain projects.

## Verification Procedure

Before classifying a mutant as equivalent, complete all five checks:

1. **Type context**: Determine the types of all variables involved in the mutation. Unsigned integers, booleans, and enums each have specific equivalence patterns
2. **Reachability**: Confirm that the mutated code is actually reachable during execution. Mutations in dead code are trivially equivalent
3. **Downstream consumption**: Trace whether the mutated value is read or used by any subsequent logic. If the value is never consumed, the mutation has no observable effect
4. **Semantic comparison**: Compare the behavior of original and mutated code across all possible inputs within the type constraints. If no input produces a different result, the mutant is equivalent
5. **Distinguishing test attempt**: Try to construct a concrete input that produces different behavior between the original and mutated code. If such an input exists, the mutant is not equivalent — describe the input as a recommended test case. If no distinguishing input can be found after checking boundary values, type extremes, and domain-specific edge cases, this strengthens the equivalence classification

A mutant is equivalent only when the analysis establishes identical observable behavior. If a check is uncertain, retain it as unresolved and explain what evidence is missing. Uncertainty alone does not establish a testing gap.

---

## Semantic Equivalence Patterns

### Unsigned Comparison Equivalence

**Pattern:** `x > 0` mutated to `x != 0` (or vice versa)
**Why equivalent:** For unsigned integers, the only value that is not greater than zero is zero itself. Therefore `x > 0` and `x != 0` produce identical results for all possible unsigned values.
**Applies to:** Any unsigned integer type (Rust `u8`-`u128`/`usize`, C/C++ `unsigned`, Solidity `uint`, FunC/Tolk integers when used as unsigned)

**Not equivalent when:** The variable is a signed type. For signed integers, `x > 0` excludes negative values while `x != 0` includes them.

### Boolean Double-Negation

**Pattern:** `!(!condition)` mutated to `condition`
**Why equivalent:** Double negation of a boolean produces the original value. These expressions are logically identical.
**Applies to:** All languages

### Tautological Bound Checks

**Pattern:** `x >= 0` for an unsigned integer, mutated to `true`
**Why equivalent:** Both expressions are true for every value of the unsigned type, provided evaluating `x` has no observable side effects.
**Applies to:** Any unsigned integer type (Rust unsigned types, C/C++ `unsigned`, Solidity `uint`)

**Not equivalent when:** The replacement is `x > 0`. At `x == 0`, the original returns true and the replacement returns false. Zero is reachable for an unsigned type unless the surrounding code excludes it. Signed types and comparisons such as `x >= 1` also require a separate analysis.

### Dead Code Mutations

**Pattern:** Any mutation inside an unreachable branch
**Why equivalent:** If the code path is never executed, no mutation within it can produce an observable difference.
**How to verify:** Check whether the branch condition can ever be true. Common cases: `if (false)`, branches after unconditional `return`/`revert`, code guarded by compile-time constants that always evaluate one way.

**Caution:** A branch that is not exercised by current tests is not necessarily unreachable. Distinguish between "no test covers this" (real finding) and "no input can reach this" (equivalent).

### Redundant Assignment Mutations

**Pattern:** Mutation to a variable that is never read after the assignment
**Why equivalent:** If the variable's value is not consumed by any subsequent operation, changing the assigned value has no effect on program behavior.
**How to verify:** Trace all uses of the variable after the mutated assignment. If no read occurs before the variable is reassigned or goes out of scope, the mutation is equivalent.

### Commutative Operation Reordering

**Pattern:** `a + b` mutated to `b + a`, or `a * b` mutated to `b * a`
**Why equivalent:** Addition and multiplication are commutative. The operand order does not affect the result.
**Applies to:** Built-in integer operations with pure operands and the same types. Inspect overloaded operators and floating-point semantics separately, including observable NaN representations and floating-point exceptions.

**Not equivalent when:** The operation has side effects (e.g., function calls as operands with observable side effects), or the operation is non-commutative (subtraction, division, modulo).

---

## Common Mistakes in Equivalence Classification

These patterns look equivalent but are NOT. Do not classify them as false positives:

### Boundary Value Changes

**Pattern:** `>` mutated to `>=` (or vice versa)
**Why NOT equivalent:** The boundary value (where `x == threshold`) produces a different result. This is a real finding unless the boundary value is provably unreachable.
**Common error:** Assuming that because current tests do not exercise the boundary, it is unreachable. Unreachability must be proven from the type system or control flow, not from test coverage.

### Off-by-One in Loop Bounds

**Pattern:** `i < length` mutated to `i <= length` in a loop
**Why NOT equivalent:** The loop executes one additional iteration, which may access out-of-bounds memory or process an extra element. This is a real finding.

### Removed Event Emission

**Pattern:** `emit Transfer(from, to, amount)` commented out
**Why NOT equivalent in all cases:** While event removal does not change execution logic, it may break downstream monitoring, indexing services, or integration tests that rely on events. Classify as Tier 4 (Low), not as equivalent.

### Swapped Non-Commutative Operations

**Pattern:** `a - b` mutated to `b - a`, or `a / b` mutated to `b / a`
**Why NOT equivalent:** Subtraction and division are not commutative. The results differ unless `a == b`.

### Undefined Behavior Introduction (C/C++)

**Pattern:** Mutation changes a bounds check, pointer operation, or integer arithmetic in a way that introduces undefined behavior (e.g., signed overflow, buffer overrun, null dereference)
**Why NOT equivalent:** The mutation may produce identical test output today, but undefined behavior can manifest differently under other compilers, optimization levels, or platforms. UB-introducing mutations represent real safety bugs regardless of current test results.
**Common error:** Observing that all tests still pass and concluding the mutation is equivalent. In C/C++, UB can silently corrupt memory, be optimized away, or cause crashes only under specific conditions.
