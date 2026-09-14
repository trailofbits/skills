# Mutation Testing Analysis Report

**Project:** Vault Fixture
**Repository:** `plugins/mutation-testing/evals/weak-suite-analysis/fixture`
**Analysis Date:** 2026-07-31
**Mutation Testing Tool:** mewt 4.0.0
**Analyzer:** Claude Code with mutation-testing skill

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total mutants generated | 29 |
| Mutants killed | 16 |
| Mutants survived | 8 |
| Equivalent mutants (false positives) | 2 |
| Real surviving mutants | 6 |
| Mutation kill rate (raw) | 66.7% |
| Adjusted kill rate (excluding equivalent) | 72.7% |

Rates are computed over the 24 tested mutants; 5 were skipped because a more
severe mutant on the same line was already uncaught.

### Key Findings

The `vault` crate's test suite verifies a single happy-path withdrawal and a
single non-zero balance query. Two thirds of tested mutants are caught, but the
survivors cluster in exactly the code that matters: every guard in `withdraw`
can be removed or short-circuited without a test failing.

The most severe gap is authorization. Both the removal of the `if !is_admin`
guard and the replacement of its condition with `false` survive, meaning no test
ever calls `withdraw` as a non-admin. The insufficient-funds guard has the same
shape of gap, allowing an over-withdrawal to pass unnoticed.

The suite needs negative-path tests before anything else: a non-admin caller and
an over-balance withdrawal. Both survivors on line 37 are equivalent mutants and
require no action.

### Severity Distribution

| Severity Tier | Count | Percentage of Real Survivors |
|---------------|-------|------------------------------|
| Critical (Security-Sensitive) | 2 | 33.3% |
| High (Financial/State Integrity) | 2 | 33.3% |
| Medium (Business Logic) | 0 | 0% |
| Low (Observability) | 2 | 33.3% |

---

## Equivalent Mutants (False Positives)

An equivalent mutant changes the source without changing behavior for any
possible input, so no test can kill it. Two of the eight survivors qualify, both
on line 37.

| # | File | Line | Mutation | Equivalence Reason |
|---|------|------|----------|-------------------|
| 1 | `src/lib.rs` | 37 | `balance > 0` → `balance != 0` | `balance` is a `u64`. Zero is the only unsigned value that is not greater than zero, so the two expressions agree on every input in the type's domain. No distinguishing test exists. |
| 2 | `src/lib.rs` | 37 | `balance > 0` → `balance >= 0` | `balance` is an unsigned `u64`, so `balance >= 0` is a tautological bound check — an unsigned integer is always greater than or equal to zero. This matches the documented tautological-bound-check pattern for unsigned types. |

---

## Tier 1: Critical — Security-Sensitive Findings

Two survivors remove the only authorization check in the crate.

### Finding C-1: Authorization guard can be deleted entirely

**File:** `src/lib.rs`
**Line:** 24
**Mutation:** `if !is_admin { return Err(VaultError::Unauthorized); }` → commented out
**Mutation Operator:** CR (Comment Replacement)

**Context:**
This guard is the sole access control on `withdraw`. With it removed, any caller
withdraws regardless of the `is_admin` argument.

**Responsible test file(s):** `tests/vault.rs`
**Relevant test case(s):** `admin_can_withdraw`

**Why this was not caught:**
The only test of `withdraw` passes `true` for `is_admin` and asserts the
returned balance. Deleting a guard that the test never triggers cannot change
that test's outcome. No test constructs the unauthorized case at all, so the
`VaultError::Unauthorized` variant is never observed.

**Recommended test improvement:**
Add a test that calls `withdraw` with `is_admin` set to false and asserts the
result is `Err(VaultError::Unauthorized)`. Assert additionally that the
account's balance is unchanged, so a guard that returns the error but still
mutates state is also caught.

---

### Finding C-2: Authorization condition can be forced false

**File:** `src/lib.rs`
**Line:** 24
**Mutation:** `if !is_admin {` → `if false {`
**Mutation Operator:** IF (If False)

**Context:**
Short-circuiting the condition makes the guard unreachable, which is
behaviorally identical to deleting it while leaving the code visibly present.

**Responsible test file(s):** `tests/vault.rs`
**Relevant test case(s):** `admin_can_withdraw`

**Why this was not caught:**
Same root cause as C-1: the non-admin branch is never entered by any test, so
neither branch of the condition is discriminated. That both `CR` and `IF`
survive on this line confirms the branch is entirely uncovered rather than
weakly asserted.

**Recommended test improvement:**
The non-admin test described in C-1 kills this mutant as well. Cover both
`is_admin` values so the condition itself, not just one of its outcomes, is
exercised.

---

## Tier 2: High — Financial/State Integrity Findings

Two survivors remove the balance check that prevents over-withdrawal.

### Finding H-1: Insufficient-funds guard can be deleted

**File:** `src/lib.rs`
**Line:** 27
**Mutation:** `if amount > account.balance { return Err(VaultError::InsufficientFunds); }` → commented out
**Mutation Operator:** CR (Comment Replacement)

**Context:**
This guard prevents `account.balance -= amount` from underflowing. Without it a
withdrawal larger than the balance panics in debug builds and wraps in release
builds, producing an enormous balance.

**Responsible test file(s):** `tests/vault.rs`
**Relevant test case(s):** `admin_can_withdraw`

**Why this was not caught:**
The single withdrawal test takes 40 from a balance of 100, staying well inside
the guard. No test requests more than the available balance, so the error path
and the underflow it prevents are both untested.

**Recommended test improvement:**
Add a test withdrawing more than the balance and assert
`Err(VaultError::InsufficientFunds)` together with an unchanged balance. Add a
boundary case withdrawing exactly the full balance and assert it succeeds with a
resulting balance of zero, which pins the `>` in the comparison.

---

### Finding H-2: Insufficient-funds condition can be forced false

**File:** `src/lib.rs`
**Line:** 27
**Mutation:** `if amount > account.balance {` → `if false {`
**Mutation Operator:** IF (If False)

**Context:**
Makes the funds guard unreachable, with the same consequence as deleting it.

**Responsible test file(s):** `tests/vault.rs`
**Relevant test case(s):** `admin_can_withdraw`

**Why this was not caught:**
The over-withdrawal branch is never entered, so forcing the condition to a
constant is indistinguishable from the original under the current suite.

**Recommended test improvement:**
Covered by the over-balance test in H-1.

---

## Tier 4: Low — Observability Findings

Two survivors remove logging without affecting control flow.

### Finding L-1: Withdrawal record call can be deleted

**File:** `src/lib.rs`
**Line:** 31
**Mutation:** `record_withdrawal(amount);` → commented out
**Mutation Operator:** CR (Comment Replacement)

**Context:**
`record_withdrawal` emits an audit line for each withdrawal. Removing the call
silently drops the audit trail while withdrawals continue to succeed.

**Responsible test file(s):** `tests/vault.rs`
**Relevant test case(s):** `admin_can_withdraw`

**Why this was not caught:**
`admin_can_withdraw` asserts only the returned balance. The call's sole effect
is on stderr, which no test captures, so its absence is invisible.

**Recommended test improvement:**
Refactor the recording side effect behind a collaborator the test can observe —
a trait object or a callback the test substitutes — and assert it receives the
withdrawn amount once per successful withdrawal. Until then this gap cannot be
closed by an assertion alone.

---

### Finding L-2: Audit log line can be deleted

**File:** `src/lib.rs`
**Line:** 41
**Mutation:** `eprintln!("withdrew {amount}");` → commented out
**Mutation Operator:** CR (Comment Replacement)

**Context:**
The body of `record_withdrawal`. Removing it empties the function while leaving
its call site intact.

**Responsible test file(s):** `tests/vault.rs`
**Relevant test case(s):** none — no test exercises `record_withdrawal` directly.

**Why this was not caught:**
No test observes stderr, so the function's only observable behavior is
unverified. This is the same gap as L-1 seen one frame deeper.

**Recommended test improvement:**
Addressed by the same refactor as L-1. Once the sink is injectable, assert on
the recorded amount rather than on the formatted string.

---

## Recommendations

**`tests/vault.rs`** carries every finding in this report.

- Add a non-admin withdrawal test asserting `Err(VaultError::Unauthorized)` and
  an unchanged balance (C-1, C-2).
- Add an over-balance withdrawal test asserting
  `Err(VaultError::InsufficientFunds)` and an unchanged balance, plus an
  exact-balance withdrawal that succeeds (H-1, H-2).
- Make the withdrawal record observable and assert on it (L-1, L-2). This is a
  source change rather than a test-only change and should be scheduled
  separately.

---

## Appendix

### Input Files Analyzed

- `fixture/mewt-results.json` — 8 uncaught mutants
- `fixture/mewt-status.txt` — campaign totals

### Source Files with Surviving Mutants

| File | Total Surviving | Critical | High | Medium | Low |
|------|----------------|----------|------|--------|-----|
| `src/lib.rs` | 8 | 2 | 2 | 0 | 2 |

Two further survivors on `src/lib.rs` are the equivalent mutants on line 37 and
are excluded from the tier counts.

### Methodology

This analysis follows Trail of Bits' mutation testing analysis methodology.
Surviving mutants are classified by the impact type of the mutated code, not by
the mutation operator used. Equivalent mutants are identified through
type-system analysis and reachability checks.
