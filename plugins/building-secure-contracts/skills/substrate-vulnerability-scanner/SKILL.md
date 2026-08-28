---
name: substrate-vulnerability-scanner
description: Scans Substrate/Polkadot pallets for 7 critical vulnerabilities including arithmetic overflow, panic DoS, incorrect weights, and bad origin checks. Use when auditing Substrate runtimes or FRAME pallets.
---

# Substrate Vulnerability Scanner

## 1. Purpose

Systematically scan Substrate runtime modules (pallets) for platform-specific security vulnerabilities that can cause node crashes, DoS attacks, or unauthorized access. This skill encodes 7 critical vulnerability patterns unique to Substrate/FRAME-based chains.

## 2. When to Use This Skill

- Auditing custom Substrate pallets
- Reviewing FRAME runtime code
- Pre-launch security assessment of Substrate chains (Polkadot parachains, standalone chains)
- Validating dispatchable extrinsic functions
- Reviewing weight calculation functions
- Assessing unsigned transaction validation logic

## 3. Platform Detection

### File Extensions & Indicators
- **Rust files**: `.rs`

### Language/Framework Markers
```rust
// Substrate/FRAME indicators
#[pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config { }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(10_000)]
        pub fn example_function(origin: OriginFor<T>) -> DispatchResult { }
    }
}

// Common patterns
DispatchResult, DispatchError
ensure!, ensure_signed, ensure_root
StorageValue, StorageMap, StorageDoubleMap
#[pallet::storage]
#[pallet::call]
#[pallet::weight]
#[pallet::validate_unsigned]
```

### Project Structure
- `pallets/*/lib.rs` - Pallet implementations
- `runtime/lib.rs` - Runtime configuration
- `benchmarking.rs` - Weight benchmarks
- `Cargo.toml` with `frame-*` dependencies

### Tool Support
- **cargo-fuzz**: Fuzz testing for Rust
- **test-fuzz**: Property-based testing framework
- **benchmarking framework**: Built-in weight calculation
- **try-runtime**: Runtime migration testing

---

## 4. How This Skill Works

When invoked, I will:

1. **Search your codebase** for Substrate pallets
2. **Analyze each pallet** for the 7 vulnerability patterns
3. **Report findings** with file references and severity, above them a coverage table carrying a verdict for every pattern
4. **Provide fixes** for each identified issue
5. **Check weight calculations** and origin validation

---

## 5. Vulnerability Patterns (7 Critical Patterns)

I check for 7 critical vulnerability patterns unique to Substrate/FRAME. For detailed detection patterns, code examples, mitigations, and testing strategies, see [VULNERABILITY_PATTERNS.md](resources/VULNERABILITY_PATTERNS.md).

### Pattern Summary:

1. **Arithmetic Overflow** ⚠️ CRITICAL
   - Direct `+`, `-`, `*`, `/` operators wrap in release mode
   - Must use `checked_*` or `saturating_*` methods
   - Affects balance/token calculations, reward/fee math

2. **Don't Panic** ⚠️ CRITICAL - DoS
   - Panics cause node to stop processing blocks
   - No `unwrap()`, `expect()`, array indexing without bounds check
   - All user input must be validated with `ensure!`

3. **Weights and Fees** ⚠️ CRITICAL - DoS
   - Incorrect weights allow spam attacks
   - Fixed weights for variable-cost operations enable DoS
   - Must use benchmarking framework, bound all input parameters

4. **Verify First, Write Last** ⚠️ HIGH (Pre-v0.9.25)
   - Storage writes before validation persist on error (pre-v0.9.25)
   - Pattern: validate → write → emit event
   - Upgrade to v0.9.25+ or use manual `#[transactional]`

5. **Unsigned Transaction Validation** ⚠️ HIGH
   - Insufficient validation allows spam/replay attacks
   - Prefer signed transactions
   - If unsigned: validate parameters, replay protection, authenticate source

6. **Bad Randomness** ⚠️ MEDIUM
   - `pallet_randomness_collective_flip` vulnerable to collusion
   - Must use BABE randomness (`pallet_babe::RandomnessFromOneEpochAgo`)
   - Use `random(subject)` not `random_seed()`

7. **Bad Origin** ⚠️ CRITICAL
   - `ensure_signed` allows any user for privileged operations
   - Must use `ensure_root` or custom origins (ForceOrigin, AdminOrigin)
   - Origin types must be properly configured in runtime

For complete vulnerability patterns with code examples, see [VULNERABILITY_PATTERNS.md](resources/VULNERABILITY_PATTERNS.md).

---

## 6. Scanning Workflow

### Step 1: Platform Identification
1. Verify Substrate/FRAME framework usage
2. Check Substrate version (v0.9.25+ has transactional storage)
3. Locate pallet implementations (`pallets/*/lib.rs`)
4. Identify runtime configuration (`runtime/lib.rs`)

### Step 2: Dispatchable Analysis
For each `#[pallet::call]` function:
- [ ] Arithmetic: Uses checked/saturating operations?
- [ ] Panics: No unwrap/expect/indexing?
- [ ] Weights: Proportional to cost, bounded inputs?
- [ ] Origin: Appropriate validation level?
- [ ] Validation: All checks before storage writes?

### Step 3: Panic Sweep
```bash
# Search for panic-prone patterns
rg "unwrap\(\)" pallets/
rg "expect\(" pallets/
rg "\[.*\]" pallets/  # Array indexing
rg " as u\d+" pallets/  # Type casts
rg "\.unwrap_or" pallets/
```

### Step 4: Arithmetic Safety Check
```bash
# Find direct arithmetic
rg " \+ |\+=| - |-=| \* |\*=| / |/=" pallets/

# Should find checked/saturating alternatives instead
rg "checked_add|checked_sub|checked_mul|checked_div" pallets/
rg "saturating_add|saturating_sub|saturating_mul" pallets/
```

### Step 5: Weight Analysis
- [ ] Run benchmarking: `cargo test --features runtime-benchmarks`
- [ ] Verify weights match computational cost
- [ ] Check for bounded input parameters
- [ ] Review weight calculation functions

### Step 6: Origin & Privilege Review
```bash
# Find privileged operations
rg "ensure_signed" pallets/ | grep -E "pause|emergency|admin|force|sudo"

# Should use ensure_root or custom origins
rg "ensure_root|ForceOrigin|AdminOrigin" pallets/
```

### Step 7: Testing Review
- [ ] Unit tests cover all dispatchables
- [ ] Fuzz tests for panic conditions
- [ ] Benchmarks for weight calculation
- [ ] try-runtime tests for migrations

### Step 8: Report Coverage

Report on every pattern in §5, whether or not it turned anything up. This skill has no Finding Template, so the
table opens the report and the findings follow it, with all 7 rows present:

| # | Pattern | Verdict | Evidence |
|---|---------|---------|----------|
| 1 | Arithmetic Overflow | `found` | `src/lib.rs:212` -- `+` on `BalanceOf<T>` in `do_transfer` |
| 2 | Don't Panic | | |
| 3 | Weights and Fees | | |
| 4 | Verify First, Write Last | | |
| 5 | Unsigned Transaction Validation | | |
| 6 | Bad Randomness | | |
| 7 | Bad Origin | | |

Each verdict is one of:

- **`found`** — cite `file:line` and write the finding up in full after the table.
- **`clear`** — the pattern applies to this pallet and the pallet handles it. Name the macro, origin check, or
  arithmetic method you searched for, so a reader can repeat the search.
- **`n/a`** — the pattern cannot apply here. Give the reason in one clause ("this pallet accepts no unsigned
  transactions"). Not having looked is not `n/a`. Note that pattern 4 is version-scoped (pre-v0.9.25): say
  which runtime version the pallet targets rather than dropping the row.

A table with fewer than 7 rows is an incomplete scan and must be reported as one. A row whose Verdict cell is empty is incomplete in the same way: row 1 above is filled in to show the shape, and every row is filled in the same way before the report is done. Seven `clear` verdicts is a
result a reader can act on. A report that covers three patterns and says nothing about the other four reads
exactly like a clean pallet, and that is the failure this table exists to prevent.

---

## 7. Priority Guidelines

### Critical (Immediate Fix Required)
- Arithmetic overflow (token creation, balance manipulation)
- Panic DoS (node crash risk)
- Bad origin (unauthorized privileged operations)

### High (Fix Before Launch)
- Incorrect weights (DoS via spam)
- Verify-first violations (state corruption, pre-v0.9.25)
- Unsigned validation issues (spam, replay attacks)

### Medium (Address in Audit)
- Bad randomness (manipulation possible but limited impact)

---

## 8. Testing Recommendations

### Fuzz Testing
```rust
// Use test-fuzz for property-based testing
#[cfg(test)]
mod tests {
    use test_fuzz::test_fuzz;

    #[test_fuzz]
    fn fuzz_transfer(from: AccountId, to: AccountId, amount: u128) {
        // Should never panic
        let _ = Pallet::transfer(from, to, amount);
    }

    #[test_fuzz]
    fn fuzz_no_panics(call: Call) {
        // No dispatchable should panic
        let _ = call.dispatch(origin);
    }
}
```

### Benchmarking
```bash
# Run benchmarks to generate weights
cargo build --release --features runtime-benchmarks
./target/release/node benchmark pallet \
    --chain dev \
    --pallet pallet_example \
    --extrinsic "*" \
    --steps 50 \
    --repeat 20
```

### try-runtime
```bash
# Test runtime upgrades
cargo build --release --features try-runtime
try-runtime --runtime ./target/release/wbuild/runtime.wasm \
    on-runtime-upgrade live --uri wss://rpc.polkadot.io
```

---

## 9. Additional Resources

- **Building Secure Contracts**: `building-secure-contracts/not-so-smart-contracts/substrate/`
- **Substrate Documentation**: https://docs.substrate.io/
- **FRAME Documentation**: https://paritytech.github.io/substrate/master/frame_support/
- **test-fuzz**: https://github.com/trailofbits/test-fuzz
- **Substrate StackExchange**: https://substrate.stackexchange.com/

---

## 10. Quick Reference Checklist

Before completing Substrate pallet audit:

**Arithmetic Safety (CRITICAL)**:
- [ ] No direct `+`, `-`, `*`, `/` operators in dispatchables
- [ ] All arithmetic uses `checked_*` or `saturating_*`
- [ ] Type conversions use `try_into()` with error handling

**Panic Prevention (CRITICAL)**:
- [ ] No `unwrap()` or `expect()` in dispatchables
- [ ] No direct array/slice indexing without bounds check
- [ ] All user inputs validated with `ensure!`
- [ ] Division operations check for zero divisor

**Weights & DoS (CRITICAL)**:
- [ ] Weights proportional to computational cost
- [ ] Input parameters have maximum bounds
- [ ] Benchmarking used to determine weights
- [ ] No free (zero-weight) expensive operations

**Access Control (CRITICAL)**:
- [ ] Privileged operations use `ensure_root` or custom origins
- [ ] `ensure_signed` only for user-level operations
- [ ] Origin types properly configured in runtime
- [ ] Sudo pallet removed before production

**Storage Safety (HIGH)**:
- [ ] Using Substrate v0.9.25+ OR manual `#[transactional]`
- [ ] Validation before storage writes
- [ ] Events emitted after successful operations

**Other (MEDIUM)**:
- [ ] Unsigned transactions use signed alternative if possible
- [ ] If unsigned: proper validation, replay protection, authentication
- [ ] BABE randomness used (not RandomnessCollectiveFlip)
- [ ] Randomness uses `random(subject)` not `random_seed()`

**Testing**:
- [ ] Unit tests for all dispatchables
- [ ] Fuzz tests to find panics
- [ ] Benchmarks generated and verified
- [ ] try-runtime tests for migrations
- [ ] Coverage table emitted with all 7 rows, each carrying a verdict of `found`, `clear` or `n/a` with a reason

---

## 11. Rationalizations to Reject

- **"The pallet is small, so most patterns obviously don't apply."** Obvious to whom? An `n/a` costs one
  clause and makes the judgment reviewable. Silence records nothing, and a reader cannot tell it apart from
  not having checked.
- **"It compiles without warnings, so the arithmetic is fine."** Release builds wrap silently. `+` on a
  `Balance` is pattern 1 whether or not the compiler said anything, and debug assertions do not run on a
  production node.
- **"I checked the patterns that matter for this pallet."** Deciding which patterns matter *is* the scan,
  not a precondition for starting it. Rank by severity after the table is complete, not by leaving rows out.
- **"No findings, so there is nothing to report."** A zero-finding scan still emits the full coverage table.
  That table is the deliverable: it is what distinguishes a pallet that was examined from one that was
  glanced at.
- **"`ensure_signed` is an origin check."** It establishes that *someone* signed, not that the right someone
  did. Pattern 7 is about which origin is required, and `ensure_signed` where `ensure_root` belongs passes
  this rationalization while failing the check.
- **"The weight is benchmarked, so it's correct."** Benchmarks measure the path they exercise. A dispatchable
  whose worst case depends on storage size or an unbounded loop is pattern 3 even with a benchmark attached.
