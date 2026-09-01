---
name: cairo-vulnerability-scanner
description: Scans Cairo/StarkNet smart contracts for 6 critical vulnerabilities including felt252 arithmetic overflow, L1-L2 messaging issues, address conversion problems, and signature replay. Use when auditing StarkNet projects.
---

# Cairo/StarkNet Vulnerability Scanner

## 1. Purpose

Systematically scan Cairo smart contracts on StarkNet for platform-specific security vulnerabilities related to arithmetic, cross-layer messaging, and cryptographic operations. This skill encodes 6 critical vulnerability patterns unique to Cairo/StarkNet ecosystem.

## 2. When to Use This Skill

- Auditing StarkNet smart contracts (Cairo)
- Reviewing L1-L2 bridge implementations
- Pre-launch security assessment of StarkNet applications
- Validating cross-layer message handling
- Reviewing signature verification logic
- Assessing L1 handler functions

## 3. Platform Detection

### File Extensions & Indicators
- **Cairo files**: `.cairo`

### Language/Framework Markers
```rust
// Cairo contract indicators
#[contract]
mod MyContract {
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        balance: LegacyMap<ContractAddress, felt252>,
    }

    #[external(v0)]
    fn transfer(ref self: ContractState, to: ContractAddress, amount: felt252) {
        // Contract logic
    }

    #[l1_handler]
    fn handle_deposit(ref self: ContractState, from_address: felt252, amount: u256) {
        // L1 message handler
    }
}

// Common patterns
felt252, u128, u256
ContractAddress, EthAddress
#[external(v0)], #[l1_handler], #[constructor]
get_caller_address(), get_contract_address()
send_message_to_l1_syscall
```

### Project Structure
- `src/contract.cairo` - Main contract implementation
- `src/lib.cairo` - Library modules
- `tests/` - Contract tests
- `Scarb.toml` - Cairo project configuration

### Tool Support
- **Caracal**: Trail of Bits static analyzer for Cairo
- Installation: `cargo install --git https://github.com/crytic/caracal --profile release --force` (a Rust tool — not on PyPI)
- Usage: `caracal detect src/`
- **cairo-test**: Built-in testing framework
- **Starknet Foundry**: Testing and development toolkit

---

## 4. How This Skill Works

When invoked, I will:

1. **Search your codebase** for Cairo files
2. **Analyze each contract** for the 6 vulnerability patterns
3. **Report findings** with file references and severity, above them a coverage table carrying a verdict for every pattern
4. **Provide fixes** for each identified issue
5. **Check L1-L2 interactions** for messaging vulnerabilities

---

## 5. Example Output

When vulnerabilities are found, you'll get a report like this:

```
=== CAIRO/STARKNET VULNERABILITY SCAN RESULTS ===
```

---

## 6. Vulnerability Patterns (6 Patterns)

I check for 6 critical vulnerability patterns unique to Cairo/Starknet. For detailed detection patterns, code examples, mitigations, and testing strategies, see [VULNERABILITY_PATTERNS.md](resources/VULNERABILITY_PATTERNS.md).

### Pattern Summary:

1. **Felt252 Arithmetic Overflow/Underflow** ⚠️ HIGH - `felt252` wraps silently; use `u128`/`u256`
2. **L1 to L2 Address Conversion** ⚠️ HIGH - L1 address not validated against STARKNET_FIELD_PRIME
3. **L1 to L2 Message Failure** ⚠️ HIGH - No cancellation path when a message cannot be consumed
4. **Overconstrained L1 <-> L2 Interaction** ⚠️ MEDIUM - Coupling that can strand funds or block progress
5. **Signature Replay Protection** ⚠️ HIGH - No nonce, or a domain separator missing chain/contract
6. **Unchecked from_address in L1 Handler** ⚠️ CRITICAL - Any L1 contract can drive the handler

For complete vulnerability patterns with code examples, see [VULNERABILITY_PATTERNS.md](resources/VULNERABILITY_PATTERNS.md).

## 7. Scanning Workflow

### Step 1: Platform Identification
1. Verify Cairo language and StarkNet framework
2. Check Cairo version (Cairo 1.0+ vs legacy Cairo 0)
3. Locate contract files (`src/*.cairo`)
4. Identify L1-L2 bridge contracts (if applicable)

### Step 2: Arithmetic Safety Sweep
```bash
# Find felt252 usage in arithmetic
rg "felt252" src/ | rg "[-+*/]"

# Find balance/amount storage using felt252
rg "felt252" src/ | rg "balance|amount|total|supply"

# Should prefer u128, u256 instead
```

### Step 3: L1 Handler Analysis
For each `#[l1_handler]` function:
- [ ] Validates `from_address` parameter
- [ ] Checks address != zero
- [ ] Has proper access control
- [ ] Emits events for monitoring

### Step 4: Signature Verification Review
For signature-based functions:
- [ ] Includes nonce tracking
- [ ] Nonce incremented after use
- [ ] Domain separator includes chain ID and contract address
- [ ] Cannot replay signatures

### Step 5: L1-L2 Bridge Audit
If contract includes bridge functionality:
- [ ] L1 validates address < STARKNET_FIELD_PRIME
- [ ] L1 implements message cancellation
- [ ] L2 validates from_address in handlers
- [ ] Symmetric access controls L1 ↔ L2
- [ ] Test full roundtrip flows

### Step 6: Static Analysis with Caracal
```bash
# Run Caracal detectors
caracal detect src/

# Specific detectors
caracal detect src/ --detectors unchecked-felt252-arithmetic
caracal detect src/ --detectors unchecked-l1-handler-from
caracal detect src/ --detectors missing-nonce-validation
```

---

## 8. Reporting Format

### Coverage Table

Report on every pattern in §6, whether or not it turned anything up. Emit this table above the findings, with
all 6 rows present:

| # | Pattern | Verdict | Evidence |
|---|---------|---------|----------|
| 1 | Felt252 Arithmetic Overflow/Underflow | `clear` | balances are `u256`; searched `felt252` in arithmetic, none |
| 2 | L1 to L2 Address Conversion | | |
| 3 | L1 to L2 Message Failure | | |
| 4 | Overconstrained L1 <-> L2 Interaction | | |
| 5 | Signature Replay Protection | | |
| 6 | Unchecked from_address in L1 Handler | | |

Each verdict is one of:

- **`found`** — cite `file:line` and write the finding up in full below.
- **`clear`** — the pattern applies to this contract and the contract handles it. Name the function, trait, or
  check you searched for, so a reader can repeat the search.
- **`n/a`** — the pattern cannot apply here. Give the reason in one clause ("no L1 handlers in this contract").
  Not having looked is not `n/a`.

A table with fewer than 6 rows is an incomplete scan and must be reported as one. A row whose Verdict cell is empty is incomplete in the same way: row 1 above is filled in to show the shape, and every row is filled in the same way before the report is done. Six `clear` verdicts is a
result a reader can act on. A report that covers two patterns and says nothing about the other four reads
exactly like a clean contract, and that is the failure this table exists to prevent.

### Finding Template
````markdown
## [CRITICAL] Unchecked from_address in L1 Handler

**Location**: `src/bridge.cairo:145-155` (handle_deposit function)

**Description**:
The `handle_deposit` L1 handler function does not validate the `from_address` parameter. Any L1 contract can send messages to this function and mint tokens for arbitrary users, bypassing the intended L1 bridge access controls.

**Vulnerable Code**:
```rust
// bridge.cairo, line 145
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,  // Not validated!
    user: ContractAddress,
    amount: u256
) {
    let current_balance = self.balances.read(user);
    self.balances.write(user, current_balance + amount);
}
```

**Attack Scenario**:
1. Attacker deploys malicious L1 contract
2. Malicious contract calls `starknetCore.sendMessageToL2(l2Contract, selector, [attacker_address, 1000000])`
3. L2 handler processes message without checking sender
4. Attacker receives 1,000,000 tokens without depositing any funds
5. Protocol suffers infinite mint vulnerability

**Recommendation**:
Validate `from_address` against authorized L1 bridge:
```rust
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    user: ContractAddress,
    amount: u256
) {
    // Validate L1 sender
    let authorized_l1_bridge = self.l1_bridge_address.read();
    assert(from_address == authorized_l1_bridge, 'Unauthorized L1 sender');

    let current_balance = self.balances.read(user);
    self.balances.write(user, current_balance + amount);
}
```

**References**:
- building-secure-contracts/not-so-smart-contracts/cairo/unchecked_l1_handler_from
- Caracal detector: `unchecked-l1-handler-from`
````

---

## 9. Priority Guidelines

### Critical (Immediate Fix Required)
- Unchecked from_address in L1 handlers (infinite mint)
- L1-L2 address conversion issues (funds to zero address)

### High (Fix Before Deployment)
- Felt252 arithmetic overflow/underflow (balance manipulation)
- Missing signature replay protection (replay attacks)
- L1-L2 message failure without cancellation (locked funds)

### Medium (Address in Audit)
- Overconstrained L1-L2 interactions (trapped funds)

---

## 10. Testing Recommendations

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_felt252_overflow() {
        // Test arithmetic edge cases
    }

    #[test]
    #[should_panic]
    fn test_unauthorized_l1_handler() {
        // Wrong from_address should fail
    }

    #[test]
    fn test_signature_replay_protection() {
        // Same signature twice should fail
    }
}
```

### Integration Tests (with L1)
```rust
// Test full L1-L2 flow
#[test]
fn test_deposit_withdraw_roundtrip() {
    // 1. Deposit on L1
    // 2. Wait for L2 processing
    // 3. Verify L2 balance
    // 4. Withdraw to L1
    // 5. Verify L1 balance restored
}
```

### Caracal CI Integration
```yaml
# .github/workflows/security.yml
- name: Run Caracal
  run: |
    # Rebuilds from source each run; cache ~/.cargo or pin a release binary instead.
    cargo install --git https://github.com/crytic/caracal --profile release --force
    caracal detect src/ --fail-on high,critical
```

---

## 11. Additional Resources

- **Building Secure Contracts**: `building-secure-contracts/not-so-smart-contracts/cairo/`
- **Caracal**: https://github.com/crytic/caracal
- **Cairo Documentation**: https://book.cairo-lang.org/
- **StarkNet Documentation**: https://docs.starknet.io/
- **OpenZeppelin Cairo Contracts**: https://github.com/OpenZeppelin/cairo-contracts

---

## 12. Quick Reference Checklist

Before completing Cairo/StarkNet audit:

**Arithmetic Safety (HIGH)**:
- [ ] No felt252 used for balances/amounts (use u128/u256)
- [ ] OR felt252 arithmetic has explicit bounds checking
- [ ] Overflow/underflow scenarios tested

**L1 Handler Security (CRITICAL)**:
- [ ] ALL `#[l1_handler]` functions validate `from_address`
- [ ] from_address compared against stored L1 contract address
- [ ] Cannot bypass by deploying alternate L1 contract

**L1-L2 Messaging (HIGH)**:
- [ ] L1 bridge validates addresses < STARKNET_FIELD_PRIME
- [ ] L1 bridge implements message cancellation
- [ ] L2 handlers check from_address
- [ ] Symmetric validation rules L1 ↔ L2
- [ ] Full roundtrip flows tested

**Signature Security (HIGH)**:
- [ ] Signatures include nonce tracking
- [ ] Nonce incremented after each use
- [ ] Domain separator includes chain ID and contract address
- [ ] Signature replay tested and prevented
- [ ] Cross-chain replay prevented

**Tool Usage**:
- [ ] Caracal scan completed with no critical findings
- [ ] Unit tests cover all vulnerability scenarios
- [ ] Integration tests verify L1-L2 flows
- [ ] Testnet deployment tested before mainnet
- [ ] Coverage table emitted with all 6 rows, each carrying a verdict of `found`, `clear` or `n/a` with a reason

---

## 13. Rationalizations to Reject

- **"The contract is small, so most patterns obviously don't apply."** Obvious to whom? An `n/a` costs one
  clause and makes the judgment reviewable. Silence records nothing, and a reader cannot tell it apart from
  not having checked.
- **"Caracal reported nothing, so the contract is clean."** Caracal covers a subset of these 6 patterns and
  does not reach the logic-level ones at all. A clean tool run is one row of evidence, not a verdict on the
  patterns it never examined. Say which patterns it covered.
- **"I checked the patterns that matter for this contract."** Deciding which patterns matter *is* the scan,
  not a precondition for starting it. Rank by severity after the table is complete, not by leaving rows out.
- **"No findings, so there is nothing to report."** A zero-finding scan still emits the full coverage table.
  That table is the deliverable: it is what distinguishes a contract that was examined from one that was
  glanced at.
- **"Cairo 1 has native overflow checks, so arithmetic is safe."** Name the types. `felt252` does not behave
  like the sized integer types, and the boundary between them is where pattern 4 lives.
- **"The L1 side validates that."** Then cite the L1 contract. A check you believe exists across the bridge is
  an assumption until you have read it, and unverified `from_address` is the canonical StarkNet bridge bug.
