---
name: ton-vulnerability-scanner
description: Scans TON (The Open Network) smart contracts for 3 critical vulnerabilities including integer-as-boolean misuse, fake Jetton contracts, and forward TON without gas checks. Use when auditing FunC contracts.
---

# TON Vulnerability Scanner

## 1. Purpose

Systematically scan TON blockchain smart contracts written in FunC for platform-specific security vulnerabilities related to boolean logic, Jetton token handling, and gas management. This skill encodes 3 critical vulnerability patterns unique to TON's architecture.

## 2. When to Use This Skill

- Auditing TON smart contracts (FunC language)
- Reviewing Jetton token implementations
- Validating token transfer notification handlers
- Pre-launch security assessment of TON dApps
- Reviewing gas forwarding logic
- Assessing boolean condition handling

## 3. Platform Detection

### File Extensions & Indicators
- **FunC files**: `.fc`, `.func`

### Language/Framework Markers
```func
;; FunC contract indicators
#include "imports/stdlib.fc";

() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    ;; Contract logic
}

() recv_external(slice in_msg) impure {
    ;; External message handler
}

;; Common patterns
send_raw_message()
load_uint(), load_msg_addr(), load_coins()
begin_cell(), end_cell(), store_*()
transfer_notification operation
op::transfer, op::transfer_notification
.store_uint().store_slice().store_coins()
```

### Project Structure
- `contracts/*.fc` - FunC contract source
- `wrappers/*.ts` - TypeScript wrappers
- `tests/*.spec.ts` - Contract tests
- `ton.config.ts` or `wasm.config.ts` - TON project config

### Tool Support
- **TON Blueprint**: Development framework for TON
- **toncli**: CLI tool for TON contracts
- **ton-compiler**: FunC compiler
- Manual review primarily (limited automated tools)

---

## 4. How This Skill Works

When invoked, I will:

1. **Search your codebase** for FunC/Tact contracts
2. **Analyze each contract** for the 3 vulnerability patterns
3. **Report findings** with file references and severity, above them a coverage table carrying a verdict for every pattern
4. **Provide fixes** for each identified issue
5. **Emit the coverage table** — all 3 patterns, each with a verdict

---

## 5. Example Output

When vulnerabilities are found, you'll get a report like this:

```
=== TON VULNERABILITY SCAN RESULTS ===

Project: my-ton-contract
Files Scanned: 3 (.fc, .tact)
Vulnerabilities Found: 2

Coverage: 3/3 patterns reported
 1 Integer as Boolean .............. found   contracts/wallet.fc:45
 2 Fake Jetton Contract ............ found   contracts/staking.fc:85
 3 Forward TON Without Gas Check ... clear   forward amounts fixed at 0.05 TON

---

[CRITICAL] Fake Jetton Contract - Missing Sender Validation
File: contracts/staking.fc:85
Pattern: transfer_notification sender not checked against the stored Jetton wallet
```

---

## 6. Vulnerability Patterns (3 Patterns)

I check for 3 critical vulnerability patterns unique to TON. For detailed detection patterns, code examples, mitigations, and testing strategies, see [VULNERABILITY_PATTERNS.md](resources/VULNERABILITY_PATTERNS.md).

### Pattern Summary:

1. **Integer as Boolean** ⚠️ HIGH - Positive integers used as true; FunC's true is -1
2. **Fake Jetton Contract** ⚠️ CRITICAL - `transfer_notification` sender not validated
3. **Forward TON Without Gas Check** ⚠️ HIGH - Forwarding without reserving gas for the rest of execution

For complete vulnerability patterns with code examples, see [VULNERABILITY_PATTERNS.md](resources/VULNERABILITY_PATTERNS.md).

## 7. Scanning Workflow

### Step 1: Platform Identification
1. Verify FunC language (`.fc` or `.func` files)
2. Check for TON Blueprint or toncli project structure
3. Locate contract source files
4. Identify Jetton-related contracts

### Step 2: Boolean Logic Review
```bash
# Find boolean-like variables
rg "int.*is_|int.*has_|int.*flag|int.*enabled" contracts/

# Check for positive integers used as booleans
rg "= 1;|return 1;" contracts/ | grep -E "is_|has_|flag|enabled|valid"

# Look for NOT operations on boolean-like values
rg "~.*\(|~ " contracts/
```

For each boolean:
- [ ] Uses -1 for true, 0 for false
- [ ] NOT using 1 or other positive integers
- [ ] Logic operations work correctly

### Step 3: Jetton Handler Analysis
```bash
# Find transfer_notification handlers
rg "transfer_notification|op::transfer_notification" contracts/
```

For each Jetton handler:
- [ ] Validates sender address
- [ ] Sender checked against stored Jetton wallet address
- [ ] Cannot trust forward_payload without sender validation
- [ ] Has admin function to set Jetton wallet address

### Step 4: Gas/Forward Amount Review
```bash
# Find forward amount usage
rg "forward_ton_amount|forward_amount" contracts/
rg "load_coins\(\)" contracts/

# Find send_raw_message calls
rg "send_raw_message" contracts/
```

For each outgoing message:
- [ ] Forward amounts are fixed/bounded
- [ ] OR user-provided amounts validated against msg_value
- [ ] Cannot drain contract balance
- [ ] Appropriate send_raw_message flags used

### Step 5: Manual Review
TON contracts require thorough manual review:
- Boolean logic with `~`, `&`, `|` operators
- Message parsing and validation
- Gas economics and fee calculations
- Storage operations and data serialization

---

## 8. Reporting Format

### Coverage Table

Report on every pattern in §6, whether or not it turned anything up. Emit this table above the findings, with
all 3 rows present:

| # | Pattern | Verdict | Evidence |
|---|---------|---------|----------|
| 1 | Integer as Boolean | `clear` | searched `is_`/`has_`/`flag`; all set to -1 |
| 2 | Fake Jetton Contract | | |
| 3 | Forward TON Without Gas Check | | |

Each verdict is one of:

- **`found`** — cite `file:line` and write the finding up in full below.
- **`clear`** — the pattern applies to this contract and the contract handles it. Name the function, stored
  address, or check you searched for, so a reader can repeat the search.
- **`n/a`** — the pattern cannot apply here. Give the reason in one clause ("this contract handles no Jetton
  transfer notifications"). Not having looked is not `n/a`.

Three patterns is a short list, which makes an incomplete table harder to excuse rather than easier: a report
covering one pattern and silent on the other two reads exactly like a clean contract. Emit all three rows even
when all three are `clear`. A row whose Verdict cell is empty is incomplete in the same way: row 1 above is filled in to show the shape, and every row is filled in the same way before the report is done.

### Finding Template
````markdown
## [CRITICAL] Fake Jetton Contract - Missing Sender Validation

**Location**: `contracts/staking.fc:85-95` (recv_internal, transfer_notification handler)

**Description**:
The `transfer_notification` operation handler does not validate that the sender is the expected Jetton wallet contract. Any attacker can send a fake `transfer_notification` message claiming to have transferred tokens, crediting themselves without actually depositing any Jettons.

**Vulnerable Code**:
```func
// staking.fc, line 85
if (op == op::transfer_notification) {
    int jetton_amount = in_msg_body~load_coins();
    slice from_user = in_msg_body~load_msg_addr();

    ;; WRONG: No validation of sender_address!
    ;; Attacker can claim any jetton_amount

    credit_user(from_user, jetton_amount);
}
```

**Attack Scenario**:
1. Attacker deploys malicious contract
2. Malicious contract sends `transfer_notification` message to staking contract
3. Message claims attacker transferred 1,000,000 Jettons
4. Staking contract credits attacker without checking sender
5. Attacker can now withdraw from contract or gain benefits without depositing

**Proof of Concept**:
```typescript
// Attacker sends fake transfer_notification
const attackerContract = await blockchain.treasury("attacker");

await stakingContract.sendInternalMessage(attackerContract.getSender(), {
  op: OP_CODES.TRANSFER_NOTIFICATION,
  jettonAmount: toNano("1000000"), // Fake amount
  fromUser: attackerContract.address,
});

// Attacker successfully credited without sending real Jettons
const balance = await stakingContract.getUserBalance(attackerContract.address);
expect(balance).toEqual(toNano("1000000")); // Attack succeeded
```

**Recommendation**:
Store expected Jetton wallet address and validate sender:
```func
global slice jetton_wallet_address;

() recv_internal(...) impure {
    load_data();  ;; Load jetton_wallet_address from storage

    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    slice sender_address = cs~load_msg_addr();

    int op = in_msg_body~load_uint(32);

    if (op == op::transfer_notification) {
        ;; CRITICAL: Validate sender
        throw_unless(error::wrong_jetton_wallet,
            equal_slices(sender_address, jetton_wallet_address));

        int jetton_amount = in_msg_body~load_coins();
        slice from_user = in_msg_body~load_msg_addr();

        ;; Safe to credit user
        credit_user(from_user, jetton_amount);
    }
}
```

**References**:
- building-secure-contracts/not-so-smart-contracts/ton/fake_jetton_contract
````

---

## 9. Priority Guidelines

### Critical (Immediate Fix Required)
- Fake Jetton contract (unauthorized minting/crediting)

### High (Fix Before Launch)
- Integer as boolean (logic errors, broken conditions)
- Forward TON without gas check (balance drainage)

---

## 10. Testing Recommendations

### Unit Tests
```typescript
import { Blockchain } from "@ton/sandbox";
import { toNano } from "ton-core";

describe("Security tests", () => {
  let blockchain: Blockchain;
  let contract: Contract;

  beforeEach(async () => {
    blockchain = await Blockchain.create();
    contract = blockchain.openContract(await Contract.fromInit());
  });

  it("should use correct boolean values", async () => {
    // Test that TRUE = -1, FALSE = 0
    const result = await contract.getFlag();
    expect(result).toEqual(-1n); // True
    expect(result).not.toEqual(1n); // Not 1!
  });

  it("should reject fake jetton transfer", async () => {
    const attacker = await blockchain.treasury("attacker");

    const result = await contract.send(
      attacker.getSender(),
      { value: toNano("0.05") },
      {
        $$type: "TransferNotification",
        query_id: 0n,
        amount: toNano("1000"),
        from: attacker.address,
      }
    );

    expect(result.transactions).toHaveTransaction({
      success: false, // Should reject
    });
  });

  it("should validate gas for forward amount", async () => {
    const result = await contract.send(
      user.getSender(),
      { value: toNano("0.01") }, // Insufficient gas
      {
        $$type: "Transfer",
        to: recipient.address,
        forward_ton_amount: toNano("1"), // Trying to forward 1 TON
      }
    );

    expect(result.transactions).toHaveTransaction({
      success: false,
    });
  });
});
```

### Integration Tests
```typescript
// Test with real Jetton wallet
it("should accept transfer from real jetton wallet", async () => {
  // Deploy actual Jetton minter and wallet
  const jettonMinter = await blockchain.openContract(JettonMinter.create());
  const userJettonWallet = await jettonMinter.getWalletAddress(user.address);

  // Set jetton wallet in contract
  await contract.setJettonWallet(userJettonWallet);

  // Real transfer from Jetton wallet
  const result = await userJettonWallet.sendTransfer(
    user.getSender(),
    contract.address,
    toNano("100"),
    {}
  );

  expect(result.transactions).toHaveTransaction({
    to: contract.address,
    success: true,
  });
});
```

---

## 11. Additional Resources

- **Building Secure Contracts**: `building-secure-contracts/not-so-smart-contracts/ton/`
- **TON Documentation**: https://docs.ton.org/
- **FunC Documentation**: https://docs.ton.org/develop/func/overview
- **TON Blueprint**: https://github.com/ton-org/blueprint
- **Jetton Standard**: https://github.com/ton-blockchain/TEPs/blob/master/text/0074-jettons-standard.md

---

## 12. Quick Reference Checklist

Before completing TON contract audit:

**Boolean Logic (HIGH)**:
- [ ] All boolean values use -1 (true) and 0 (false)
- [ ] NO positive integers (1, 2, etc.) used as booleans
- [ ] Functions returning booleans return -1 for true
- [ ] Boolean logic with `~`, `&`, `|` uses correct values
- [ ] Tests verify boolean operations work correctly

**Jetton Security (CRITICAL)**:
- [ ] `transfer_notification` handler validates sender address
- [ ] Sender checked against stored Jetton wallet address
- [ ] Jetton wallet address stored during initialization
- [ ] Admin function to set/update Jetton wallet
- [ ] Cannot trust forward_payload without sender validation
- [ ] Tests with fake Jetton contracts verify rejection

**Gas & Forward Amounts (HIGH)**:
- [ ] Forward TON amounts are fixed/bounded
- [ ] OR user-provided amounts validated: `msg_value >= tx_fee + forward_amount`
- [ ] Contract balance protected from drainage
- [ ] Appropriate `send_raw_message` flags used
- [ ] Tests verify cannot drain contract with excessive forward amounts

**Testing**:
- [ ] Unit tests for all three vulnerability types
- [ ] Integration tests with real Jetton contracts
- [ ] Gas cost analysis for all operations
- [ ] Testnet deployment before mainnet
- [ ] Coverage table emitted with all 3 rows, each carrying a verdict of `found`, `clear` or `n/a` with a reason

---

## 13. Rationalizations to Reject

- **"The contract is small, so most patterns obviously don't apply."** Obvious to whom? An `n/a` costs one
  clause and makes the judgment reviewable. Silence records nothing, and a reader cannot tell it apart from
  not having checked. With only three patterns, there is no version of this scan too large to complete.
- **"There is no automated tooling for FunC, so coverage can't be systematic."** The absence of a scanner is
  the reason the table matters, not an excuse for skipping it. Manual review is the method here; the table is
  what makes it auditable.
- **"I checked the patterns that matter for this contract."** Deciding which patterns matter *is* the scan,
  not a precondition for starting it. Rank by severity after the table is complete, not by leaving rows out.
- **"No findings, so there is nothing to report."** A zero-finding scan still emits the full coverage table.
  That table is the deliverable: it is what distinguishes a contract that was examined from one that was
  glanced at.
- **"The sender is obviously the Jetton wallet."** Then cite the stored address it is compared against. Any
  contract can send a transfer notification; the check is a comparison against an address the contract itself
  computed, and its absence is the fake-Jetton bug.
- **"The message is non-bounceable, so gas doesn't matter."** Name the reserve. Forwarding without leaving
  enough for the remaining execution strands the contract mid-operation regardless of bounce behavior.
