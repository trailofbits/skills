---
name: algorand-vulnerability-scanner
description: Scans Algorand smart contracts for 11 common vulnerabilities including rekeying attacks, unchecked transaction fees, missing field validations, and access control issues. Use when auditing Algorand projects (TEAL/PyTeal).
---

# Algorand Vulnerability Scanner

## 1. Purpose

Systematically scan Algorand smart contracts (TEAL and PyTeal) for platform-specific security vulnerabilities documented in Trail of Bits' "Not So Smart Contracts" database. This skill encodes 11 critical vulnerability patterns unique to Algorand's transaction model.

## 2. When to Use This Skill

- Auditing Algorand smart contracts (stateful applications or smart signatures)
- Reviewing TEAL assembly or PyTeal code
- Pre-audit security assessment of Algorand projects
- Validating fixes for reported Algorand vulnerabilities
- Training team on Algorand-specific security patterns

## 3. Platform Detection

### File Extensions & Indicators
- **TEAL files**: `.teal`
- **PyTeal files**: `.py` with PyTeal imports

### Language/Framework Markers
```python
# PyTeal indicators
from pyteal import *
from algosdk import *

# Common patterns
Txn, Gtxn, Global, InnerTxnBuilder
OnComplete, ApplicationCall, TxnType
@router.method, @Subroutine
```

### Project Structure
- `approval_program.py` / `clear_program.py`
- `contract.teal` / `signature.teal`
- References to Algorand SDK or Beaker framework

### Tool Support
- **Tealer**: Trail of Bits static analyzer for Algorand
- Installation: `uv tool install tealer` (ensure uv's tool bin dir is on PATH)
- Usage: `tealer contract.teal --detect all`

---

## 4. How This Skill Works

When invoked, I will:

1. **Search your codebase** for TEAL/PyTeal files
2. **Analyze each file** for the 11 vulnerability patterns
3. **Report findings** with file references and severity, above them a coverage table carrying a verdict for every pattern
4. **Provide fixes** for each identified issue
5. **Run Tealer** (if installed) for automated detection

---

## 5. Example Output

When vulnerabilities are found, you'll get a report like this:

```
=== ALGORAND VULNERABILITY SCAN RESULTS ===

Project: my-algorand-dapp
Files Scanned: 3 (.teal, .py)
Vulnerabilities Found: 2

Coverage: 11/11 patterns reported
 1 Rekeying Attack ................... found   approval.py:45
 2 Unchecked Transaction Fee ......... n/a     stateful app, fees paid by sender
 3 Closing Account ................... clear   Assert(Txn.close_remainder_to() == Global.zero_address())
 ... one row per pattern, all 11 present ...

---

[CRITICAL] Rekeying Attack
File: contracts/approval.py:45
Pattern: Missing RekeyTo validation

Code:
    If(Txn.type_enum() == TxnType.Payment,
        Seq([
            # Missing: Assert(Txn.rekey_to() == Global.zero_address())
            App.globalPut(Bytes("balance"), balance + Txn.amount()),
            Approve()
        ])
    )

Issue: The contract doesn't validate the RekeyTo field, allowing attackers
to change account authorization and bypass restrictions.
```

---

## 6. Vulnerability Patterns (11 Patterns)

I check for 11 critical vulnerability patterns unique to Algorand. For detailed detection patterns, code examples, mitigations, and testing strategies, see [VULNERABILITY_PATTERNS.md](resources/VULNERABILITY_PATTERNS.md).

### Pattern Summary:

1. **Rekeying Attack** ⚠️ CRITICAL - Unchecked RekeyTo field
2. **Unchecked Transaction Fee** ⚠️ HIGH - Fee not validated in smart signatures
3. **Closing Account (CloseRemainderTo)** ⚠️ CRITICAL - Unchecked CloseRemainderTo drains the account
4. **Closing Asset (AssetCloseTo)** ⚠️ CRITICAL - Unchecked AssetCloseTo drains the asset holding
5. **Group Size Check** ⚠️ HIGH - No `Global.group_size()` validation on atomic groups
6. **Time-Based Replay Attack** ⚠️ MEDIUM - No lease or round-range bound
7. **Access Controls** ⚠️ CRITICAL - Update/delete and privileged calls unprotected
8. **Asset ID Verification** ⚠️ HIGH - Asset ID not validated in asset operations
9. **Denial of Service (Asset Opt-In)** ⚠️ MEDIUM - Push transfers strand on un-opted accounts
10. **Inner Transaction Fee** ⚠️ MEDIUM - Inner fee not explicitly set to 0
11. **Clear State Transaction** ⚠️ HIGH - Clear state program cannot reject, state left inconsistent

For complete vulnerability patterns with code examples, see [VULNERABILITY_PATTERNS.md](resources/VULNERABILITY_PATTERNS.md).

## 7. Scanning Workflow

### Step 1: Platform Identification
1. Confirm file extensions (`.teal`, `.py`)
2. Identify framework (PyTeal, Beaker, pure TEAL)
3. Determine contract type (stateful application vs smart signature)
4. Locate approval and clear state programs

### Step 2: Static Analysis with Tealer
```bash
# Run Tealer on contract
tealer contract.teal --detect all

# Or specific detectors
tealer contract.teal --detect unprotected-rekey,group-size-check,update-application-check
```

### Step 3: Manual Vulnerability Sweep
For each of the 11 vulnerabilities above:
1. Search for relevant transaction field usage
2. Verify validation logic exists
3. Check for bypass conditions
4. Validate inner transaction handling

### Step 4: Transaction Field Validation Matrix
Create checklist for all transaction types used:

**Payment Transactions**:
- [ ] RekeyTo validated
- [ ] CloseRemainderTo validated
- [ ] Fee validated (if smart signature)

**Asset Transfers**:
- [ ] Asset ID validated
- [ ] AssetCloseTo validated
- [ ] RekeyTo validated

**Application Calls**:
- [ ] OnComplete validated
- [ ] Access controls enforced
- [ ] Group size validated

**Inner Transactions**:
- [ ] Fee explicitly set to 0
- [ ] RekeyTo not user-controlled (Teal v6+)
- [ ] All fields validated

### Step 5: Group Transaction Analysis
For atomic transaction groups:
1. Validate `Global.group_size()` checks
2. Review absolute vs relative indexing
3. Check for replay protection (Lease field)
4. Verify OnComplete fields for ApplicationCalls in group

### Step 6: Access Control Review
- [ ] Creator/admin privileges properly enforced
- [ ] Update/delete operations protected
- [ ] Sensitive functions have authorization checks

---

## 8. Reporting Format

### Coverage Table

Report on every pattern in §6, whether or not it turned anything up. Emit this table above the findings, with
all 11 rows present:

| # | Pattern | Verdict | Evidence |
|---|---------|---------|----------|
| 1 | Rekeying Attack | `found` | `approval.py:45` -- no `Txn.rekey_to()` assertion on the payment branch |
| 2 | Unchecked Transaction Fee | | |
| 3 | Closing Account (CloseRemainderTo) | | |
| 4 | Closing Asset (AssetCloseTo) | | |
| 5 | Group Size Check | | |
| 6 | Time-Based Replay Attack | | |
| 7 | Access Controls | | |
| 8 | Asset ID Verification | | |
| 9 | Denial of Service (Asset Opt-In) | | |
| 10 | Inner Transaction Fee | | |
| 11 | Clear State Transaction | | |

Each verdict is one of:

- **`found`** — cite `file:line` and write the finding up in full below.
- **`clear`** — the pattern applies to this contract and the contract handles it. Name the field, opcode, or
  check you searched for, so a reader can repeat the search.
- **`n/a`** — the pattern cannot apply here. Give the reason in one clause ("no inner transactions in this
  contract"). Not having looked is not `n/a`.

A table with fewer than 11 rows is an incomplete scan and must be reported as one. A row whose Verdict cell is empty is incomplete in the same way: row 1 above is filled in to show the shape, and every row is filled in the same way before the report is done. Eleven `clear` verdicts is
a result a reader can act on. A report that covers four patterns and says nothing about the other seven reads
exactly like a clean contract, and that is the failure this table exists to prevent.

### Finding Template
````markdown
## [SEVERITY] Vulnerability Name (e.g., Missing RekeyTo Validation)

**Location**: `contract.teal:45-50` or `approval_program.py:withdraw()`

**Description**:
The contract approves payment transactions without validating the RekeyTo field, allowing an attacker to rekey the account and bypass future authorization checks.

**Vulnerable Code**:
```python
# approval_program.py, line 45
If(Txn.type_enum() == TxnType.Payment,
    Approve()  # Missing RekeyTo check
)
```

**Attack Scenario**:
1. Attacker submits payment transaction with RekeyTo set to attacker's address
2. Contract approves transaction without checking RekeyTo
3. Account authorization is rekeyed to attacker
4. Attacker gains full control of account

**Recommendation**:
Add explicit validation of the RekeyTo field:
```python
If(And(
    Txn.type_enum() == TxnType.Payment,
    Txn.rekey_to() == Global.zero_address()
), Approve(), Reject())
```

**References**:
- building-secure-contracts/not-so-smart-contracts/algorand/rekeying
- Tealer detector: `unprotected-rekey`
````

---

## 9. Priority Guidelines

### Critical (Immediate Fix Required)
- Rekeying attacks
- CloseRemainderTo / AssetCloseTo issues
- Access control bypasses

### High (Fix Before Deployment)
- Unchecked transaction fees
- Asset ID validation issues
- Group size validation
- Clear state transaction checks

### Medium (Address in Audit)
- Inner transaction fee issues
- Time-based replay attacks
- DoS via asset opt-in

---

## 10. Testing Recommendations

### Unit Tests Required
- Test each vulnerability scenario with PoC exploit
- Verify fixes prevent exploitation
- Test edge cases (group size = 0, empty addresses, etc.)

### Tealer Integration
```bash
# Add to CI/CD pipeline
tealer approval.teal --detect all --json > tealer-report.json

# Fail build on critical findings
tealer approval.teal --detect all --fail-on critical,high
```

### Scenario Testing
- Submit transactions with all critical fields manipulated
- Test atomic groups with unexpected sizes
- Attempt access control bypasses
- Verify inner transaction fee handling

---

## 11. Additional Resources

- **Building Secure Contracts**: `building-secure-contracts/not-so-smart-contracts/algorand/`
- **Tealer Documentation**: https://github.com/crytic/tealer
- **Algorand Developer Docs**: https://developer.algorand.org/docs/
- **PyTeal Documentation**: https://pyteal.readthedocs.io/

---

## 12. Quick Reference Checklist

Before completing Algorand audit, verify ALL items checked:

- [ ] RekeyTo validated in all transaction types
- [ ] CloseRemainderTo validated in payment transactions
- [ ] AssetCloseTo validated in asset transfers
- [ ] Transaction fees validated (smart signatures)
- [ ] Group size validated for atomic transactions
- [ ] Lease field used for replay protection (where applicable)
- [ ] Access controls on Update/Delete operations
- [ ] Asset ID validated in all asset operations
- [ ] Asset transfers use pull pattern to avoid DoS
- [ ] Inner transaction fees explicitly set to 0
- [ ] OnComplete field validated for ApplicationCall transactions
- [ ] Tealer scan completed with no critical/high findings
- [ ] Unit tests cover all vulnerability scenarios
- [ ] Coverage table emitted with all 11 rows, each carrying a verdict of `found`, `clear` or `n/a` with a reason

---

## 13. Rationalizations to Reject

- **"The contract is small, so most patterns obviously don't apply."** Obvious to whom? An `n/a` costs one
  clause and makes the judgment reviewable. Silence records nothing, and a reader cannot tell it apart from
  not having checked.
- **"Tealer reported nothing, so the contract is clean."** Tealer covers a subset of these 11 patterns and
  does not reach the logic-level ones at all. A clean tool run is one row of evidence, not a verdict on the
  patterns it never examined. Say which patterns it covered.
- **"I checked the patterns that matter for this contract."** Deciding which patterns matter *is* the scan,
  not a precondition for starting it. Rank by severity after the table is complete, not by leaving rows out.
- **"No findings, so there is nothing to report."** A zero-finding scan still emits the full coverage table.
  That table is the deliverable: it is what distinguishes a contract that was examined from one that was
  glanced at.
- **"PyTeal/Beaker handles this."** Name the version and the mechanism. Framework defaults change between
  releases, and a framework that covers a pattern on one call path often does not on another.
- **"The RekeyTo check is in the other program."** Then cite it. A validation you believe exists elsewhere is
  an assumption until you have the `file:line`, and split-program contracts are where these checks go missing.
