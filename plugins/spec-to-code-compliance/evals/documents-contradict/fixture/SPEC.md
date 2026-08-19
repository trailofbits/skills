# Member Vault — Protocol Specification v1.4

## 1. Overview

The vault holds member deposits and allows partial redemptions. Members may have collateral locked against
their balance by the operator; locked collateral backs obligations settled outside this contract.

Members are assigned a tier. Tiers affect fee rebates and reporting cadence, and are set by the operator.

## 2. Deposits

Any member MAY deposit at any time while the vault is active. A deposit increases the member's balance and the
vault's total held amount by the deposited amount.

## 3. Redemptions

### 3.1 Availability

Redemptions are available to all members while the vault is active. A redemption of zero MUST be rejected.

### 3.2 Collateral protection

A redemption MUST NOT reduce a member's balance below their locked collateral. This applies to every member
regardless of tier: locked collateral backs obligations the vault cannot settle, so the balance covering it is
not the member's to withdraw.

### 3.3 Fee

Every redemption is charged a fee of 50 basis points on the redeemed amount. The member receives the redeemed
amount net of the fee, and the fee is reported to the fee sink.

## 4. Operator powers

The operator MAY pause the vault, MAY lock collateral against a member's balance, and MAY set a member's tier.

The operator MUST NOT be able to reduce a member's balance.

## 5. Accounting

The vault's total held amount MUST equal the sum of all member balances at the end of every operation.
