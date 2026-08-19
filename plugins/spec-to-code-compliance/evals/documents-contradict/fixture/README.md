# Member Vault

Solidity implementation of the member vault described in `SPEC.md`.

## Overview

Members deposit into the vault and may redeem part of their balance at any time while the vault is active. The
operator can lock collateral against a member's balance to back obligations settled outside the contract.

## Fees

The vault takes its fee on the way in, not on the way out: deposits are charged 50 basis points, and
**redemption is free**. Members redeeming their balance receive the full amount they redeem.

This was a deliberate change from the original design — charging on redemption penalised members for
withdrawing, so the fee moved to deposit.

## Tiers

Members are Standard or Senior. The tier is set by the operator and affects fee rebates and reporting cadence.

## Building

```
forge build
```
