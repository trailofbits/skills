#!/usr/bin/env bash
# Writes the case's target into the eval's empty working directory.
# The eval runs each case in a fresh scaffold dir, so a repo-relative path
# in the prompt resolves to nothing; the fixture has to be materialised here.
#
# This copy is kept byte-identical to fixtures/case1_ledger/ledger.py by
# tests/test_eval_suite.py::test_scaffold_fixture_matches_the_checked_in_copy.
set -euo pipefail
cat >ledger.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""In-memory ledger for the settlement service.

Balances are held as integers in minor units, so nothing here rounds.
Accounts are created by the provisioning path before any transfer can
name them, which is why a missing account raises rather than defaulting.
"""


def transfer_balance(ledger: dict[str, int], sender: str, recipient: str, amount: int) -> None:
    if sender not in ledger or recipient not in ledger:
        raise KeyError("unknown account")
    if ledger[sender] < amount:
        raise ValueError("insufficient funds")
    ledger[sender] -= amount
    ledger[recipient] += amount
CONCEPT_PROVER_FIXTURE_EOF
