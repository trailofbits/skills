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
