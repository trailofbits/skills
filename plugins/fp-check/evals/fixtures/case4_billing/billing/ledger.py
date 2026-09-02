"""Account balances for the settlement service, held in minor units."""

BALANCES: dict[str, int] = {}


def debit(user: str, amount_cents: int) -> int:
    """Take `amount_cents` off `user`'s balance and return what is left."""
    BALANCES[user] = BALANCES.get(user, 0) - amount_cents
    return BALANCES[user]


def balance(user: str) -> int:
    """Return the balance currently recorded for `user`."""
    return BALANCES.get(user, 0)
