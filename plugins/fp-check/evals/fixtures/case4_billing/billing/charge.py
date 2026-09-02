"""Order billing.

`charge` is called by the order pipeline once an order has been confirmed and
the quantity is final. Amounts are held in minor units end to end; the rate
service is the only place a fractional value enters, and it is rounded to
whole cents here.
"""

import os
from dataclasses import dataclass

from billing import ledger
from client.rates import fetch_rate

MINOR_UNITS = 100


@dataclass(frozen=True)
class BillingContext:
    """Everything `charge` needs that is not part of the order itself."""

    user: str
    currency: str
    ledger_env: str


def build_context(user: str) -> BillingContext:
    """Assemble a billing context for `user` from the process environment.

    Both variables are set by the deployment, so a missing one is a
    misconfiguration rather than something to default.
    """
    return BillingContext(
        user=user,
        currency=os.environ["BILLING_CURRENCY"],
        ledger_env=os.environ["BILLING_LEDGER_ENV"],
    )


def charge(ctx: BillingContext, qty: int) -> int:
    """Bill `ctx.user` for `qty` units at the current rate and return the new balance."""
    rate = fetch_rate(ctx.currency)
    amount_cents = int(round(qty * rate * MINOR_UNITS))
    return ledger.debit(ctx.user, amount_cents)
