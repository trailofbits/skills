#!/usr/bin/env bash
# Writes the case's targets into the eval's empty working directory.
# The eval runs each case in a fresh scaffold dir, so a repo-relative path
# in the prompt resolves to nothing; the fixtures have to be materialised here.
#
# These copies are kept byte-identical to fixtures/case4_billing/ by
# tests/test_eval_suite.py::test_scaffold_fixture_matches_the_checked_in_copy.
#
# The tree is committed because build-poc builds with isolation: 'worktree'.
# A worktree is cut from HEAD, so anything left uncommitted here is missing
# from the directory the builder actually works in.
set -euo pipefail

mkdir -p billing client

cat >client/rates.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Client for the upstream FX rate service.

One rate lookup is made per order, at the moment the order is billed.
"""

import json
import urllib.parse
import urllib.request

RATE_API = "https://rates.example.internal/v1/current"
TIMEOUT_SECONDS = 5


def fetch_rate(currency: str) -> float:
    """Return the rate the pricing service is currently quoting for `currency`."""
    query = urllib.parse.urlencode({"currency": currency})
    with urllib.request.urlopen(f"{RATE_API}?{query}", timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)["rate"]
CONCEPT_PROVER_FIXTURE_EOF

cat >billing/ledger.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Account balances for the settlement service, held in minor units."""

BALANCES: dict[str, int] = {}


def debit(user: str, amount_cents: int) -> int:
    """Take `amount_cents` off `user`'s balance and return what is left."""
    BALANCES[user] = BALANCES.get(user, 0) - amount_cents
    return BALANCES[user]


def balance(user: str) -> int:
    """Return the balance currently recorded for `user`."""
    return BALANCES.get(user, 0)
CONCEPT_PROVER_FIXTURE_EOF

cat >billing/charge.py <<'CONCEPT_PROVER_FIXTURE_EOF'
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
CONCEPT_PROVER_FIXTURE_EOF

git -c init.defaultBranch=main init -q
git add -A
GIT_AUTHOR_DATE='2026-06-18T09:41:00+00:00' \
  GIT_COMMITTER_DATE='2026-06-18T09:41:00+00:00' \
  git -c user.name='Billing Team' -c user.email='billing@example.invalid' \
  -c commit.gpgsign=false \
  commit -q -m 'feat(billing): charge confirmed orders against the rate service'
