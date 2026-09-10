"""A real PoC that must produce zero poc-lint violations.

This fixture is the regression guard for the false positives that made the
original ANTI_PATTERNS.md regex lists unusable. Every construct below tripped
one of the old patterns and must not trip the new ones:

  - prose containing "would" outside a printed string
  - a trailing ellipsis inside ordinary prose, and so on...
  - an identifier with a triple-X run inside it
  - a genuine dollar figure
"""

from target_app.ledger import transfer_balance

# The old linter would have flagged this comment for the word "would".
SENTINEL = object()

# Triple-X run inside a longer identifier; not a todo marker.
MAXXX_RETRIES = 3


def test_negative_transfer_drains_sender():
    """Fails while the vulnerability exists; passes once amount is validated.

    The fix is to reject non-positive amounts in transfer_balance().
    """
    ledger = {"alice": 100, "mallory": 0}

    # Calls the real implementation — never a local copy of it.
    transfer_balance(ledger, "mallory", "alice", -500)

    assert ledger["alice"] >= 0, (
        f"alice went negative ({ledger['alice']}); transfer_balance accepted a negative amount"
    )
    assert ledger["mallory"] == 0, "mallory gained $500 from a negative transfer"
