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
