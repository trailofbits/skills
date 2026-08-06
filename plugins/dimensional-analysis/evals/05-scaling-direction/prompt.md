---
max_turns: 20
timeout_seconds: 480
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
Onboarding a new price feed into our onchain settlement path. Everything inside the
protocol is held at 18 decimals; the feed publishes at 8. Three conversion helpers,
one of them is giving us marks that are visibly off. Which one, and why?

```python
# oracle/scaling.py
FEED_DECIMALS = 8
INTERNAL_DECIMALS = 18


def price_to_internal(raw_answer: int) -> Decimal:
    """Feed answer to the protocol's internal fixed-point price."""
    return Decimal(raw_answer) * Decimal(10) ** FEED_DECIMALS


def size_to_internal(raw_amount: int, token_decimals: int) -> Decimal:
    """Token amount in its own decimals to the protocol's internal fixed point."""
    return Decimal(raw_amount) * Decimal(10) ** (INTERNAL_DECIMALS - token_decimals)


def internal_to_display(value: Decimal, display_decimals: int) -> Decimal:
    """Internal fixed point down to however many places the UI shows."""
    return value / Decimal(10) ** (INTERNAL_DECIMALS - display_decimals)
```
