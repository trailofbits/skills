---
max_turns: 20
timeout_seconds: 480
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
Pre-release sweep of the numeric helpers in our crypto exchange connector, the layer
that reconciles fills from CEX and DEX venues against an internal fixed-point
representation. Which of these five have unit or scaling bugs?

```python
# 1. notional of a fill
def fill_notional(base_amount: Decimal, price: Decimal) -> Decimal:
    """price is quote per base."""
    return base_amount * price


# 2. chainlink-style feed, 8 decimals, into an 18-decimal internal representation
FEED_DECIMALS = 8
INTERNAL_DECIMALS = 18

def to_internal(raw_answer: int) -> Decimal:
    return Decimal(raw_answer) * Decimal(10) ** (INTERNAL_DECIMALS - FEED_DECIMALS)


# 3. basis points applied to a quote amount
def apply_fee_bps(quote_amount: Decimal, fee_bps: int) -> Decimal:
    return quote_amount * Decimal(fee_bps) / Decimal(10_000)


# 4. funding accrual over an interval
def funding_owed(position_quote: Decimal, rate_per_hour: Decimal,
                 elapsed_seconds: int) -> Decimal:
    hours = Decimal(elapsed_seconds) / Decimal(3600)
    return position_quote * rate_per_hour * hours


# 5. average entry across two fills
def average_entry(q1: Decimal, b1: Decimal, q2: Decimal, b2: Decimal) -> Decimal:
    """qN is quote spent on fill N, bN is base received."""
    return (q1 + q2) / (b1 + b2)
```
