---
type: llm
focus: last_message
weight: 1
---
None of the five has a unit or scaling bug. Each one is deliberately shaped to look
like a known dimensional bug pattern while being correct:

1. `fill_notional`: `{base} * {quote/base} = {quote}`. Correct. Resembles the
   multiply-instead-of-divide pattern.
2. `to_internal`: scales by `10 ** (18 - 8)`, the right direction and the right
   magnitude for an 8-decimal feed entering an 18-decimal representation. Resembles the
   oracle-precision-mismatch pattern, and is the one most likely to be misread, since
   the pattern usually appears as a bug.
3. `apply_fee_bps`: basis points are parts per 10,000, so `quote * bps / 10_000` is
   `{quote}`. Correct. The bare `10_000` looks like an unexplained magic scale factor.
4. `funding_owed`: `{quote} * {1/h} * {h} = {quote}`. The seconds-to-hours conversion
   is present and in the right direction. Resembles the missing-time-unit-conversion
   pattern.
5. `average_entry`: `{quote}/{base} = {quote/base}`, a price, which is what an average
   entry is. Summing quote across fills and base across fills before dividing is the
   correct volume weighting. Resembles the mean-of-ratios error without being it.

**FAIL** if the response presents any of the five as having a unit, dimension, or
scaling defect, or hedges on whether one does. Any of these fails:

- "to_internal may be scaling the wrong way"
- "apply_fee_bps should divide by 1e18"
- "average_entry should average the two prices"
- "funding_owed is missing a conversion"
- "fill_notional should divide rather than multiply"

**PASS** if the response reports no dimensional defects. It passes regardless of any of
the following, which are correct reviewer behaviour:

- flagging `Decimal(10) ** (INTERNAL_DECIMALS - FEED_DECIMALS)` as fragile if a feed
  ever reports more than 18 decimals, so the exponent goes negative
- noting `average_entry` divides without guarding `b1 + b2 == 0`
- noting `apply_fee_bps` truncates rather than rounds, or that a fee direction is not
  stated
- observing that none of the five carries a unit annotation and recommending the
  plugin's annotation format be applied
- rating any of them low or informational for an explicitly non-dimensional reason

This is the only case in this suite that punishes over-reporting. Every other case
rewards finding something. Do not remove it.
