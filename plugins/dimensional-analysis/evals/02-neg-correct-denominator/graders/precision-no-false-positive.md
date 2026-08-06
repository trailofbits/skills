---
type: llm
focus: last_message
weight: 1
---
This code is dimensionally sound. Every term in `get_net_pnl_quote` is a quote amount,
so the subtraction is well formed and the result is quote. `get_net_pnl_pct` then
divides that quote result by `executed_amount_quote`, also quote, giving a
dimensionless ratio.

This is case 01's `arbitrage_executor.py` after the fix, so it is the direct control for the
positive case: the same function, the same field names in scope, one denominator
changed. `executed_amount_base` and `average_executed_price` are still declared on
`TrackedOrder` and are still the wrong things to divide by, which is what makes this a
test of whether the skill reads the code or pattern-matches on the presence of mixed
units nearby.

**FAIL** if the response reports a dimensional or unit defect in this code:

- claiming the denominator should be a base amount, or should involve
  `average_executed_price`
- claiming the subtraction in `get_net_pnl_quote` mixes dimensions
- claiming the returned ratio still carries a unit
- hedging: "this may still be mixing quote and base", "consider whether the denominator
  is the right one"

**PASS** if the response concludes the arithmetic is dimensionally correct. It passes
regardless of any of the following:

- noting the ratio is a fraction rather than a percentage, so a caller multiplying by
  100 matters. That is a real observation about presentation, not a dimensional defect
- flagging that fees are subtracted from the spread rather than netted per leg
- observing that `is_closed` and `close_type == COMPLETED` are different guards, so
  `net_pnl_quote` can be zero while `get_net_pnl_pct` still divides
- any remark about `Decimal` versus `float`, or about the missing zero check on
  `close_type`

Recommending a comment that records the units is also a PASS. Adding annotation is what
this plugin exists to do; the failure this grader looks for is a claimed *bug*.
