---
type: llm
focus: last_message
weight: 1
---
Exactly one of the four executors is dimensionally wrong: `arbitrage_executor.py`.

The dimension of `net_pnl_quote` is not stated, it has to be derived:
`executed_amount_base * average_executed_price` is `{base} * {quote/base} = {quote}`,
and `cum_fees_quote` is quote, so the difference is quote. That quote amount is then
divided by `executed_amount_base`, a base amount, leaving `{quote/base}`, which is a
price rather than the dimensionless ratio a percentage needs. The other three divide
by a quote amount and are `{quote/quote}`, correct.

The size of the error is the entry price: at 3000 quote per base, a 0.27% return is
reported as 800%.

**PASS** requires both of the following:

1. The response identifies `arbitrage_executor.py` as wrong, and its reasoning is dimensional:
   it says the denominator is a base amount where a quote amount is required, or that
   the result carries a leftover `quote/base` (price) dimension, or equivalent. Naming
   the units correctly matters; "looks inconsistent with the others" alone is not
   enough, because that reasoning does not tell you which one is wrong.
2. The response gives a correct fix: divide by the buy leg's quote amount. Accept any
   of `executed_amount_quote`, `executed_amount_base * average_executed_price`, or a
   description that is unambiguously one of those.

**FAIL** if any of:

- the response does not name `arbitrage_executor.py`
- it names `arbitrage_executor.py` only as a style or consistency deviation, with no unit or
  dimension reasoning
- it proposes a fix that is still `{quote/base}`, for example dividing by
  `average_executed_price` alone or by a base amount from a different leg

Scale of the error is not required for a PASS. If the response does state a magnitude,
it must be tied to the price rather than to a fixed constant; a claim such as "off by
100x" with no price dependence is wrong reasoning and fails this grader.
