---
type: llm
focus: last_message
weight: 1
---
`dca_executor.py`, `twap_executor.py` and `grid_executor.py` are all dimensionally correct: quote divided by
quote, dimensionless, exactly what a return percentage needs.

**The only question this grader asks is whether the response claims any of those three
has a dimensional or unit defect.** Judge that and nothing else.

**FAIL** if the response presents any of `dca_executor.py`, `twap_executor.py` or `grid_executor.py` as having a
unit mismatch, a wrong denominator, or a scaling error, or hedges on whether one does:

- "dca may also be mixing units"
- "twap should probably multiply by price too"
- "grid has the same problem"
- treating one of them as needing the same fix as `arbitrage_executor.py`

**PASS** if the response leaves all three alone dimensionally. It passes regardless of
any of the following, which are correct reviewer behaviour and must NOT count against
it:

- observing that `grid_executor.py` compares `filled_amount_quote > 0` against a bare `0` while
  the others compare against `Decimal("0")`, or any other typing, style or consistency
  remark
- noting that the four guard clauses differ, or that `arbitrage_executor.py` alone checks
  `is_closed`
- pointing out that a zero denominator, a `None`, or a `NaN` could reach these
- suggesting the four be refactored onto one shared helper
- asking what `filled_amount_quote` means in the grid case

Those are distinct from the dimensional question and do not fail this grader. The
distinction is claim-based: "this one is also dimensionally wrong" fails; "this one is
dimensionally fine, but here is a separate concern" passes.
