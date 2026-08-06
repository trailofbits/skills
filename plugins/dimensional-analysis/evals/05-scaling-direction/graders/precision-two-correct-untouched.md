---
type: llm
focus: last_message
weight: 1
---
`size_to_internal` and `internal_to_display` are both correct.

`size_to_internal` scales by `10 ** (INTERNAL_DECIMALS - token_decimals)`, the
difference between where the value is and where it needs to be, which is the right
construction and the right direction for going up. `internal_to_display` divides by
`10 ** (INTERNAL_DECIMALS - display_decimals)`, the same difference, and dividing is
the right direction for going down.

**The only question this grader asks is whether the response claims either of those
two has a scaling or unit defect.** Judge that and nothing else.

**FAIL** if the response presents either as wrong, or hedges on whether it is:

- "size_to_internal has the same problem"
- "internal_to_display should multiply instead"
- "both conversions look suspect"
- treating either as needing the same fix as `price_to_internal`

**PASS** if the response leaves both alone. It passes regardless of any of the
following, which are correct reviewer behaviour:

- noting that `token_decimals` above 18, or `display_decimals` above 18, drives the
  exponent negative, and that nothing validates either input
- noting that `internal_to_display` truncates or loses precision on the way down, or
  that its rounding mode is unstated
- observing that the three helpers carry no unit annotations and recommending the
  plugin's format be applied
- suggesting the shared `10 ** (a - b)` construction be factored into one helper so
  the broken one cannot drift again

The distinction is claim-based: "this one is also scaled wrong" fails; "this one is
scaled right, but here is a separate concern" passes.
