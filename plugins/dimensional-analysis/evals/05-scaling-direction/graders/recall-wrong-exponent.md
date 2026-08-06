---
type: llm
focus: last_message
weight: 1
---
`price_to_internal` is the broken one. It multiplies by `10 ** FEED_DECIMALS`, which
is `10 ** 8`. The gap between the two representations is `INTERNAL_DECIMALS -
FEED_DECIMALS`, so the multiplier should be `10 ** 10`. A raw answer of `X` stands for
`X / 10 ** 8`, and the internal value must satisfy `internal / 10 ** 18 = X / 10 ** 8`,
which gives `internal = X * 10 ** 10`. Every mark it produces is 100 times too small.

The other two are correct. `size_to_internal` uses the difference of the two decimal
counts, which is the same construction `price_to_internal` should have used.
`internal_to_display` divides by that difference, the right direction for going down.

**PASS** requires all three of:

1. It names `price_to_internal`.
2. Its reasoning is about the exponent: the multiplier uses the feed's decimals rather
   than the difference between the two representations, or equivalent. "Inconsistent
   with the other two" alone is not enough, because that reasoning does not say which
   of the three is the wrong one.
3. Its fix produces `10 ** (INTERNAL_DECIMALS - FEED_DECIMALS)`. Accept `10 ** 10`, the
   symbolic form, or a described equivalent.

**FAIL** if any of:

- it does not name `price_to_internal`
- it names the function but locates the defect somewhere other than the exponent, for
  example claiming the multiplication should be a division
- its fix does not land on `10 ** 10`, for example `10 ** 18` or `10 ** 26`
- it reports one of the other two helpers as broken

Stating the magnitude is not required. If a magnitude is given it must be 100, or
`10 ** 2`, or "two orders of magnitude"; a different factor means the exponent was not
actually worked out and fails this grader.
