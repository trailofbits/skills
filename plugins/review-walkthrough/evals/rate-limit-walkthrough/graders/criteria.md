---
type: llm
weight: 3
focus:
  source: file
  path: walkthrough.html
---
You are grading a generated HTML review walkthrough of a Python rate limiter.
Ignore the CSS and viewer JavaScript. Judge only the
`EXPLANATIONS` and `REVIEWS` arrays assigned near the end of the file.

Judge exactly two things, and nothing else.

1. **The review found the real problem.** At least one item in `REVIEWS`
   identifies a genuine defect in how the limiter's token accrual behaves over
   elapsed time, and explains what it means for a client rather than only
   restating the line. This is worded generally on purpose: do not require any
   particular phrasing, and do not require a specific fix.
2. **The explanations are concrete.** Each entry in `EXPLANATIONS` names actual
   identifiers from the step it accompanies, such as class, method, or field names,
   with an explanation of what changed.

Answer PASS if both hold. Answer FAIL if the reviews are only praise or
restatement on a diff that contains a real defect, or if an item cites a symbol
that appears nowhere in the step's diff.

Do **not** fail this run for any of the following; they are checked
deterministically elsewhere and judging them here only produces false negatives:

- HTML escaping, entity usage, or tag balance in any fragment.
- Backticks anywhere. Inside `<pre>` or `<code>` they are quoted source code.
- Array lengths, positional alignment between the three arrays, or whether
  `file`/`line` anchors point at valid diff lines.
- Step ordering, step count, or how the diff was grouped.
- Anything about the page's styling, layout or scripts.
