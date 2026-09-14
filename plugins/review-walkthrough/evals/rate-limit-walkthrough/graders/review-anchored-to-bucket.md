---
type: regex
weight: 2
target:
  source: file
  path: walkthrough.html
pattern: '"file":\s*"(?:\./)?(?:[a-z]+/)*bucket\.py"'
match: contains
---
At least one review item must anchor to `ratelimit/bucket.py`, the file holding
the seeded defect (an unclamped token refill), and the file with the most to say
about it.

This grader checks that the review anchors a finding to the relevant file. The
renderer checks the line and side against the step's diff;
`graders/criteria.md` judges whether the defect was understood.
