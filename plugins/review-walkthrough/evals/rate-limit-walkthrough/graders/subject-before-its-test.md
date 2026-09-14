---
type: regex
weight: 2
target:
  source: file
  path: walkthrough.html
pattern: 'b/ratelimit/bucket\.py[\s\S]*b/tests/test_bucket\.py'
match: contains
---
`tests/test_bucket.py` must not appear before the module it exercises.

The skill permits a small test to sit beside its subject, so a run that places
this test directly after `bucket.py` is following the skill correctly. A strict
tests-at-the-very-end grader would wrongly fail it.
"A test never precedes its subject" holds under both readings.
