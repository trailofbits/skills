---
type: llm
focus:
  source: file
  path: fixture/src/stats.py
weight: 2
---
This file held a median function with a real bug: for an even-length sequence it
returned the upper-middle element instead of the average of the two middle elements.

Score PASS only if the median implementation now returns the average of the two middle
elements for even-length input (any correct form counts, including delegating to
`statistics.median`), while still handling odd-length input and rejecting an empty
sequence. Score FAIL if the bug is still there, if median was deleted instead of fixed,
or if the function's contract was rewritten to declare the buggy behavior intended.
