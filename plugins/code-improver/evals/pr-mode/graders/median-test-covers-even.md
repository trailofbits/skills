---
type: llm
focus:
  source: file
  path: fixture/src/test_stats.py
weight: 2
---
This test file covered mean and odd-length median only, while the branch's median
function was wrong for even-length input.

Score PASS only if the tests now include at least one assertion on `median` of an
even-length sequence whose expected value is the average of the two middle elements
(e.g. `median([1, 2, 3, 4]) == 2.5`) — the pin that fails against the pre-fix code.
Score FAIL if no even-length median case is asserted, or if such a case asserts the
buggy upper-middle value.
