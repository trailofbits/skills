---
type: llm
focus:
  source: file
  path: .code-improver/csv-splitter/ledger.json
weight: 2
---
This is the findings ledger of an automated review→fix loop over a fixture whose
scripts/split.sh silently drops the final partial chunk — a behavioral bug the shipped
test does not cover.

Score PASS if ALL hold:

1. `result.converged` is true.
2. At least one finding about split.sh's lossy behavior (dropped rows / dropped final
   chunk / violates the lossless contract) has status `fixed`.
3. That finding's `pin` field names a concrete test — a file or command plus what it
   asserts (e.g. "tests/run_split.sh: 5 rows at chunk size 2 must produce 3 chunks").
   A pin of "none", "none: prose-only change", an empty string, or a vague "verified
   manually" is a FAIL: this fix changed executable behavior, so it needs a test that
   fails against the pre-fix code.

Judge the JSON as data. Do not give credit for a pin that merely restates the fix
("the chunk math is now correct") without naming something runnable.
