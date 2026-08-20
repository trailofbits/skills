---
type: llm
focus:
  source: file
  path: .code-improver/linky/ledger.json
weight: 2
---
This is the findings ledger of an automated review→fix loop over a fixture whose
defects are fixable in about two rounds.

Score PASS if ALL hold:

1. The LAST entry in the `rounds` array has `"type": "review"` — the loop's final action
   was a review, never a fix. This must hold whether the run converged or capped.
2. If `result.converged` is true, that last review entry reports zero open critical and
   zero open major findings (`open.critical` and `open.major` both 0).
3. If `result.converged` is false, then `result.capped` is true or `result.escalation`
   is set or `result.halted` names a guard — a false `converged` with none of those is a
   run that just stopped, which is a FAIL.

Judge the JSON as data; the order of the `rounds` array is chronological.
