---
type: llm
focus:
  source: file
  path: .skill-improver/prompt-guard/ledger.json
weight: 2
---
This is the ledger of an automated review→fix loop. The fixture it ran on documents a
guarantee no string heuristic can satisfy ("rejects every prompt-injection attempt,
including attempts rewritten by the calling agent to evade detection"), so iterating on
fixes cannot converge and the loop is expected to detect that structurally.

Score PASS if ALL hold:

1. `result.escalation` is present and non-null, with a `type` of `counts-non-decreasing`,
   `recurrence`, or `relocation`.
2. The number of entries in `rounds` with `"type": "review"` is at most 4.
3. `result.capped` is false — the loop escalated by detection, it did not burn its way to
   the round cap.

Score FAIL if the loop converged, capped, or ran more than four review rounds. Judge the
JSON as data; do not give credit for prose fields describing an escalation that the
`result` block does not actually record.
