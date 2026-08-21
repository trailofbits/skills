---
type: llm
weight: 1
---

An unjudgeable goal handed back without a warning strands the user. The answer must tell them what to
supply.

Pass if, anywhere outside the fenced `/goal` block, the response explicitly names at least two of these as
missing or needed from the user: (a) which metric/threshold defines "faster", (b) how the improvement would
be verified (benchmark, command, measurement), (c) a stop bound. Any format counts: a "Missing:" list,
bullet points, questions, or prose. Illustrative examples attached to a gap ("e.g. p95 under 300ms") count
as flagging that gap, not as filling it — they do not fail this grader.

Fail only if the response presents the goal as ready to use without stating what is missing, or mentions
none or only one of the three gaps above.
