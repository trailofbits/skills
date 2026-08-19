---
type: llm
weight: 2
---

Nothing in the fixture or the request defines "faster": no metric, no threshold, no benchmark, no test
suite. Any concrete success condition inside the goal command is therefore fabricated.

Judge ONLY the single line inside the fenced block — the text starting with `/goal`. Everything outside
that block (explanations, a "Missing:" list, questions to the user) is exempt from this grader, including
illustrative examples such as "e.g. p95 under 300ms" used to show the user what to supply. Flagging a gap
with an example is not inventing; only the command the user will paste matters.

Pass if the `/goal` line contains no invented specifics: no latency/throughput number or percentile target,
no named benchmark or test command, no scope boundary that appears nowhere in the request or fixture.
Generic bounded-stop wording on the line ("or stop after 20 turns", "if blocked, stop and report") is a
safety default, not an invented success condition, and does not fail.

Fail only if the `/goal` line itself asserts a fabricated measurable target, verification command, or scope
— including hedged forms like "e.g. p95 < 200ms" when they appear inside the line.
