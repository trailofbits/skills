# Review Integration

Use the review gate packet as supporting evidence for a human branch review.
It should be attached to, pasted into, or summarized alongside line-level
review notes.

## With Differential Review

Use `differential-review` for line-level analysis and this skill for structural
signals. Recommended order:

1. Run `differential-review` to identify risky changed files and functions.
2. Run `graph-evolution` and `trailmark-review-gate` on the same before/after
   range.
3. Cross-reference `FAIL` and `WARN` rules with changed source lines.
4. Add the gate packet to the review notes.
5. Treat `PASS` as "no configured graph rule fired", not as approval.

## With PR Review Processes

When an engagement has a separate PR review workflow, include:

- gate verdict
- triggered rules table
- exact changed nodes and paths
- manual reviewer actions
- limitations

Do not use GitHub write actions unless the review process explicitly asks for
them. The packet is review evidence, not an automatic merge decision.

## With Remediation Review

For a fix commit:

- compare vulnerable base to the proposed fix
- check that affected reachable paths changed as expected
- check that no new entrypoint or sensitive-sink path appeared
- report `UNKNOWN` if graph evidence cannot confirm the structural change

This does not replace semantic verification that the original finding was
fixed.
