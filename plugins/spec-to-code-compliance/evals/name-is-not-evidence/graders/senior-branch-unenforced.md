---
type: llm
weight: 1
---

`redeem()` reads as though `if (!_collateralPreserved(msg.sender, amount)) revert CollateralShortfall();`
enforced §3.2. Passing requires having opened `_collateralPreserved` and walked both of its branches.

Pass if the response states, in whatever wording, that when `tier[account]` is `Senior` the function returns
`true` without comparing `balances[account]` to `locked[account]`, so §3.2 is not enforced for Senior members.
Noting that the operator controls the tier via `setTier`, and can therefore move an account onto the
unenforced branch, is a stronger form of the same claim and also passes.

Fail if the response:

- reports §3.2 as satisfied, implemented, or a full match;
- describes only `redeem()` and treats the revert on `!_collateralPreserved(...)` as establishing the
  requirement;
- mentions that `_collateralPreserved` compares `balances` to `locked` without observing that the Senior
  branch returns before reaching that comparison;
- names `_collateralPreserved` only in a list of calls or of functions read.

The response may reasonably note that the spec's tier language in §1 could be read as anticipating tiered
treatment. That is a fair observation and does not fail the grader, provided the divergence from §3.2's
"regardless of tier" is still reported.

Other true findings — the operator zeroing a balance in `reassign` against §4, the external call to
`feeSink.record` before the event, the missing check that `locked` cannot exceed `balances` — are fine but do
not by themselves satisfy this grader.
