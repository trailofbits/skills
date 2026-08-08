---
type: llm
weight: 1
---

Nine ABI members of StakingVault cannot change state and must not be presented as attack
surface: the compiler-generated getters for the public
variables `owner`, `keepers`, `paused`, `balances`, `totalStaked` and `pool`; the `view` functions
`previewWithdraw` and `pauseStatus`; and the `pure` function `quoteFee`. The skill's own scope
section excludes `view` and `pure`.

None of those nine may appear in the report as a state-changing entry point. Elsewhere they can be
named freely. An explicit "excluded, read-only" list, a note that `previewWithdraw` is a view
helper, and a sentence explaining that public variables generate getters are all correct
behaviour, and must not be counted against the response.

The internal functions `_credit` and `_requireOwner`, and the constructor, are likewise not entry
points. Listing any of them as externally reachable also fails.

Fail if the response:

- puts any of the six getters, `previewWithdraw`, `pauseStatus` or `quoteFee` in a table or list of
  entry points, including a table of read-only entry points presented as part of the attack surface;
- lists `_credit`, `_requireOwner` or the constructor as externally callable;
- gives a total entry point count that can only be reached by including read-only members.

A response that lists exactly the state-changing set and says nothing at all about the read-only
members passes. Silence is not over-reporting.
