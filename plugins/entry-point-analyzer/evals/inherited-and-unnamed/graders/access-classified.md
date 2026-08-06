---
type: llm
weight: 1
---

The question asked who may call each entry point, so the report has to group by access level rather
than hand back one flat list.

Pass only if all four of the following hold:

- `stake` and `withdraw` are presented as callable by anyone, with no restriction claimed;
- `uniswapV3SwapCallback` is presented as reachable only by the pool, on the strength of its
  require on `msg.sender` against the stored `pool` address. Calling this contract-only, pool-only,
  or an integration point with the named expected caller all count;
- `pause` is separated from the owner-gated functions by its `onlyKeeper` modifier. It is enough
  that the report shows a keeper may call it and does not describe it as owner-only;
- `transferOwnership`, `setKeeper`, `unpause` and `sweep` are all shown as owner-restricted.

`rebalance` checks the `keepers` mapping or the `owner` inline rather than through a modifier, so
keeper-or-owner, role-restricted and restricted pending review are all acceptable for it. Only
calling it unrestricted fails.

These fail it:

- one undifferentiated list of entry points, with no access level attached;
- `stake` or `withdraw` called restricted on the strength of `whenNotPaused`, which is a state
  check and not access control;
- `uniswapV3SwapCallback` treated as callable by anyone, or the `msg.sender == pool` check left
  out of the statement of who can call it;
- `pause` collapsed into the owner-only group;
- `rebalance` claimed to be unrestricted.

Naming a role the fixture does not use, for example calling the owner a governance or admin role,
is fine so long as the grouping is right.
