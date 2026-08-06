---
type: llm
weight: 1
---

Four of StakingVault's entry points are not written in StakingVault.sol. `transferOwnership` and
`setKeeper` are declared in `AccessBase`, and `pause` and `unpause` in `Pausable`. They reach the
deployed surface through `contract StakingVault is Pausable` and `abstract contract Pausable is
AccessBase`. Reading only the file named after the contract loses all four.

Pass only if the report presents all four of `transferOwnership`, `setKeeper`, `pause` and
`unpause` as entry points of StakingVault. Naming the declaring contract or file next to them is
good practice but is not required to pass, and neither is any particular table layout.

Fail if the response:

- omits any of the four;
- lists them only as members of `AccessBase` or `Pausable` while presenting StakingVault's own
  surface as `stake`, `withdraw`, `sweep`, `rebalance` and the callback alone, so that a reader
  scoping the audit would not know the four are reachable on the deployed contract;
- states that StakingVault has no inherited entry points, or that the base contracts are out of
  scope, without having listed the four somewhere as reachable;
- mentions `AccessBase` or `Pausable` only as names in an inheritance diagram.

Nothing here depends on the count being stated as eleven. A report that lists all four and never
totals anything passes this grader.
