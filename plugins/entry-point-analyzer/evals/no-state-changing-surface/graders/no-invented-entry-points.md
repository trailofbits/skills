---
type: llm
weight: 1
---

The eight ABI members are `quote`, `quoteBatch`, `isRouter`, `bpsToWad` and the generated getters
`baseFeeBps`, `maxFeeBps`, `router` and `tierOf`. All are `view` or `pure`. `_clamp` is internal
and the constructor is not reachable after deployment.

None of them may be presented as a state-changing entry point. Naming them as read-only, listing
them under an explicit exclusions heading, or explaining that `tierOf` is written once in the
constructor and never again are all correct and must not be counted against the response.

Fail if the response:

- lists any of the eight in a table or list of entry points, including one headed "read-only entry
  points" or "view entry points" and presented as part of the attack surface;
- lists `_clamp` or the constructor as externally callable;
- calls `quoteBatch` state-changing because it accumulates into `total`, which is a local variable;
- calls `quote` state-changing because it reads the `tierOf` mapping.

Saying nothing at all is not scored here. That is `states-surface-is-empty`.
