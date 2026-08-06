---
type: llm
weight: 1
---

`receive()` credits the sender through `_credit`, so a bare value transfer to the vault changes
`balances` and `totalStaked` without any named function being called. It carries no name, so a
search for `function ` in the source does not return it.

`receive` has to appear in the surface being mapped, as a state-changing entry point anyone can
reach. Wording is free: "receive()", "the receive function", "plain ETH transfers" and "sending
value with empty calldata" all count. Naming it only in prose about the contract does not.

`fallback()` is not scored. It is externally reachable and payable but its body reverts, so
listing it, omitting it, or noting that it always reverts are all acceptable.

Four ways to fail it:

- `receive` omitted from the entry point list;
- `receive` shown only inside a code excerpt or a file description, never as reachable surface;
- the vault claimed to be fundable only through `stake`;
- `receive` treated as read-only, or excluded because it has no name.
