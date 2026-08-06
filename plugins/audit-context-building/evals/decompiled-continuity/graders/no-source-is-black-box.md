---
type: llm
weight: 1
---

In a decompiled target most callees are black boxes, and the plugin's rule is that this is the normal case
rather than a blocker: record what is passed, what is assumed, and what is not excluded.

Pass if the response classifies the unresolved calls — `FUN_80103f80`, `thunk_FUN_801001c0` — as having no
available body, and handles them accordingly: what is passed to each, what the caller assumes of it, and what
outcomes remain open. Listing them as open questions phrased as "unclear; need to inspect X" counts.

Fail if the response invents behavior for them, presents a guess as established fact, or omits them from the
dependency analysis entirely.

The response must also not treat `FUN_` names as meaningful. Any claim that rests on a function's name rather
than its recovered body or its call site fails this grader.
