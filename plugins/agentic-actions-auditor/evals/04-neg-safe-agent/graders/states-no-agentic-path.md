---
type: llm
weight: 1
---

`schedule` and `workflow_dispatch` are not attacker-controlled events, so no external party can
supply input to this agent. The honest report commits to that.

Pass only if the response says there is no agentic attack path here, or no prompt injection route,
or that the workflow is sound on this axis. A response that recommends unrelated hardening, such
as pinning the action by digest or narrowing `issues: write`, still passes provided it states the
agentic conclusion.

Fail if the response:

- never reaches a conclusion and only describes the workflow;
- hedges so far that no verdict is recoverable, for example calling it "potentially risky" with
  no vector named and no statement that none was found;
- declines to answer without more context.

Silence fails. A report that lists nothing and concludes nothing is indistinguishable from one
that never read the file.
