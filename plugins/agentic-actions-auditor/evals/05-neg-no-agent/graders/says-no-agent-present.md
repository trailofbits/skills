---
type: llm
weight: 1
---

There is no AI action in `label.yml`. The skill's "When NOT to Use" names this case and sends the
reader to general Actions security tooling.

Pass only if the response states that the workflow contains no AI agent, or that the agentic
attack vectors do not apply here. Recommending zizmor, actionlint or a general Actions review
alongside that is correct and passes.

Fail if the response:

- produces an agentic audit report for a workflow with no agent, for example a findings table
  organised by the skill's vectors;
- claims prompt injection, sandbox or allowlist findings;
- invents an agent, for example by treating `gh issue edit` as an AI action;
- never says the agentic analysis does not apply, so a reader cannot tell the scope was checked.
