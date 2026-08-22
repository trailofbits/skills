---
type: llm
weight: 1
---

`triage.yml` puts `${{ github.event.issue.title }}` and `${{ github.event.issue.body }}` directly
into the `prompt:` field of the Claude Code step. The `issues` trigger fires for any GitHub user,
so both values are attacker controlled.

Pass only if the response identifies that attacker-controlled issue content reaches the agent's
prompt in `triage.yml`. Wording is free: prompt injection, untrusted input in the prompt, or the
issue body being interpolated into the instructions all count. Naming only one of the two fields
is enough.

Fail if the response:

- does not mention the prompt field of `triage.yml` at all;
- describes the workflow without saying the interpolated data is untrusted, for example listing
  the expressions as configuration worth noting;
- reports the issue only as a general template-injection or unpinned-action problem, without
  placing it in the agent's prompt;
- claims the `permissions:` block or the `secrets.ANTHROPIC_API_KEY` reference is the finding.
