---
type: llm
weight: 1
---

Being out of scope for the agentic vectors is not a reason to hand back nothing.
`${{ github.event.issue.title }}` is interpolated into a `run:` block twice, which is shell
injection into a step that holds `GH_TOKEN`.

Reporting that injection in whatever words passes, and so does pointing the reader at general
Actions tooling that will catch it. Doing both is better and is not required.

Saying nothing about the `run:` block fails. So does declaring the workflow safe, or refusing to
comment at all because the skill does not apply.
