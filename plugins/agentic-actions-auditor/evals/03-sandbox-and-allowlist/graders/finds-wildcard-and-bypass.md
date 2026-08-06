---
type: llm
weight: 1
---

Two settings have to be reported, and they are different failures rather than one.
`allowed_non_write_users: "*"` removes user gating, so anyone who can comment can invoke the
agent. `--dangerously-skip-permissions` removes the approval boundary on what the agent then does.

Pass only if both appear as findings. Wording is free and the flag may be described rather than
quoted.

`Bash(*)` alongside `Bash(echo:*)` is not gated here, because a response can reasonably read
`Bash(*)` as subsuming the narrower entry and report the allowlist as one finding. Reporting the
subshell point separately is correct and adds nothing to this grader either way.

Noting that `allowed_non_write_users` takes effect only because `github_token` is supplied is a
sharper reading than the grader asks for. It passes.

Fail if the response:

- reports only one of the two;
- describes the allowlist as merely permissive without saying it admits any user;
- reads `allowed_non_write_users` as restricting the agent rather than gating who triggers it;
- states that the tool allowlist limits the blast radius, when `Bash(*)` is in it.
