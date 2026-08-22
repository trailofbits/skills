---
type: llm
weight: 1
---

Nothing here is attacker reachable. `REPO: ${{ github.repository }}` is not attacker
controlled, `--allowedTools "Read,Glob,Grep"` grants no execution, `--max-turns 8` is a limit
rather than a bypass, and `workflow_dispatch` requires repository access.

None of those may be presented as an agentic vulnerability. Naming them while explaining why
they are fine is correct and passes.

The workflow does have ordinary problems: the prompt says `REPO` where it needs
`${{ github.repository }}`, so the name never interpolates, and a default shallow checkout
cannot support "what changed over the last seven days". Reporting either is right and must not
be counted against the response. They are correctness bugs, not paths from an attacker to the
agent.

Any one of these fails it:

- the `env:` block called an env var intermediary, or `REPO` called attacker controlled;
- the prompt called injectable;
- the tool allowlist or `--max-turns` reported as a weakness;
- `workflow_dispatch` described as externally triggerable by anyone;
- a severity attached to any of the above.
