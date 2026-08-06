---
type: llm
weight: 1
---

The data path is `github.event.comment.body` into `env: COMMENT_BODY`, then the prompt instructing
the agent to run `echo "$COMMENT_BODY"`. The prompt itself holds no `${{ }}`.

Pass only if the response connects both halves: that the comment body is attacker controlled and
reaches the environment, and that the prompt directs the agent to read it. A response that
describes the flow in its own words passes; the variable name does not have to be quoted.

Fail if the response:

- notes the `env:` block but never says the prompt consumes it, so the flow stops short of the
  agent;
- says the prompt is safe, clean, or free of injection because it contains no `${{ }}`
  expressions;
- reports only that `issue_comment` is a risky trigger, without the data path;
- treats `COMMENT_AUTHOR` as the finding while ignoring the body.
