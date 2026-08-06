---
type: llm
weight: 1
---

The point of this fixture is that the prompt looks clean. A response can trace the flow correctly
and still tell the reader the wrong thing about it.

The clean-looking prompt must not be offered as evidence of safety. Saying the pattern is easy
to miss, or that it defeats a grep for `${{ }}`, is the correct reading and passes.

Three things fail. Calling the prompt safe because it holds no expressions, anywhere in the
report and even beside a correct finding elsewhere. Recommending that expressions be moved out
of prompts into env vars, which is already this fixture's shape. Concluding that the workflow is
safe to leave enabled.
