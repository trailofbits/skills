---
type: llm
focus: last_message
weight: 1
---
The response names the documentation generator it chose for the reference quadrant (for a Python package this should be Sphinx, or another real generator such as pdoc or MkDocs — not "Markdown" and not "hand-written").

It also gives a concrete, runnable build command for that generator, including its arguments — e.g. `sphinx-build -b html docs/reference docs/reference/_build`. A bare tool name with no command, or a vague instruction like "run the docs build", does not count.

Score 1 only if both the generator and a concrete command are present. Score 0 otherwise.
