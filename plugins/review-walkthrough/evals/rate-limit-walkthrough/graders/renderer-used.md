---
type: tool_used
weight: 2
arm: with-only
tool: Bash
input_match: render_walkthrough.py
---
The skill supplies a renderer that validates the complete diff and review
anchors. The run must execute it rather than replacing it with handwritten
template substitution. The artifact graders separately require the output file.
This plugin-specific invocation check is excluded from scores in a with/without
comparison, so a baseline cannot lose points for lacking the bundled renderer.
