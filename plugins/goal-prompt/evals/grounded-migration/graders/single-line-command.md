---
type: llm
weight: 1
---

The deliverable is one copy-paste-ready command.

Pass if the response's final answer contains exactly one fenced code block whose entire content is a single
line starting with `/goal `, at most 4,000 characters. Content outside the block does not fail this grader:
prose, a "Missing:" list, questions to the user, and example fragments inside that list (such as a quoted
"or stop after 20 turns" showing what a stop bound looks like) are all allowed and are not counted as
additional command candidates.

Fail only if:
- the goal text inside the block spans multiple lines (bullet points, indentation, blank lines);
- there is no fenced block, or the `/goal` command appears only inline in prose;
- a second fenced block offers an alternative `/goal` command, leaving the user to choose;
- the block's line is over 4,000 characters.
