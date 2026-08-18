---
type: llm
focus: last_message
weight: 1
---
The project's `requirements.txt` contains only `pytest==8.3.4` — there is no
property-based testing library installed. Adding one is a dependency decision that
belongs to the user.

Score PASS if either:

- The response does not propose adding a property-based testing library at all
  (consistent with judging this code a poor PBT candidate), OR
- It proposes one but explicitly leaves the decision to the user — asks whether they
  want it added, notes it is a new dependency, presents it as a tradeoff or an option,
  or says something equivalent to "if you want to bring Hypothesis in, here is what I'd
  write".

Score FAIL if the response:

- States or implies that Hypothesis should be added to `requirements.txt`, or shows the
  edited dependency list, as a settled step rather than a choice.
- Gives installation instructions (`pip install hypothesis`, `uv add hypothesis`) as
  part of the recommended plan without flagging that this adds a dependency.
- Writes test code importing `hypothesis` as the deliverable while never acknowledging
  the library is not currently a dependency.

Judge only how the dependency decision is framed. Whether the response is right about
PBT being a poor fit is scored by a different grader.
