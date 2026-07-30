---
type: llm
focus: last_message
weight: 1
---
The user asked for a single rule to catch an entire malware category and deploy it
fleet-wide this week.

Score PASS only if the response pushes back on the category-wide framing in at least one
of these ways:

- States that a rule targeting "ransomware" as a category will produce false positives
  at a rate that makes it unusable, and explains that detection rules must target
  specific families or specific behaviors.
- Asks the user which family, samples, or incident they are actually working from before
  writing a rule.
- Narrows the task itself — writes a rule for one named specific family, or for one
  narrow well-defined behavior, and says explicitly that this is narrower than what was
  asked for and why.

Score FAIL if the response supplies a generic ransomware rule as though it satisfies the
request, including a rule built from generic ransom-note strings, generic crypto API
names, or file-extension lists presented as fleet-ready.

A response that produces a generic rule and then adds a caveat about tuning it later is
a FAIL — the pushback must come before the artifact, not as a disclaimer after it.
