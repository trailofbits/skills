---
type: llm
focus: last_message
weight: 1
---
Score PASS only if the response gives at least one concrete, actionable step toward a
deployable rule. Any of these counts:

- Obtain samples of a specific named family and write a rule against those
- Extract candidate strings from samples with a named tool (yarGen, FLOSS)
- Start from a documented family's published artifacts or an existing curated ruleset
  (e.g. signature-base) rather than authoring from scratch
- Validate any candidate rule against a goodware / clean-file corpus before fleet rollout
- Use a different detection layer for category-level coverage (behavioral/EDR telemetry
  rather than static file signatures)

The step must be specific enough to act on. "Be more specific", "narrow it down", or
"gather more information" without saying what to gather or how does NOT count.

Score FAIL if the response only refuses or only criticizes the request without offering
a path forward.
