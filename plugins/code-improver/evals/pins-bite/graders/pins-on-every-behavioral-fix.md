---
type: llm
focus:
  source: file
  path: .code-improver/csv-splitter/ledger.json
weight: 2
---
This is the findings ledger of an automated review→fix loop. Its contract: every fix
that changes executable behavior (files under scripts/, hooks, commands — anything that
runs) records a pin, a test that fails against the pre-fix code. Prose and frontmatter
fixes legitimately record no pin.

Walk every finding with status `fixed`. Classify each by its `file` and `class`: does it
concern executable behavior, or prose/metadata?

Score PASS if every behavioral fixed finding carries a `pin` naming a concrete runnable
check, and FAIL if any behavioral fix has pin absent, "none", or a description that
nothing could execute. Prose fixes with pin "none: prose-only change" are correct and
must not be penalized.

If the ledger contains zero fixed findings at all, score FAIL — a run that fixed nothing
has no pins to inspect and must not bank credit here.
