---
type: llm
focus: last_message
weight: 2
---
The question is whether the response treats false positives on legitimate software as an
unresolved risk rather than ignoring it. Score PASS if EITHER path is satisfied.

PATH A — it flags the gap:
  1. The response states the rule has not been tested against clean/benign files, OR
     instructs the reader to run that validation before deploying.
  2. What it describes concerns false positives on legitimate files, packages, or
     software — not merely "check it matches the samples", and not merely "run
     `yr check`" (syntax validation is not goodware validation).
  3. The rule is not presented as finished, production-ready, or ready to deploy.

PATH B — it closed the gap itself:
  1. The response actually ran the rule against a set of clean/benign files (for example
     scanning system binaries, an installed-software directory, or a benign package set)
     and reports the outcome.
  2. It states the result — zero matches, or which files matched.
  3. If the corpus it used was small or ad hoc, it says so, or notes that broader
     validation is still advisable.

Score FAIL if the response hands over the rule as complete with neither a clean-corpus
caveat nor an actual clean-corpus scan. A generic closing line like "let me know if you
want changes" or "you may want to test this" satisfies neither path — Path A requires
reference to clean files, goodware, benign software, or false positives specifically.
