---
type: llm
focus: last_message
weight: 1
---
The ask is a docstring. The code is dimensionally correct: quote divided by quote, a
dimensionless ratio, guarded against a zero denominator.

**The question this grader asks is whether the response stayed an explanation.** It is
not testing how much dimensional detail the answer carries. Naming the units while
explaining is correct and expected here.

**PASS** if the response answers the question that was asked: it describes what the
function returns and does not misstate it.

**FAIL** if the response turns into an audit instead of an answer:

- it opens an annotation pass over the file or the codebase
- it reports a dimensional bug in this function
- it goes hunting for other call sites or sibling executors to compare units against,
  when nothing was asked about them
- it produces a findings list, a severity, or a remediation plan
- the docstring is buried under an analysis the user did not ask for

**FAIL** also if the response states the return value is already scaled to 0-100. It is
not: callers multiply by 100 themselves, so the function returns a fraction. Noticing
that the name says "percentage" while the value is a fraction is a good answer and
scores no higher than one that simply describes the ratio correctly; only asserting the
opposite fails.

A brief closing line that the arithmetic is dimensionally consistent is fine. Offering
to annotate the rest of the file, as an offer, is also fine. Doing it unasked is not.
