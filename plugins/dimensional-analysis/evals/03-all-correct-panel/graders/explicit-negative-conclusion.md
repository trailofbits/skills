---
type: llm
focus: last_message
weight: 1
---
A sweep that finds nothing has to say so. A clean result is a result, and a response
that walks through five helpers without ever committing leaves the reader to guess
whether the release is safe.

**PASS** if the response states plainly that none of the five has a unit or scaling
bug: that the sweep came back clean, that all five are dimensionally sound, or
equivalent. A per-helper verdict of "correct" on all five also passes; the conclusion
does not have to be one summary sentence.

**FAIL** if the response describes each helper without ever reaching an overall
verdict, or if it ends ambiguously: trailing off into next steps, listing things to
check later, or leaving open whether any of the five is wrong.

Judge only whether a clear negative conclusion is reached. Whether that conclusion is
correct is graded separately by `precision-floor-zero-bugs`; do not consider
correctness here.
