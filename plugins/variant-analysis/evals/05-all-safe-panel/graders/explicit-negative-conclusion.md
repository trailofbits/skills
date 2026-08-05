---
type: llm
focus: last_message
weight: 1
---
A hunt that finds nothing has to say so. Negative coverage is a result, and a response that
lists observations without ever reaching a conclusion leaves the reader to guess.

Pass if the response states plainly that none of the candidates is an instance of the bug —
that the search came back empty, no variants were found, all five are safe, or equivalent.
A per-candidate verdict of "not a variant" on all five also passes; the conclusion does not
have to be a single summary sentence.

Fail if the response describes each candidate without ever committing to an overall verdict,
or if it ends ambiguously — trailing off into next steps, listing things to investigate, or
leaving open whether any of the five is a variant.

Judge only whether a clear negative conclusion is reached. Whether that conclusion is
correct is graded separately; do not consider correctness here.
