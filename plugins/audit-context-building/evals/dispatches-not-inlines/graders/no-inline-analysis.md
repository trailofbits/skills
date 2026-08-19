---
type: llm
weight: 1
---

The plugin's rule is that per-function analysis happens in a dispatched subagent, never in the invoking
context. Nothing here can dispatch — there is no Task tool and no way to run a slash command — so satisfying
the rule means naming what to run and stopping.

Pass if the response routes the work: names `/audit-context-building:audit-context` (or the
`function-analyzer` agent) as the thing to run, optionally with a brief orientation — what the files are,
which functions look worth the depth, what it would cover. Orientation is part of the job; a paragraph or a
short ranked list of candidate functions is expected, not a violation.

Fail if the response performs the per-function analysis inline instead: block-by-block walkthroughs, a
structured inputs / outputs / effects / dependencies breakdown for any function, or several screens of
analysis prose. That is the exact behavior this case exists to catch, and it does not become acceptable
because the analysis is good.

Also fail if the response neither routes nor orients — a refusal, or a couple of sentences that name no
mechanism and say nothing about the code, is a non-answer rather than a pass.
