---
type: regex
weight: 3
target:
  source: file
  path: walkthrough.html
pattern: 'b/app/middleware\.py[\s\S]*"message":\s*"[\s\S]*b/ratelimit/bucket\.py'
match: not_contains
---
The ordering check, and the highest-weighted grader in the case: step order is
what makes a walkthrough worth reading. The skill asks for definitions before
their consumers.

`app/middleware.py` imports `TokenBucket`, so a reviewer who meets the middleware
first has to hold an undefined symbol in their head. Because STEPS is serialized
in presentation order, ordering is expressible as a regex over the artifact.

Written as a violation to *not* find, rather than as the order to find, because
the unit is the **step**, not the file. `"message":` is the step boundary: every
step object carries one, ahead of its `files` and `diff`, so two paths with a
`"message":` between them are in different steps and two paths without one are in
the same step. The pattern therefore fires only when middleware's step genuinely
precedes bucket's.

That distinction matters because the skill permits merging small files into
one step, and git emits files within a step in path order: `b/app/middleware.py`
sorts before `b/ratelimit/bucket.py`. A plain `bucket.*middleware` contains-pattern
would fail that grouping, which is correct output, and this is the heaviest grader
in the case.

The boundary marker is the `"message":` key rather than a `"sha"` value because
the sha is whatever the run named its steps, while `message` is required for the
page to render a header at all.

Matching on `b/`-prefixed diff-header paths rather than bare filenames also
matters: `bucket.py`'s own diff contains `from ratelimit.config import ...` and
middleware's contains `from ratelimit.bucket import ...`, but those use dots, so
they cannot satisfy the pattern by accident.

Deliberately *not* asserted: that `config.py` precedes `bucket.py`. Grouping both
definitions into one step is a legitimate reading.

The renderer requires each file's complete patch to appear in exactly one step,
so a file cannot appear on both sides of a step boundary.
