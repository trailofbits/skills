---
type: regex
weight: 1
target:
  source: file
  path: walkthrough.html
pattern: 'const STEPS = \[\s*\{(?:(?!"diff")[\s\S])*"diff":\s*"[^"]*@@ -\d+,?\d* \+\d+,?\d* @@'
match: contains
---
Asserts the **first** step carries genuine unified-diff text rather than a prose
summary: a real hunk header (`@@ -0,0 +1,37 @@`) has to appear inside its own
`diff` value.

Both restrictions are deliberate. Anchoring inside `"diff": "…"` stops a hunk
header in a review body from satisfying the check, and `(?:(?!"diff")[\s\S])*`
pins the match to the *first* `"diff"` key in the array, so a run that fabricates
step 1 and only diffs step 2 fails here instead of passing on step 2's evidence. A
lazy `[\s\S]*?` is not enough for that: it prefers the nearest match but
backtracks into a later step when the nearest one does not satisfy the rest of the
pattern, which is exactly the case being caught.

This grader checks the first step. The bundled renderer compares every step's
complete file patches against the captured branch diff and rejects omissions,
duplicates, and fabricated content.
