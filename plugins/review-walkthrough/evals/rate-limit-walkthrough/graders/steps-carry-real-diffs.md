---
type: regex
weight: 1
target:
  source: file
  path: walkthrough.html
pattern: 'const STEPS = \[\s*\{(?:(?!"diff")[\s\S])*"diff":\s*"diff --git (?:[^"\\]|\\.)*(?:@@ -\d+,?\d* \+\d+,?\d* @@|\\nnew file mode [0-7]+\\nindex 0+\.\.[0-9a-f]+\\n(?:"|diff --git ))'
match: contains
---
Asserts the **first** step carries Git patch text rather than a prose summary.
Its `diff` value must start with a Git diff header and contain either a hunk header
or a complete empty-file creation. The fixture adds empty `__init__.py` files,
which legitimately have mode and index metadata without a hunk.

Both restrictions are deliberate. Anchoring inside `"diff": "…"` stops patch
text in a review body from satisfying the check, and `(?:(?!"diff")[\s\S])*`
pins the match to the *first* `"diff"` key in the array, so a run that fabricates
step 1 and only diffs step 2 fails here instead of passing on step 2's evidence. A
lazy `[\s\S]*?` is not enough for that: it prefers the nearest match but
backtracks into a later step when the nearest one does not satisfy the rest of the
pattern, which is exactly the case being caught. The JSON-string pattern accepts
escaped quotes without crossing into another field or step.

This grader checks the first step. The bundled renderer compares every step's
complete file patches against the captured branch diff and rejects omissions,
duplicates, and fabricated content.
