---
type: regex
weight: 2
target:
  source: file
  path: walkthrough.html
pattern: '\n\s*<(?:title|h1)>[A-Z_]*PLACEHOLDER|\nconst [A-Z_]+ = [A-Z_]+_PLACEHOLDER;'
match: not_contains
---
The artifact must contain rendered data, not an unpopulated template. A surviving
`STEPS_PLACEHOLDER` is invalid JavaScript and leaves the page blank even if a
transcript describes the intended result.

The pattern matches the template's own placeholder sites rather than the bare word,
because the word may legitimately appear in the *diff under review*. Templating
code, including this plugin, can contain it. The
anchor that separates the two is a real newline: `json.dumps` escapes newlines
inside the embedded values as `\n`, two characters, so a literal newline in the
artifact is always the template's own structure and never content from the diff.
