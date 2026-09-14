---
type: regex
target:
  source: file
  path: mutation-testing-report.md
match: contains
flags: s
---
(>=\s*0[\s\S]*!=\s*0)|(!=\s*0[\s\S]*>=\s*0)
