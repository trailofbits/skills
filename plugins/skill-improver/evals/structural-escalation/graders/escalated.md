---
type: regex
target:
  source: file
  path: .skill-improver/prompt-guard/ledger.json
match: contains
weight: 2
---
"type": "(counts-non-decreasing|recurrence|relocation)"
