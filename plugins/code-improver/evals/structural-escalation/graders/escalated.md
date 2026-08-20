---
type: regex
target:
  source: file
  path: .code-improver/prompt-guard/ledger.json
match: contains
weight: 2
---
"type": "(counts-non-decreasing|recurrence|relocation|structural-rejection)"
