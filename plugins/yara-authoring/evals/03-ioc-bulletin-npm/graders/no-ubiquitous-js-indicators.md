---
type: regex
target:
  source: file
  path: tinhorn_npm.yar
match: not_contains
---
"require"|"fetch"|"axios"
