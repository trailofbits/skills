---
type: regex
target:
  source: file
  path: migrated.yar
match: not_contains
flags: im
weight: 1
---
^(?:[^/\n]|/(?![/*]))*uint32\(0\)\s*==\s*0x(?:CAFEBABE|504B0304)
