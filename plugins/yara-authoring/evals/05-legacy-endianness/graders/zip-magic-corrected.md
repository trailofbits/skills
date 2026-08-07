---
type: regex
target:
  source: file
  path: migrated.yar
match: contains
flags: im
weight: 1
---
^(?:[^/\n]|/(?![/*]))*(?:uint32\(0\)\s*==\s*0x04034B50|uint32be\(0\)\s*==\s*0x504B0304)
