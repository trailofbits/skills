---
type: regex
target:
  source: file
  path: migrated.yar
match: contains
flags: im
weight: 1
---
^(?:[^/\n]|/(?![/*]))*(?:uint32be\(0\)\s*==\s*0xCAFEBABE|uint32\(0\)\s*==\s*0xBEBAFECA)
