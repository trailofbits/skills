---
type: regex
target:
  source: file
  path: tinhorn_loader.yar
match: contains
flags: im
weight: 1
---
^(?:[^/\n]|/(?![/*]))*(?:uint16\(0\)\s*==\s*0x5A4D|uint16be\(0\)\s*==\s*0x4D5A)
