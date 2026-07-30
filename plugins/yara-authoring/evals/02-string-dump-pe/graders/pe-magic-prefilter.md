---
type: regex
target:
  source: file
  path: tinhorn_loader.yar
match: contains
flags: i
---
uint16\(0\)\s*==\s*0x5A4D
