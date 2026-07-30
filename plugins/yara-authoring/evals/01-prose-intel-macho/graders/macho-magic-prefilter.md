---
type: regex
target:
  source: file
  path: larkspur.yar
match: contains
flags: i
---
uint32\(0\)\s*==\s*0x(FEEDFACF|FEEDFACE|CAFEBABE)
