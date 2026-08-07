---
type: regex
target:
  source: file
  path: tinhorn_loader.yar
match: contains
flags: m
weight: 1
---
^(?:[^/\n]|/(?![/*]))*LarkMtx_7742
