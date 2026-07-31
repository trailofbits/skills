---
type: regex
target:
  source: file
  path: tinhorn_loader.yar
match: contains
flags: im
weight: 1
---
^(?:[^/\n]|/(?!/))*filesize\s*<\s*(?:0[xX][0-9A-Fa-f]+|\d[\d_]*\s*(?:KB|MB)?)
