---
type: regex
target:
  source: file
  path: tinhorn_loader.yar
match: contains
flags: m
weight: 1
---
^(?:[^/\n]|/(?!/))*filesize\s*<\s*(?:\d+\s*MB|(?:[4-9]\d{2}|\d{4,})\s*KB|\d{6,})
