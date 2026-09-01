---
type: regex
target:
  source: file
  path: fixture/legacy/old_util.py
match: contains
weight: 2
---
^def first_word\(text\):\n    # FIXME: crashes on empty input; nobody has touched this module in years\.\n    return text\.split\(\)\[0\]\n$
