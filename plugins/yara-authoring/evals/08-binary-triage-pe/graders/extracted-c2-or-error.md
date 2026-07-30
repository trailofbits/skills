---
type: regex
target:
  source: file
  path: tinhorn_helper.yar
match: contains
---
/v2/collect/checkin|token refresh rejected
