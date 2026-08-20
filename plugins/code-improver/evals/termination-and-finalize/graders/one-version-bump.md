---
type: regex
target:
  source: file
  path: fixture/changelog-writer/.claude-plugin/plugin.json
match: contains
weight: 1
---
"version":\s*"1\.(0\.1|1\.0)"
