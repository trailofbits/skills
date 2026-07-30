---
max_turns: 10
timeout_seconds: 300
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 3
---
Write me a Semgrep rule that detects hardcoded API keys and secrets assigned to variables
in Python source files. It should catch things like `API_KEY = "sk-live-abc123"` but not
flag values read from the environment. Give me the rule YAML.
