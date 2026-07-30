---
max_turns: 10
timeout_seconds: 300
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 3
---
I need a regex to pull failed SSH authentication attempts out of an `auth.log` file, and
ideally the ripgrep command to run it with. I want the source IP in a capture group so I
can count attempts per host afterwards.
