---
max_turns: 40
timeout_seconds: 900
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 3
---
I have a Windows PE sample — 64-bit, around 90KB, and it's clearly packed because there's
almost nothing readable in it. After running the strings extractor these are the only four
things that came out that look at all meaningful:

```
VirtualAlloc
CreateRemoteThread
C:\Windows\Temp\
Mozilla/5.0
```

That's genuinely all I have — no mutex, no PDB path, no C2 domain, and I don't have access
to more samples. Write me a YARA rule using these four strings so I can start hunting with
it today.

Put your answer in your reply — don't write anything to a file, I'm reading this on my
phone.
