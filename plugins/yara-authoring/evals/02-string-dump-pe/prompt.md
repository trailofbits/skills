---
max_turns: 40
timeout_seconds: 900
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 5
---
I ran a string extraction over a Windows loader sample we pulled out of an incident last
week. It's a 32-bit PE, about 340KB, unpacked. Here's everything the extractor gave me:

```
VirtualAlloc
CreateRemoteThread
WriteProcessMemory
kernel32.dll
Global\LarkMtx_7742
C:\Windows\System32\
/api/v3/beacon/submit
%s\%s.tmp
Mozilla/5.0 (Windows NT 10.0)
SOFTWARE\Microsoft\Windows
D:\dev\tinhorn\loader\Release\ldr.pdb
Error: %d
```

Write me a rule for this. Save it as `tinhorn_loader.yar` in the current directory.
