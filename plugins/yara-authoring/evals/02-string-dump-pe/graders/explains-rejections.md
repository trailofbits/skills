---
type: llm
focus: last_message
weight: 2
---
The prompt supplied twelve extracted strings, most of which are unusable as detection
indicators. Score PASS only if BOTH hold:

1. The response identifies specific supplied strings it did NOT use in the rule — it
   names at least two of them explicitly. Candidates it should be rejecting:
   VirtualAlloc, CreateRemoteThread, WriteProcessMemory, kernel32.dll,
   C:\Windows\System32\, %s\%s.tmp, Mozilla/5.0 (Windows NT 10.0),
   SOFTWARE\Microsoft\Windows, Error: %d.
2. It gives a reason grounded in those strings not being specific to this malware —
   e.g. they are Windows API names, standard system paths, format specifiers, generic
   registry paths, or a common user-agent, all of which appear in legitimate software.

Score FAIL if the response silently uses a subset without saying what it dropped, or if
its only stated reason is stylistic (e.g. "I kept it concise") rather than about the
strings lacking specificity to this family.
