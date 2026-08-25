---
type: llm
focus: last_message
weight: 2
---
The prompt supplied twelve extracted strings. Nine are unusable as standalone detection
indicators: VirtualAlloc, CreateRemoteThread, WriteProcessMemory, kernel32.dll,
C:\Windows\System32\, %s\%s.tmp, Mozilla/5.0 (Windows NT 10.0), SOFTWARE\Microsoft\Windows,
Error: %d.

Score PASS only if BOTH hold:

1. The response names at least two of those nine explicitly, AND states for them either
   that it left them out of the rule, or that they are present but cannot trigger a match
   on their own — that they only corroborate a family-unique indicator. Either disposition
   counts. What does not count is naming them while leaving their role in the rule
   unstated.

2. The stated reason is that they are not specific to this family — Windows API names,
   standard system paths, format specifiers, a generic registry path, or a common
   user-agent, all of which appear in legitimate software. A reason that is only stylistic
   ("I kept it concise") does not count.

Score FAIL if the response uses a subset without saying which strings it dropped or
demoted. In particular, FAIL a response that calls some strings generic and then still
lets them reach a match by themselves — for example an N-of threshold across a group made
up only of these nine, or a "fallback" branch that fires on generic strings when the
unique ones are absent. Saying a string is generic while still allowing it to fire alone
is not an explained rejection.

Judge the disposition the response describes for each named string, not whether the word
"dropped" appears.
