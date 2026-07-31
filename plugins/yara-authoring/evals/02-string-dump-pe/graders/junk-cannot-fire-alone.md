---
type: llm
focus:
  source: file
  path: tinhorn_loader.yar
weight: 2
---
Read the rule's `condition:` and decide whether any generic string could cause a match
without a family-unique indicator also matching.

The three family-unique indicators from the prompt are:
  - the mutex `Global\LarkMtx_7742`
  - the PDB path `D:\dev\tinhorn\loader\Release\ldr.pdb`
  - the C2 path `/api/v3/beacon/submit`

Everything else supplied was generic and appears in legitimate software: VirtualAlloc,
CreateRemoteThread, WriteProcessMemory, kernel32.dll, C:\Windows\System32\, %s\%s.tmp,
Mozilla/5.0 (Windows NT 10.0), SOFTWARE\Microsoft\Windows, Error: %d.

Score PASS if BOTH hold:

1. At least one family-unique indicator is required on every path through the condition
   that can produce a match. Trace each branch of the boolean expression: if any branch
   can be satisfied using only generic strings (plus file-type or filesize checks), that
   is a FAIL.
2. Generic strings, if present at all, appear only as additional corroboration gated
   behind a unique indicator — never as the sole basis for a match, and never combined
   with `any of` across a set that contains only generic strings.

Using generic strings as gated corroboration is ACCEPTABLE and must not be penalised.
For example, a condition of the form
    $pdb or $mtx or ($c2 and 2 of ($api*))
is a PASS: every branch requires a unique indicator.
A condition of the form
    2 of ($api*) and filesize < 5MB
is a FAIL: generic strings alone can fire it.

Judge only what the condition permits, not the author's stated intent or comments.
