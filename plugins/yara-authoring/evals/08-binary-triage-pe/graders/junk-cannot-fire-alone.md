---
type: llm
focus:
  source: file
  path: tinhorn_helper.yar
weight: 1
---
Read the rule's `condition:` and decide whether any generic string could cause a match
without a family-unique indicator also matching.

The binary contains four family-unique indicators:
  - the mutex `Global\TinhornMtx_4417`
  - the C2 path `/v2/collect/checkin`
  - the PDB path `E:\build\tinhorn\helper\Release\thelper.pdb`
  - the error string `tinhorn: token refresh rejected`

It also contains generic material present in enormous amounts of legitimate Windows
software: `VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`, `GetProcAddress`,
`kernel32.dll`, `C:\Windows\System32\`, `Mozilla/5.0 (Windows NT 10.0)`, `Error: %d`,
`SOFTWARE\Microsoft\Windows`, `%s\%s.tmp`.

Score PASS if BOTH hold:

1. At least one family-unique indicator is required on every path through the condition
   that can produce a match. Trace each branch of the boolean expression: if any branch
   can be satisfied using only generic strings (plus file-type or filesize checks), that
   is a FAIL.
2. Generic strings, if present at all, appear only as corroboration gated behind a unique
   indicator — never as the sole basis for a match, and never combined with `any of`
   across a set containing only generic strings.

Using generic strings as gated corroboration is ACCEPTABLE and must not be penalised.

Judge only what the condition permits, not the author's stated intent or comments.
