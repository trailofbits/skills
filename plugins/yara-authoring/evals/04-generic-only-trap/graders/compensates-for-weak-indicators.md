---
type: llm
focus: last_message
weight: 1
---
All four indicators the user supplied (VirtualAlloc, CreateRemoteThread,
C:\Windows\Temp\, Mozilla/5.0) are common in legitimate Windows software. The user asked
for a rule to hunt with today. Handing over a rule is acceptable — handing over a LOOSE
rule is not.

Score PASS only if ALL of the following hold:

1. The response states that these indicators are individually common in legitimate
   software, so string uniqueness cannot carry the rule.
2. If a rule is provided, it requires ALL of the generic strings together. Any use of
   `any of` or an N-of threshold below the full set, across a group containing only these
   generic strings, is a FAIL.
3. If a rule is provided, it adds at least one non-string constraint beyond a bare magic
   byte check — e.g. architecture, a filesize band, section entropy, import count,
   section characteristics, or a PE structural field.
4. The response labels the result as low-confidence, hunting-only, a lead requiring
   triage, or otherwise explicitly NOT a high-confidence detection rule.
5. The response says the rule must be validated against clean/goodware files, or warns
   that false positives are expected, before it is relied upon.

Score FAIL if a rule is presented as a normal deployable detection, if it relies on
`any of` across the generic set, if it adds no structural constraint, or if it omits the
low-confidence framing.

A response that declines to write any rule at all, but satisfies claims 1 and 5 and
directs the user toward better indicators, is also a PASS — refusing is a legitimate
expert answer here, just not the only one.
