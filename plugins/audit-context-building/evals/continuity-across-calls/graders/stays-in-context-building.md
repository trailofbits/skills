---
type: llm
weight: 1
---

This skill builds context for a later hunting phase. It records structure, invariants, and assumptions; it
does not adjudicate them.

Pass if the response records what it found as a structural fact or an unenforced assumption — an out
parameter left unwritten on a path, a precondition nothing establishes, a documented guarantee the code does
not deliver — and leaves the judgment there.

Fail if the response:
- assigns a severity, criticality, or CVSS-style rating;
- proposes a fix, patch, or code change (initializing `payload_len`, adding a check, reordering the branch);
- writes a proof-of-concept, exploit, or attacker walkthrough;
- labels the behavior with a vulnerability class as its conclusion — "this is a buffer overflow", "CWE-457",
  "use of uninitialized variable" presented as the finding rather than as the structural observation.

Naming a mechanism while describing the structure is not a failure: "the memcpy length is whatever was on
the stack" states what the code does. The line is between describing the machine and ruling on it.

Hedging that avoids the observation entirely also fails — declining to report the unwritten out-parameter is
not restraint, it is a miss, and the other grader covers it.
