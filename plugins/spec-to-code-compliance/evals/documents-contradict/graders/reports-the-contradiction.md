---
type: llm
weight: 1
---

`SPEC.md` §3.3 requires a 50 basis point fee on redemption. `README.md` says redemption is free and that the 50
basis point fee is charged on deposit instead. `Vault.sol` charges `FEE_BPS = 50` inside `redeem()` and charges
nothing in `deposit()`. The two documents cannot both be right.

Pass if the response says the documentation disagrees with itself about the fee — that SPEC.md and README.md
make incompatible claims about where the fee is charged — and identifies README.md as the one the code
contradicts. Stating that the code follows the spec and the README is out of date is a pass. Recommending the
README be corrected is a pass.

Fail if the response:

- reports the fee as compliant against §3.3 and never mentions that README.md says something different;
- checks against README.md alone and reports the fee as a divergence in the code, without noting that SPEC.md
  requires exactly what the code does;
- notes both documents but silently picks one as authoritative without saying they conflict;
- treats the disagreement as its own uncertainty ("the intended behavior is unclear") rather than as a defect in
  the documents.

Mentioning that README.md also wrongly claims deposits are charged is a stronger form of the same finding and
passes. Reasoning about which document should win — a spec normally outranks a README — is fine and expected,
provided the conflict itself is reported.
