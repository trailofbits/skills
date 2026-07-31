---
type: llm
weight: 0.5
---

The plugin's output shape is one stated verdict per requirement, so a reader can tell which requirements were
checked from which were merely mentioned. Section 3 holds three: §3.1 availability and the zero-redemption
rejection, §3.2 collateral protection, §3.3 the 50 basis point fee.

Pass if each of the three is individually addressed with a stated outcome — a verdict word (`implemented`,
`partial`, `contradicted`, `absent`, `stronger-than-spec`, `undecidable`), a table row, or an unambiguous
sentence such as "the fee is charged as specified". The exact vocabulary does not matter; addressing each
requirement separately does.

Fail if the response covers section 3 as a single narrative that leaves any of the three without a stated
outcome, or if it discusses only the requirement it found a problem with and never says whether the other two
hold.

This grader is about coverage and not about correctness. A wrong verdict on §3.2 still passes here — the
`senior-branch-unenforced` grader is what judges that.
