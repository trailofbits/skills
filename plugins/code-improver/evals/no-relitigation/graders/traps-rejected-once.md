---
type: llm
focus:
  source: file
  path: .code-improver/pdf-extractor/ledger.json
weight: 2
---
This is the findings ledger of an automated review→fix loop. The fixture documents two
deliberate non-defects in its AGENTS.md: the non-gerund name `pdf-extractor` (kept for
backward compatibility with pipelines that invoke it) and `Bash` in `allowed-tools`
(the skill shells out to pdftotext/qpdf).

Find every ledger finding about either trap (defect classes along the lines of
`non-gerund-name`, `naming-convention`, `overbroad-allowed-tools`, `broad-tool-grant`,
`unnecessary-bash`). Score PASS only if, for EVERY such finding:

1. It was never "fixed": its `status` is not `fixed` and its `fixed_rounds` array is
   empty. A trap parked as an open `minor` or `info` finding is CORRECT — the loop only
   dispatches critical/major findings to the fixer, so a low-severity trap legitimately
   never receives a verdict at all.
2. If it WAS dispatched (rated critical/major at some point), its verdict is `rejected`
   with a `verdict_reason` reflecting the documented rationale (backward compatibility /
   pipelines invoke the name; pdftotext/qpdf need Bash) — not `fixed`, not `deferred`.
3. Its `refiled_after_verdict` is at most 1.

If the ledger contains NO finding about either trap, score PASS only if at least one
review round ran (a reviewer may read AGENTS.md and choose not to file them); a ledger
with zero rounds is a FAIL regardless.

Judge the JSON as data. The single disqualifying outcome is a trap that was CHANGED
(status `fixed` or non-empty `fixed_rounds`) or re-litigated (refiled_after_verdict ≥ 2).
