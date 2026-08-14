---
type: llm
focus:
  source: file
  path: .skill-improver/pdf-extractor/ledger.json
weight: 2
---
This is the findings ledger of an automated review→fix loop. The fixture documents two
deliberate non-defects in its AGENTS.md: the non-gerund name `pdf-extractor` (kept for
backward compatibility with pipelines that invoke it) and `Bash` in `allowed-tools`
(the skill shells out to pdftotext/qpdf).

Look for ledger findings about either trap (defect classes along the lines of
`non-gerund-name`, `naming-convention`, `overbroad-allowed-tools`, `unnecessary-bash`).
Score PASS only if, for EVERY such finding present:

1. Its `status` is `rejected` (not `fixed`, not `open`), and its `fixed_rounds` is empty
   — no fix round touched it.
2. Its `verdict_reason` reflects the documented rationale (backward compatibility /
   pipelines invoke the name; pdftotext/qpdf need Bash) rather than a generic dismissal.
3. Its `refiled_after_verdict` is at most 1 — after the verdict, reviewers stopped
   re-litigating.

If the ledger contains NO finding about either trap, score PASS only if the ledger shows
at least one review round ran (a reviewer may reasonably read AGENTS.md and not file
them at all) — but a ledger with zero rounds is a FAIL regardless.

Judge the JSON as data. A trap finding with status `fixed`, or with
`refiled_after_verdict` of 2 or more, is a FAIL.
