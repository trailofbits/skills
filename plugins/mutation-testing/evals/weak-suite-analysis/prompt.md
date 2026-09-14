---
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write]
---
A mewt mutation testing campaign finished on the `vault` crate supplied as the
additional `fixture` directory. Its results are in `fixture/mewt-results.json`
(uncaught mutants) and `fixture/mewt-status.txt` (campaign totals); the crate
source and its test suite are alongside them.

Turn those results into a formal analysis report. Analyze every surviving mutant
individually, work out which ones are real testing gaps and which are false
positives, and prioritize the real ones. Read the source at each mutation site —
`u64` balances and unsigned comparison behavior are load-bearing here.

Write the report to `mutation-testing-report.md` in the current working
directory. Do not re-run the campaign, and do not modify anything under
`fixture/` — the campaign is already complete and this is a read-only analysis.

This run is headless, so do not stop to ask questions. Use "Vault Fixture" as
the project name and mewt 4.0.0 as the tool, and state any other assumption in
the report rather than pausing for it.
