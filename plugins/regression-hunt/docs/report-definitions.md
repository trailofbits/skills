# Report definitions

S0 and S1 mean before and after the complete selected change, not severity.

| Outcome | Meaning |
| --- | --- |
| REPRODUCED_REGRESSION | New defect proved on live S0/S1, independently replayed and adjudicated |
| INCOMPLETE_FIX | Intended repair missed an input source, caller or usage |
| LATENT_BUG | Change exposed an existing defect |
| PREEXISTING_BUG | Failure was already reachable before the change |
| REJECTED | Cited evidence disproves a required regression criterion |
| UNRESOLVED | Required evidence, execution or review remains missing or contradictory |

Only REPRODUCED_REGRESSION contributes to confirmed totals. Duplicate mappings preserve all
affected changes but count the root cause once. An evidenced exclusion may finish without replay.
Missing proof is unresolved, not rejected.

Coverage COMPLETE means discovery finished, baselines are available, and every candidate has a
resolved decision. INCOMPLETE means unfinished discovery, unresolved candidates or missing
baselines. Stage records may be blocked; the report retains their explanations. Complete does
not mean bug-free.

| Severity | Demonstrated impact if triggered |
| --- | --- |
| Low | Narrow incorrect behavior, inconvenience or readily recoverable failure |
| Medium | Material feature loss, repeatable disruption or limited data exposure/loss |
| High | Broad disruption, substantial sensitive-data compromise or serious integrity loss |
| Critical | Exceptional widespread compromise with explicit evidence |

| Likelihood | Trigger in supported use |
| --- | --- |
| Low | Unusual configuration, edge case or demanding demonstrated prerequisites |
| Medium | Plausible non-default workflow or moderate prerequisites |
| High | Routine operation or readily reachable conditions |

Ratings need reasons and do not establish regression validity. Categories are VULNERABILITY,
FUNCTIONAL_BUG, PERFORMANCE and BUILD_TEST, as defined in the shared standard.

Reports retain source changes, patch intent, behavior, evidence, PoC/setup links, exclusions and
limitations. Confirmations are agent conclusions pending human review. Inspect the actual
source, setup and logs: hashes verify integrity, not measurements or causal reasoning. Verify
attacker prerequisites, incomplete-fix/old-defect exclusions, and ratings independently.
Compare the campaign index with the originally supplied change list. The helper validates indexed
records; input completeness and correct PR boundaries remain the preparing/reporting agents' work.
