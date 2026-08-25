# Ablation: v2 workflow (arm A) vs v1.1.0 stop-hook loop (arm B)

Runs the same eval cases against this plugin and against the last stop-hook version,
checked out from git into a temporary marketplace. Paid, manual, never CI.

**Measured 2026-08** (three arms — v2, main's 1.0.5, and 1.1.0 — run manually with this
script's protocol): the scorecard and its honest reading live in the parent
[README](../README.md), "Measured results". Headline: v2 medians 1.00 on all five cases;
old arms 0.00–0.71, losing on escalation, version discipline, honest exits, and every
artifact check, while matching v2 on raw defect-fixing.

```sh
./run.sh --baseline-ref <commit-with-v1.1.0> [--runs 3] [--case structural-escalation]
```

Run `structural-escalation` first — it is the discriminating case (arm B has no
oscillation detection at all, so it is expected to burn to its iteration cap).

## What is compared

Per case, per arm, median over runs (min–max shown):

| Metric | Arm A source | Arm B source |
|---|---|---|
| grader score | eval harness JSON | eval harness JSON |
| `rounds_used`, `refiled_after_verdict`, `ended_on_unreviewed_fix`, `max_consecutive_rounds_same_finding`, `fixer_failed_rounds` | `metrics.json` (ledger-derived) | **UNAVAILABLE** — v1.1.0 keeps no per-round artifacts; see below |
| `narration_hits_final` | `metrics.json` | recomputed from the final workspace by `scorecard.py` (same patterns, imported from `collect_metrics.py`) |
| `out_of_scope_diff_bytes` | `metrics.json` | recomputed from the workspace's git state |
| `version_bumps` | `metrics.json` | recomputed from the workspace's git diff |
| `converged` / honest exit | `metrics.json` + graders | graders only |

**Deviation from the handoff (§4c), stated plainly:** the handoff proposed reconstructing
arm B's per-round metrics from git history plus review outputs saved each round. v1.1.0
saves no such outputs — its loop lives in a stop hook and a state file — so those metrics
cannot be reconstructed without instrumenting the baseline, which would change the thing
being measured. The scorecard prints them as UNAVAILABLE rather than as zeros; treat the
grader scores and the workspace-derived metrics as the cross-arm comparison. The
ledger-derived columns exist to show what A *makes measurable*, which is itself part of
the claim.

The scorecard fails loudly (exit 2) if an arm contributes zero run workspaces — a baseline
arm that silently did nothing must not score as "0 refiled findings". Every metric is
reported for both arms, including the ones where A loses; the scorecard does no
pre-filtering.

## Success thresholds (coarse on purpose, from the handoff)

- `structural-escalation`: A escalates in ≤ 4 rounds; B expected to hit its cap.
- `refiled_after_verdict`: A ≤ 1 per trap; B expected ≥ 2 (visible only via graders/
  transcripts for B — see the deviation note).
- `ended_on_unreviewed_fix`: A never.
- `out_of_scope_diff_bytes`: A = 0.

## Cost

Fixtures are ~10 small files with `max_turns` caps; expect roughly 5–15 minutes and low
single-digit dollars per run. 2 arms × 4 cases × 3 runs ≈ 24 runs — budget accordingly,
and pilot with `--runs 1 --case structural-escalation` (~2 runs) before committing.
