"""Score a whole run: anti-cheat first, then recall, false positives and cost.

Order matters. The anti-cheat verdict is computed **before** any number is printed,
and a non-VALID arm's numbers are excluded from the comparison table rather than
printed with a caveat. A footnote next to a recall figure does not survive being
copied into a summary; an arm missing from the table does.

Three verdicts, not two:

- `VALID` — transcripts inspected, no oracle use found.
- `INVALID` — an oracle was used, or the arm declared external sources. Excluded.
- `UNVERIFIABLE` — no transcript was supplied, so nothing was inspected. Also
  excluded, because "we did not look" and "we looked and it was clean" are different
  claims and only one of them supports a published number.

`score_run` raises when there is nothing to score: no collected arms, or a corpus
whose ground truth has no items. Every scorer in this harness refuses a
zero-denominator result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import anticheat, grade
from . import corpus as corpus_mod
from .result import ResultError, load_plan

VALID = "VALID"
INVALID = "INVALID"
UNVERIFIABLE = "UNVERIFIABLE"
UNSCOREABLE = "UNSCOREABLE"


def _blank_assessment(transcripts: list[Any], error: str) -> dict[str, Any]:
    return {
        "verdict": UNVERIFIABLE,
        "violations": [],
        "advisories": [],
        "transcripts": [str(t) for t in transcripts],
        "invocations_seen": 0,
        "tool_definitions_seen": 0,
        "records_parsed": 0,
        "records_unparseable": 0,
        "cve_mentioned_in_text": [],
        "declarations_seen": 0,
        "error": error,
    }


class ReportError(Exception):
    """Nothing to score, or the run directory is not one. Callers exit non-zero."""


def score_run(run_dir: Path, workroot: Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    plan = load_plan(run_dir)
    collected_dir = run_dir / "collected"
    files = sorted(collected_dir.glob("*.json")) if collected_dir.is_dir() else []
    if not files:
        raise ReportError(
            f"no collected arm results under {collected_dir}. Run `bench.py collect` for each arm "
            f"first; scoring zero arms would print a comparison table of nothing."
        )

    cells = {(c["arm"], c["corpus"], c["variant"]): c for c in plan["cells"]}
    arms: list[dict[str, Any]] = []
    for file in files:
        result = json.loads(file.read_text(encoding="utf-8"))
        key = (result["arm"], result["corpus"], result["variant"])
        # The filename encodes the same triple. A mismatch means the file is stale —
        # left over from an earlier naming scheme or hand-edited — and scoring it would
        # attribute one cell's findings to another.
        if file.stem != "__".join(key):
            raise ReportError(
                f"{file.name} describes {'/'.join(key)}, which does not match its own name. "
                f"Delete the stale file and re-collect; a leftover result scored under the "
                f"wrong cell is how a control run gets reported as recall."
            )
        cell = cells.get(key)
        if cell is None:
            raise ReportError(f"{file.name} is not a cell in this plan: {key}")

        private = Path(cell["private"])
        try:
            ground_truth = corpus_mod.load_ground_truth(private)
        except corpus_mod.CorpusError as exc:
            raise ReportError(str(exc)) from exc

        declared = {
            "external_sources_consulted": result.get("external_sources_consulted"),
            "external_sources_detail": result.get("external_sources_detail"),
            "declarations_seen": result.get("declarations_seen", 0),
        }
        # The arm was told to work only from its own tree. Everything else under the work
        # root is the answer: the control variant, the private manifests, the staged
        # pre-de-identification tree — and the cache above it holds the pristine upstream
        # tarball the de-identifier exists to hide.
        containment = anticheat.Containment(
            tree=cell["tree"],
            roots=[workroot, corpus_mod.cache_dir()],
            allow=[run_dir],
        )
        transcripts = [Path(t) for t in result.get("transcripts") or ()]
        if transcripts:
            try:
                assessment = anticheat.assess(
                    anticheat.scan_transcripts(transcripts, containment, result["arm"]), declared
                )
            except anticheat.AntiCheatError as exc:
                assessment = _blank_assessment(transcripts, str(exc))
        else:
            assessment = _blank_assessment(
                [],
                "no transcript supplied, so no oracle check ran. Pass --transcript to collect; "
                "an unexamined arm cannot be reported as clean.",
            )
            if declared["external_sources_consulted"]:
                assessment = anticheat.assess(
                    {**assessment, "verdict": VALID, "violations": []}, declared
                )
                assessment["error"] = (
                    "no transcript supplied; the verdict rests on the arm's own declaration"
                )

        meta = result["meta"]
        try:
            scored = grade.grade(result, ground_truth)
        except grade.GradeError as exc:
            # One unscoreable cell must not take the whole run's report with it. The old
            # behaviour raised, so `score` exited 3 and wrote nothing at all — no score.json,
            # no REPORT.md, not even for the cells that were fine. The arm is excluded with
            # its reason on the banner, which is the same treatment an arm that used an
            # oracle gets, and `score` still exits non-zero.
            arms.append(
                {
                    "arm": result["arm"],
                    "corpus": result["corpus"],
                    "variant": result["variant"],
                    "verdict": UNSCOREABLE,
                    "anticheat": {**assessment, "verdict": UNSCOREABLE, "error": str(exc)},
                    "grade": None,
                    "cost": {
                        "agents": int(meta["agents"]),
                        "tokens": int(meta["tokens"]),
                        "wall_seconds": float(meta["wall_seconds"]),
                        "model": meta.get("model", "?"),
                        "token_basis": meta.get("token_basis"),
                        "estimated_tokens": cell["estimated_tokens"],
                        "estimated_agents": cell["estimated_agents"],
                        "tokens_per_bug_found": None,
                    },
                }
            )
            continue

        hits = scored["hits"]
        arms.append(
            {
                "arm": result["arm"],
                "corpus": result["corpus"],
                "variant": result["variant"],
                "verdict": assessment["verdict"],
                "anticheat": assessment,
                "grade": scored,
                "groups_attempted": result.get("groups_attempted") or [],
                "groups_failed": result.get("groups_failed") or [],
                "cost": {
                    "agents": int(meta["agents"]),
                    "tokens": int(meta["tokens"]),
                    "wall_seconds": float(meta["wall_seconds"]),
                    "model": meta.get("model", "?"),
                    "token_basis": meta.get("token_basis"),
                    "estimated_tokens": cell["estimated_tokens"],
                    "estimated_agents": cell["estimated_agents"],
                    "tokens_per_bug_found": (int(meta["tokens"]) // hits) if hits else None,
                },
            }
        )

    # `meta.token_basis` exists because the same cell reads 92,478 / 246,755 / 2,432,494
    # tokens on three different bases. The README says mixing them in one run is refused; it
    # was not, and the totals summed a `reported_subagent_tokens` figure straight into a
    # `tokens_total` one, comparing 92 K against 2.4 M as though they were the same scale.
    bases = sorted({a["cost"].get("token_basis") or "reported_subagent_tokens" for a in arms})
    if len(bases) > 1:
        raise ReportError(
            "the cells in this run count tokens on different bases ("
            + ", ".join(bases)
            + "). A `reported_subagent_tokens` figure and a `tokens_total` figure differ by more "
            "than an order of magnitude on the same run, so a table mixing them is not a "
            "comparison. Re-derive the odd cells with `bench.py cost` and re-collect."
        )

    invalid = [a for a in arms if a["verdict"] != VALID]
    return {
        "run_dir": str(run_dir),
        "tier": plan["tier"],
        "token_basis": bases[0],
        "arms": arms,
        "invalid_arms": [
            {
                "arm": a["arm"],
                "corpus": a["corpus"],
                "variant": a["variant"],
                "verdict": a["verdict"],
            }
            for a in invalid
        ],
        "totals": {
            "tokens_actual": sum(a["cost"]["tokens"] for a in arms),
            "tokens_estimated": sum(a["cost"]["estimated_tokens"] for a in arms),
            "agents_actual": sum(a["cost"]["agents"] for a in arms),
            "wall_seconds": sum(a["cost"]["wall_seconds"] for a in arms),
        },
    }


def format_report(scored: dict[str, Any]) -> str:
    lines: list[str] = [f"# c-review benchmark — tier {scored['tier']}", ""]

    invalid = [a for a in scored["arms"] if a["verdict"] != VALID]
    if invalid:
        lines += [
            "!" * 78,
            "!! RESULTS EXCLUDED — the following arms are not valid measurements and their",
            "!! numbers do not appear in the comparison table below.",
        ]
        for arm in invalid:
            lines.append(
                f"!!   {arm['arm']} on {arm['corpus']} [{arm['variant']}]: {arm['verdict']}"
            )
            for violation in arm["anticheat"]["violations"]:
                lines.append(f"!!     {violation['why']}")
            if arm["anticheat"].get("error"):
                lines.append(f"!!     {arm['anticheat']['error']}")
        lines += ["!" * 78, ""]

    valid = [a for a in scored["arms"] if a["verdict"] == VALID]
    lines += [
        "## Comparison (valid arms only)",
        "",
        f"TOKENS are counted on the `{scored['token_basis']}` basis for every cell in this run. "
        "The same cell reads 92,478 / 246,755 / 2,432,494 tokens on the three bases this "
        "harness knows about, so the column means nothing without this line.",
        "",
        f"{'ARM':<14} {'CORPUS':<10} {'VAR':<8} {'RECALL':>9} {'FP':>10} "
        f"{'AGENTS':>7} {'TOKENS':>11} {'TOK/BUG':>10} {'WALL':>7}",
        f"{'-' * 14} {'-' * 10} {'-' * 8} {'-' * 9} {'-' * 10} "
        f"{'-' * 7} {'-' * 11} {'-' * 10} {'-' * 7}",
    ]
    if not valid:
        lines.append("(none — every arm in this run was excluded)")
    for arm in valid:
        g = arm["grade"]
        fps = g["false_positives"]
        recall = f"{g['hits']}/{g['graded_items']}" if g["bugs_present"] else "control"
        fp_cell = (
            f"{len(fps[grade.DECOY_FP]) + len(fps[grade.CONTROL_FP])}+{len(fps[grade.UNMATCHED])}?"
        )
        cost = arm["cost"]
        lines.append(
            f"{arm['arm']:<14} {arm['corpus']:<10} {arm['variant']:<8} {recall:>9} {fp_cell:>10} "
            f"{cost['agents']:>7} {cost['tokens']:>11,} "
            f"{(str(cost['tokens_per_bug_found']) if cost['tokens_per_bug_found'] else '-'):>10} "
            f"{cost['wall_seconds']:>7.0f}"
        )
    lines += [
        "",
        "FP column: certain false positives (decoy sites plus control-tree claims) + unmatched "
        "findings that need human triage. Unmatched findings are NOT counted as false positives: "
        "the base code may hold real bugs nobody injected.",
        "",
    ]

    totals = scored["totals"]
    lines += [
        "## Cost",
        "",
        f"actual: {totals['tokens_actual']:,} tokens, {totals['agents_actual']} agents, "
        f"{totals['wall_seconds'] / 60:.0f} minutes",
        f"modelled beforehand: {totals['tokens_estimated']:,} tokens "
        f"({(totals['tokens_actual'] / totals['tokens_estimated']):.2f}x the estimate)"
        if totals["tokens_estimated"]
        else "no estimate recorded",
        "",
    ]

    for arm in scored["arms"]:
        lines += [
            f"## {arm['arm']} on {arm['corpus']} [{arm['variant']}] — {arm['verdict']}",
            "",
            anticheat.format_assessment(arm["anticheat"]),
            "",
        ]
        # A c-review run in which most hunters died still produces findings and still
        # scores. The v2.0 measurement lost 13 of 16 hunters to a session limit; nothing in
        # this report used to say so, and the recall figure read as though the pipeline had
        # run. It is not a disqualification — a partial run is a real data point — but it
        # cannot be invisible.
        failed = arm.get("groups_failed") or []
        if failed:
            attempted = arm.get("groups_attempted") or []
            lines += [
                f"PARTIAL RUN: {len(failed)} of {len(attempted) or '?'} hunter group(s) failed "
                f"({', '.join(str(f) for f in failed[:8])}). This arm's recall is a floor, not a "
                f"measurement of the configuration.",
                "",
            ]
        if arm["grade"] is None:
            lines += [
                f"not scored: {arm['anticheat'].get('error', 'no grade')}",
                "",
            ]
            continue
        lines += [grade.format_grade(arm["grade"]), ""]
    return "\n".join(lines)


def check_run_dir(run_dir: Path) -> None:
    if not Path(run_dir).is_dir():
        raise ResultError(f"{run_dir} is not a directory")
