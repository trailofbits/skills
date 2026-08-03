#!/usr/bin/env python3
"""Aggregate eval.sh results and decide whether the run passed.

Reads the JSONL summary eval.sh writes. Exits non-zero if the workflow mode
missed its target on any codebase, or if it failed to beat the baseline where
both modes ran.

A summary containing no workflow rows is a failure, not a pass: it means nothing
this script decides was measured. Pass --baseline-only when that is deliberate.

Usage: summarize.py SUMMARY.jsonl [--baseline-only] [--self-test]
"""

import argparse
import collections
import json
import pathlib
import sys

# Keyed on NEW variants, matching score.py's verdict(). Total true positives
# counts the seed, whose placement is a report-formatting convention: real runs
# put it under "## Findings" or under "## Original Vulnerability" depending on
# how closely they follow the template, and thresholding on the total failed the
# ones that followed it correctly.
TARGET_NEW = 1.0


def load(path):
    rows = []
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def aggregate(rows):
    by = collections.defaultdict(list)
    for r in rows:
        by[(r["codebase"], r["mode"])].append(r)

    out = {}
    for (codebase, mode), runs in by.items():
        gradeable = [r for r in runs if r.get("gradeable")]
        out[(codebase, mode)] = {
            "runs": len(runs),
            "gradeable": len(gradeable),
            "mean_new": (
                sum(r.get("new_variants_found", 0) for r in gradeable) / len(gradeable)
                if gradeable
                else 0.0
            ),
            "mean_tp": (
                sum(r["true_positives"] for r in gradeable) / len(gradeable) if gradeable else 0.0
            ),
            "mean_fp": (
                sum(r["false_positives"] for r in gradeable) / len(gradeable) if gradeable else 0.0
            ),
            "mean_unreviewed": (
                sum(len(r.get("unreviewed_findings", [])) for r in gradeable) / len(gradeable)
                if gradeable
                else 0.0
            ),
            "decoy_ruled_out": sum(1 for r in gradeable if r.get("decoy_examined_and_ruled_out")),
            "decoy_as_real": sum(1 for r in gradeable if r.get("decoy_reported_as_real")),
            # Runs scored through score.py's permissive fallback rather than its
            # **Location:** path. The fallback over-counts by design, so a score built on
            # it means less than one built on location fields. Silence here read as
            # "the strict path worked" on a cold run where it had not.
            "permissive": sum(
                1 for r in gradeable if r.get("extraction_mode") == "permissive-lines"
            ),
        }
    return out


def report(agg, require_workflow=True):
    codebases = sorted({c for c, _ in agg})
    modes = sorted({m for _, m in agg}, reverse=True)

    header = (
        f"{'codebase':<14}{'mode':<11}{'gradeable':<11}{'new/run':<10}"
        f"{'tp':<7}{'fp':<7}{'unrev':<8}{'decoy':<15}{'loose':<7}"
    )
    print(header)
    print("-" * len(header))
    loose_total = 0
    for c in codebases:
        for m in modes:
            s = agg.get((c, m))
            if not s:
                continue
            decoy = f"{s['decoy_ruled_out']}/{s['gradeable']} ok"
            if s["decoy_as_real"]:
                decoy += f" {s['decoy_as_real']} BAD"
            loose_total += s["permissive"]
            print(
                f"{c:<14}{m:<11}{str(s['gradeable']) + '/' + str(s['runs']):<11}"
                f"{s['mean_new']:<10.2f}{s['mean_tp']:<7.2f}{s['mean_fp']:<7.2f}"
                f"{s['mean_unreviewed']:<8.1f}{decoy:<15}{s['permissive']:<7}"
            )

    failures = []
    for c in codebases:
        wf = agg.get((c, "workflow"))
        bl = agg.get((c, "baseline"))
        if wf is None:
            # A summary with no workflow rows measures nothing this script is here
            # to decide. Skipping it silently made `--mode baseline` — and any
            # mistyped `--mode` value, which eval.sh used to treat as baseline —
            # exit 0 with a green check no matter what the run found.
            if require_workflow:
                failures.append(
                    f"{c}: no workflow runs in the summary — nothing was measured "
                    f"(pass --baseline-only if that was intentional)"
                )
            continue
        if wf["gradeable"] == 0:
            failures.append(f"{c}: workflow produced no gradeable report")
            continue
        if wf["mean_new"] < TARGET_NEW:
            failures.append(
                f"{c}: workflow found {wf['mean_new']:.2f} new variants/run, need {TARGET_NEW}"
            )
        if wf["decoy_as_real"]:
            failures.append(
                f"{c}: workflow reported the decoy as real in {wf['decoy_as_real']} run(s)"
            )
        if bl and bl["gradeable"] and wf["mean_new"] < bl["mean_new"]:
            failures.append(
                f"{c}: workflow ({wf['mean_new']:.2f} new) did not beat "
                f"baseline ({bl['mean_new']:.2f} new)"
            )

    print()
    print("  unrev = findings outside ground truth: real upstream code the eval cannot")
    print("          adjudicate. Read them by hand; they do not affect pass/fail.")
    if loose_total:
        print(f"  loose = {loose_total} run(s) scored via the permissive fallback: no")
        print("          **Location:** fields in the report, so those scores over-count.")
        print("          Not a pass/fail input, but they are worth less than they look.")
    print()
    if failures:
        for f in failures:
            print(f"  ✗ {f}")
        return 1
    print("  ✓ all codebases met the target")
    return 0


SELF_TEST_ROWS = [
    {
        "codebase": "x",
        "mode": "workflow",
        "gradeable": True,
        "true_positives": 2,
        "new_variants_found": 1,
        "new_variants_total": 1,
        "false_positives": 0,
        "decoy_examined_and_ruled_out": True,
        "decoy_reported_as_real": False,
    },
    {
        "codebase": "x",
        "mode": "baseline",
        "gradeable": True,
        "true_positives": 1,
        "new_variants_found": 0,
        "new_variants_total": 1,
        "false_positives": 0,
        "decoy_examined_and_ruled_out": False,
        "decoy_reported_as_real": False,
    },
]


def self_test():
    checks = 0

    assert report(aggregate(SELF_TEST_ROWS)) == 0, "workflow 2 / baseline 1 should pass"
    checks += 1

    weak = json.loads(json.dumps(SELF_TEST_ROWS))
    weak[0]["new_variants_found"] = 0
    assert report(aggregate(weak)) == 1, "workflow finding no new variant must fail"
    checks += 1

    decoy = json.loads(json.dumps(SELF_TEST_ROWS))
    decoy[0]["decoy_reported_as_real"] = True
    assert report(aggregate(decoy)) == 1, "decoy reported as real must fail"
    checks += 1

    tie = json.loads(json.dumps(SELF_TEST_ROWS))
    tie[1]["new_variants_found"] = 1
    assert report(aggregate(tie)) == 0, "matching the baseline at target is a pass"
    checks += 1

    ungradeable = [dict(SELF_TEST_ROWS[0], gradeable=False)]
    assert report(aggregate(ungradeable)) == 1, "no gradeable workflow run must fail"
    checks += 1

    # The loose column. Without this, renaming score.py's mode label leaves the column
    # reading zero on every run forever — restoring the silence the column exists to break.
    loose = json.loads(json.dumps(SELF_TEST_ROWS))
    loose[0]["extraction_mode"] = "permissive-lines"
    loose[1]["extraction_mode"] = "location-fields"
    agg = aggregate(loose)
    assert agg[("x", "workflow")]["permissive"] == 1, agg
    assert agg[("x", "baseline")]["permissive"] == 0, agg
    assert report(agg) == 0, "permissive extraction is reported, not a failure"
    checks += 1

    baseline_only = [SELF_TEST_ROWS[1]]
    assert report(aggregate(baseline_only)) == 1, "a summary with no workflow rows must fail"
    assert report(aggregate(baseline_only), require_workflow=False) == 0, (
        "--baseline-only makes a workflow-free summary legitimate"
    )
    checks += 1

    expected = 7
    if checks != expected:
        raise AssertionError(f"self-test ran {checks}, expected {expected}")
    print(f"\nsummarize.py self-test: {checks}/{expected} checks passed")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("summary", nargs="?")
    ap.add_argument(
        "--baseline-only",
        action="store_true",
        help="the run deliberately had no workflow arm; do not fail on its absence",
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.summary:
        ap.error("summary path required unless --self-test")

    rows = load(args.summary)
    if not rows:
        print("no results in summary — the eval ran nothing", file=sys.stderr)
        return 1
    return report(aggregate(rows), require_workflow=not args.baseline_only)


if __name__ == "__main__":
    sys.exit(main())
