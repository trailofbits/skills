#!/usr/bin/env python3
"""Aggregate eval.sh results and decide whether the run passed.

Reads the JSONL summary eval.sh writes. Exits non-zero if the workflow mode
missed its target on any codebase, or if it failed to beat the baseline where
both modes ran.

Usage: summarize.py SUMMARY.jsonl [--self-test]
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
            "decoy_ruled_out": sum(1 for r in gradeable if r.get("decoy_examined_and_ruled_out")),
            "decoy_as_real": sum(1 for r in gradeable if r.get("decoy_reported_as_real")),
        }
    return out


def report(agg):
    codebases = sorted({c for c, _ in agg})
    modes = sorted({m for _, m in agg}, reverse=True)

    header = (
        f"{'codebase':<14}{'mode':<11}{'gradeable':<11}{'new/run':<10}"
        f"{'tp':<7}{'fp':<7}{'decoy':<12}"
    )
    print(header)
    print("-" * len(header))
    for c in codebases:
        for m in modes:
            s = agg.get((c, m))
            if not s:
                continue
            decoy = f"{s['decoy_ruled_out']}/{s['gradeable']} ok"
            if s["decoy_as_real"]:
                decoy += f" {s['decoy_as_real']} BAD"
            print(
                f"{c:<14}{m:<11}{str(s['gradeable']) + '/' + str(s['runs']):<11}"
                f"{s['mean_new']:<10.2f}{s['mean_tp']:<7.2f}{s['mean_fp']:<7.2f}{decoy:<12}"
            )

    failures = []
    for c in codebases:
        wf = agg.get((c, "workflow"))
        bl = agg.get((c, "baseline"))
        if wf is None:
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

    expected = 5
    if checks != expected:
        raise AssertionError(f"self-test ran {checks}, expected {expected}")
    print(f"\nsummarize.py self-test: {checks}/{expected} checks passed")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("summary", nargs="?")
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
    return report(aggregate(rows))


if __name__ == "__main__":
    sys.exit(main())
