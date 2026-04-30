#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
Run the CT-AFI benchmark over the corpus.

Usage:
    uv run benchmark/scripts/run_benchmark.py [--config <name>] [--warnings]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2]  # plugins/constant-time-analysis
sys.path.insert(0, str(PLUGIN))
sys.path.insert(0, str(PLUGIN / "benchmark" / "scripts"))

from ct_analyzer.analyzer import analyze_source  # noqa: E402
from metric import (  # noqa: E402
    aggregate,
    load_manifest,
    score_item,
)


def run(corpus_dir: Path, manifest_path: Path, include_warnings: bool,
        opt_levels: list[str], post_filters: list[str] | None = None,
        smart_fusion: bool = False) -> dict:
    """
    smart_fusion=True: ERRORs are union across all opt levels (catches the
    KyberSlash pattern that disappears at O2 with clang); WARNINGs are union
    of O2 and O3 only (suppresses the wave of loop-counter branches the
    compiler emits at O0 that vanish under realistic deployment configs).
    """
    items = load_manifest(str(manifest_path))
    per_item_results = []
    raw_findings_by_item = {}

    for item in items:
        src = corpus_dir / item.file
        if not src.exists():
            continue

        all_findings: list[dict] = []
        func_sizes: dict[str, int] = {}
        for opt in opt_levels:
            try:
                report = analyze_source(
                    str(src),
                    optimization=opt,
                    include_warnings=include_warnings,
                    post_filters=post_filters,
                )
            except Exception as e:
                print(f"  [skip] {item.file} @ {opt}: {e}", file=sys.stderr)
                continue
            for v in report.violations:
                if smart_fusion and v.severity.value == "warning" and opt == "O0":
                    continue  # Skip O0 warnings under smart fusion
                all_findings.append({
                    "function": v.function,
                    "file": v.file,
                    "line": v.line,
                    "mnemonic": v.mnemonic,
                    "severity": v.severity.value,
                    "opt_level": opt,
                })

        # Deduplicate findings by (function, mnemonic, line)
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f["function"], f["mnemonic"], f["line"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)

        scored = score_item(item, deduped, func_sizes)
        per_item_results.append(scored)
        raw_findings_by_item[item.file] = deduped

    agg = aggregate(per_item_results)
    return {
        "summary": agg.to_dict(),
        "per_item": per_item_results,
        "config": {
            "warnings": include_warnings,
            "opt_levels": opt_levels,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=str(PLUGIN / "benchmark" / "corpus" / "manifest.json"))
    ap.add_argument("--corpus-dir", default=str(PLUGIN / "benchmark" / "corpus"))
    ap.add_argument("--warnings", action="store_true",
                    help="Include conditional-branch warnings")
    ap.add_argument("--opt", action="append", default=None,
                    help="Optimization level(s) to test (default: O2)")
    ap.add_argument("--out", default=None, help="Write JSON results to this path")
    ap.add_argument("--label", default="run", help="Label for this configuration")
    ap.add_argument("--filter", action="append", default=[],
                    help="Comma-separated post-analysis filters (or 'all')")
    ap.add_argument("--smart-fusion", action="store_true",
                    help="Errors union all opts; warnings only from O2/O3")
    args = ap.parse_args()

    opt_levels = args.opt or ["O2"]
    post_filters: list[str] = []
    for f in args.filter:
        post_filters.extend(s.strip() for s in f.split(",") if s.strip())
    if "all" in post_filters:
        post_filters = ["compiler-helpers", "memcmp-source", "ct-funcs",
                        "non-secret", "aggregate"]

    t0 = time.time()
    out = run(Path(args.corpus_dir), Path(args.manifest), args.warnings, opt_levels,
              post_filters, smart_fusion=args.smart_fusion)
    out["wall_seconds"] = round(time.time() - t0, 2)
    out["label"] = args.label

    s = out["summary"]
    print(f"== {args.label} (warnings={args.warnings}, opt={opt_levels}) ==")
    print(f"  n_items   : {s['n_items']}")
    print(f"  TP/FP/FN  : {s['tp']}/{s['fp']}/{s['fn']}")
    print(f"  P / R / F1: {s['precision']:.3f} / {s['recall']:.3f} / {s['f1']:.3f}")
    print(f"  Triage min: {s['triage_minutes']:.1f}")
    print(f"  CT-AFI    : {s['ct_afi']:.4f}")
    print(f"  Yield/min : {s['yield_per_min']:.3f} TP/min")

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
        print(f"  -> {args.out}")


if __name__ == "__main__":
    main()
