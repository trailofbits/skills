#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Manifest-driven benchmark runner for the constant-time analyzer.

Computes precision / recall / F1 against a `manifest.json` whose entries
declare the ground-truth violations per file. Also computes CT-AFI, a
Jaccard-like fitness index that explicitly penalises warning noise:

    CT-AFI = |TP|  /  ( |TP| + |FP| + |FN| )

where TP/FP/FN are the union over (line, kind) tuples reported by the
analyzer at ERROR-or-WARNING level. The unfiltered baseline drowns in
FP_warnings on a real corpus, so CT-AFI sits near zero; precision-
filtered configurations push it up. F1 is reported separately because
it discounts warnings entirely.

Run:
    PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py \\
        --warnings --opt O0 --opt O2 --opt O3 \\
        --filter all --smart-fusion \\
        --corpus-dir benchmark/corpus_rust \\
        --manifest benchmark/corpus_rust/manifest.json \\
        --label rust_baseline --out benchmark/results/rust_00_baseline.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYZER = REPO_ROOT / "ct_analyzer" / "analyzer.py"

# Mapping from ground-truth `kind` strings to the analyzer mnemonics that
# count as a TP. The analyzer reports raw asm mnemonics; the manifest
# uses semantic kinds. We accept any mnemonic in the corresponding set.
KIND_TO_MNEMONICS = {
    "div_on_secret": {
        # x86_64 hardware integer division.
        "DIV", "IDIV", "DIVB", "DIVW", "DIVL", "DIVQ",
        "IDIVB", "IDIVW", "IDIVL", "IDIVQ",
        # Floating-point.
        "DIVSS", "DIVSD", "DIVPS", "DIVPD",
        "VDIVSS", "VDIVSD", "VDIVPS", "VDIVPD",
        # ARM.
        "UDIV", "SDIV", "FDIV",
        # RISC-V.
        "REM", "REMU", "REMW", "REMUW",
    },
    "branch_on_secret": {
        # Conditional branch instructions; analyzer reports these as warnings.
        "JE", "JNE", "JZ", "JNZ", "JA", "JAE", "JB", "JBE",
        "JG", "JGE", "JL", "JLE", "JO", "JNO", "JS", "JNS", "JP", "JNP",
        "B.EQ", "B.NE", "B.CS", "B.CC", "B.HI", "B.LS",
        "B.GE", "B.LT", "B.GT", "B.LE",
        "BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU",
        "CBZ", "CBNZ", "TBZ", "TBNZ",
    },
    "memcmp_on_secret": {
        # Naive == on slices lowers to a compare loop with JE/JNE early-exit.
        # Same mnemonics as branch_on_secret -- the kind is informational,
        # the matching is on instruction class.
        "JE", "JNE", "JZ", "JNZ",
        "B.EQ", "B.NE", "BEQ", "BNE",
        "CBZ", "CBNZ",
    },
    "secret_loop_bound": {
        # A loop driven by a secret count emits the same conditional
        # branches as branch_on_secret -- this is also informational.
        "JE", "JNE", "JZ", "JNZ", "JA", "JAE", "JB", "JBE",
        "JG", "JGE", "JL", "JLE",
        "B.EQ", "B.NE", "B.HI", "B.LS", "B.GE", "B.LT", "B.GT", "B.LE",
        "BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU",
        "CBZ", "CBNZ",
    },
}


@dataclass
class FileResult:
    """Per-file evaluation outcome."""

    path: str
    label: str
    ground_truth: list[dict] = field(default_factory=list)
    reported: list[dict] = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    fp_actionable: int = 0  # FP excluding *_likely_fp triage hints
    fn: int = 0
    error_count: int = 0
    warning_count: int = 0
    reachable: bool = True


@dataclass
class BenchmarkResult:
    """Full benchmark output. JSON-serialised to `--out`."""

    label: str
    timestamp: float
    config: dict = field(default_factory=dict)
    files: list[FileResult] = field(default_factory=list)
    totals: dict = field(default_factory=dict)


def run_analyzer(
    source: Path,
    *,
    warnings: bool,
    opt: str,
    precise_warnings: bool,
    strict: bool,
) -> dict | None:
    cmd = [
        "uv", "run", "python", str(ANALYZER),
        "--json",
        "--opt-level", opt,
        str(source),
    ]
    if warnings:
        cmd.append("--warnings")
    if not precise_warnings:
        cmd.append("--no-precise-warnings")
    if strict:
        cmd.append("--strict")
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT, timeout=180)
    if proc.returncode not in (0, 1):
        # 0 = passed, 1 = violations present; anything else is a real error.
        sys.stderr.write(
            f"analyzer failed for {source} (exit {proc.returncode}):\n"
            f"  cmd: {' '.join(cmd)}\n"
            f"  stderr: {proc.stderr[:1000]}\n"
        )
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(
            f"non-JSON analyzer output for {source}:\n"
            f"  stdout: {proc.stdout[:500]}\n"
        )
        return None


def violations_match_groundtruth(
    reported: list[dict], ground_truth: list[dict]
) -> tuple[set, set, set]:
    """Match reported violations to ground-truth entries.

    Matching is on `(function-name-substring, mnemonic-class)`. We do
    NOT match on source line because rustc's `.loc` directives often
    attribute inlined-from-stdlib operations to the stdlib source path
    (e.g. `==` on `&[u8]` lowers to `core::slice::eq`, whose JNE has
    `file=/rustc/.../core/.../mod.rs`, `line=152`). The function
    attribution remains correct (`core::slice::eq` is still called
    from `verify_mac_naive`); we exploit that.

    Each GT entry can be covered by ANY number of matching reports;
    the second/third report on the same vulnerable function does NOT
    count as a FP. This matters because rustc emits multiple branches
    inside a vulnerable function (loop preamble, body, post-decrement)
    and we should not penalise the analyzer for finding the bug
    multiple ways.

    Returns (tp_keys, fp_keys, fn_keys). `tp_keys` are GT entries
    that were covered. `fp_keys` are reports whose function does not
    appear in ANY GT entry's function list.
    """
    covered_gt: set[int] = set()
    fp: set = set()
    # Build a helper: for a report, what GT indices can it cover?
    for r in reported:
        fn_name = (r.get("function") or "")
        mnem = (r.get("mnemonic") or "").upper()
        mnemonics = {m.upper() for m in mnem.split("/") if m}
        matches_any_gt = False
        for gi, gt in enumerate(ground_truth):
            target = gt.get("function", "")
            if not target:
                continue
            if not _function_name_matches(fn_name, target):
                continue
            allowed = KIND_TO_MNEMONICS.get(gt.get("kind", ""), set())
            if mnemonics & allowed:
                covered_gt.add(gi)
                matches_any_gt = True
        if not matches_any_gt:
            # Only count as FP if this report's function does not appear
            # in any GT entry. Reports inside vulnerable functions whose
            # mnemonic class doesn't match any GT kind ARE FPs (e.g. an
            # extra unrelated branch in a known-vulnerable function).
            in_known_function = any(
                _function_name_matches(fn_name, gt.get("function", ""))
                for gt in ground_truth
            )
            if not in_known_function:
                fp.add((fn_name[:80], "/".join(sorted(mnemonics))))
            else:
                # Report is in a vulnerable function but with the wrong
                # mnemonic class. Treat as a FP -- it's an extra violation
                # that doesn't correspond to a GT entry. (Rare in practice.)
                fp.add((fn_name[:80], "/".join(sorted(mnemonics))))
    tp = {
        (gi, ground_truth[gi].get("function", ""), ground_truth[gi].get("kind", ""))
        for gi in covered_gt
    }
    fn_set = {
        (gi, gt["function"], gt["kind"])
        for gi, gt in enumerate(ground_truth)
        if gi not in covered_gt
    }
    return tp, fp, fn_set


def _function_name_matches(reported_name: str, target: str) -> bool:
    """True if `target` appears as a path component of `reported_name`.

    `target` is the bare function name from the manifest. The reported
    name is the demangled Rust path (`crate::module::function`). We
    require the target to be a `::` boundary path component so that
    `verify_mac_naive` doesn't spuriously match `verify_mac_naive_slice`.
    """
    if not reported_name or not target:
        return False
    # Tokenise the reported name on `::`, also splitting on common
    # mangling glyphs that survive demangling (`<`, `>`, `(`, `)`, ` `).
    import re as _re
    tokens = set(_re.split(r"[:<>(),\s\[\]]+", reported_name))
    return target in tokens


def evaluate_file(
    file_entry: dict,
    corpus_dir: Path,
    *,
    warnings: bool,
    opts: list[str],
    precise_warnings: bool,
    strict: bool,
) -> FileResult:
    """Run analyzer at each opt level; merge reports across opts.

    The smart-fusion model: an ERROR at any opt level is an ERROR; a
    warning that survives at multiple opt levels is more credible than
    one that only appears at -O0. We union the reported set across
    opts and trust the highest-severity report for each (line, mnemonic).
    """
    src = corpus_dir / file_entry["path"]
    fr = FileResult(
        path=file_entry["path"],
        label=file_entry.get("label", "unknown"),
        ground_truth=file_entry.get("ground_truth_violations", []),
    )
    merged_reports: dict[tuple, dict] = {}
    err_count = 0
    warn_count = 0
    for opt in opts:
        rep = run_analyzer(
            src,
            warnings=warnings,
            opt=opt,
            precise_warnings=precise_warnings,
            strict=strict,
        )
        if rep is None:
            fr.reachable = False
            continue
        for v in rep.get("violations", []):
            key = (v.get("line"), v.get("mnemonic"))
            existing = merged_reports.get(key)
            if (
                existing is None
                or (v.get("severity") == "error" and existing.get("severity") != "error")
            ):
                merged_reports[key] = v
        err_count = max(err_count, rep.get("error_count", 0))
        warn_count = max(warn_count, rep.get("warning_count", 0))

    fr.reported = list(merged_reports.values())
    fr.error_count = err_count
    fr.warning_count = warn_count

    tp, fp, fn = violations_match_groundtruth(fr.reported, fr.ground_truth)
    fr.tp = len(tp)
    fr.fp = len(fp)
    fr.fn = len(fn)
    # FP_actionable: cost in human-triage time. We discount three classes:
    #   1. *_likely_fp triage hints -- agent dispenses with the report
    #      by reading the hint string.
    #   2. Reports inside a known-vulnerable function (by GT) -- the
    #      reviewer triages the whole function in one pass; extra
    #      branches inside it cost zero additional time.
    #   3. The TP itself.
    actionable_fp = 0
    for v in fr.reported:
        hint = (v.get("triage_hint") or "").lower()
        if hint.endswith("_likely_fp"):
            continue
        fn_name = v.get("function") or ""
        # Reports in a function listed in any GT entry are 'free' to
        # triage -- the function is on the agent's watchlist.
        if any(
            _function_name_matches(fn_name, gt.get("function", ""))
            for gt in fr.ground_truth
        ):
            continue
        actionable_fp += 1
    fr.fp_actionable = actionable_fp
    return fr


def aggregate(files: list[FileResult]) -> dict:
    tp = sum(f.tp for f in files)
    fp = sum(f.fp for f in files)
    fp_actionable = sum(f.fp_actionable for f in files)
    fn = sum(f.fn for f in files)
    err = sum(f.error_count for f in files)
    warn = sum(f.warning_count for f in files)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    precision_act = tp / (tp + fp_actionable) if (tp + fp_actionable) else 0.0
    f1_act = (
        2 * precision_act * recall / (precision_act + recall)
        if (precision_act + recall)
        else 0.0
    )
    ct_afi = tp / (tp + fp + fn) if (tp + fp + fn) else 0.0
    ct_afi_act = (
        tp / (tp + fp_actionable + fn) if (tp + fp_actionable + fn) else 0.0
    )
    return {
        "tp": tp,
        "fp": fp,
        "fp_actionable": fp_actionable,
        "fn": fn,
        "error_count_total": err,
        "warning_count_total": warn,
        "precision": round(precision, 4),
        "precision_actionable": round(precision_act, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "f1_actionable": round(f1_act, 4),
        "ct_afi": round(ct_afi, 4),
        "ct_afi_actionable": round(ct_afi_act, 4),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--corpus-dir", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--label", required=True, help="Label written into the result JSON")
    p.add_argument("--warnings", action="store_true")
    p.add_argument(
        "--opt", action="append", default=None,
        help="Repeatable. Default: O0, O2, O3 (smart fusion across all three).",
    )
    p.add_argument(
        "--filter", choices=("none", "all"), default="all",
        help="`none` disables precision filters (raw baseline); `all` enables them.",
    )
    p.add_argument(
        "--smart-fusion", action="store_true",
        help="Cosmetic flag preserved for parity with the C harness; "
        "smart fusion is always on (we always merge across --opt levels).",
    )
    p.add_argument("--strict", action="store_true")
    args = p.parse_args()

    opts = args.opt or ["O0", "O2", "O3"]
    precise = args.filter == "all"

    manifest = json.loads(args.manifest.read_text())

    print(f"=== {args.label} ===", file=sys.stderr)
    print(
        f"  config: opts={opts}  filter={args.filter}  warnings={args.warnings}  strict={args.strict}",
        file=sys.stderr,
    )

    files: list[FileResult] = []
    for entry in manifest["files"]:
        fr = evaluate_file(
            entry,
            args.corpus_dir,
            warnings=args.warnings,
            opts=opts,
            precise_warnings=precise,
            strict=args.strict,
        )
        files.append(fr)
        print(
            f"  {fr.path:<50}  TP={fr.tp}  FP={fr.fp}  FN={fr.fn}  "
            f"E={fr.error_count}  W={fr.warning_count}",
            file=sys.stderr,
        )

    totals = aggregate(files)
    result = BenchmarkResult(
        label=args.label,
        timestamp=time.time(),
        config={
            "opts": opts,
            "filter": args.filter,
            "warnings": args.warnings,
            "strict": args.strict,
        },
        files=files,
        totals=totals,
    )

    out_data = asdict(result)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out_data, indent=2))

    print(
        f"\nTotals: TP={totals['tp']}  FP={totals['fp']}  "
        f"FP_act={totals['fp_actionable']}  FN={totals['fn']}",
        file=sys.stderr,
    )
    print(
        f"  raw:        P={totals['precision']:.3f}  R={totals['recall']:.3f}  "
        f"F1={totals['f1']:.3f}  CT-AFI={totals['ct_afi']:.4f}",
        file=sys.stderr,
    )
    print(
        f"  actionable: P={totals['precision_actionable']:.3f}  R={totals['recall']:.3f}  "
        f"F1={totals['f1_actionable']:.3f}  CT-AFI={totals['ct_afi_actionable']:.4f}",
        file=sys.stderr,
    )
    print(f"  errors_total={totals['error_count_total']}  warnings_total={totals['warning_count_total']}", file=sys.stderr)
    print(f"  -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
