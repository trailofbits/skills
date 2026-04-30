#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Unified manifest-driven benchmark runner.

Dispatches by ``--language={c,go,rust}`` into the language-specific
harness.  Each path emits result JSON in the layout already checked
into ``benchmark/results/`` -- the per-language schemas differ
(C/Go uses metric.py's CT-AFI summary, Rust uses a TP/FP/FN totals
block) and the unification is purely a CLI convenience.

Usage:
    PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py --language c [...]
    PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py --language go [...]
    PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py --language rust [...]

The C/Go path historically lived in this same file; the Rust path was
``run_benchmark_rust.py`` until the post-merge cleanup folded both
behind a single dispatcher.  All language-specific arguments and JSON
shapes are preserved byte-for-byte.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2]  # plugins/constant-time-analysis
sys.path.insert(0, str(PLUGIN))
sys.path.insert(0, str(PLUGIN / "benchmark" / "scripts"))


# ---------------------------------------------------------------------------
# C / Go path: unchanged from the pre-unification run_benchmark.py.
# ---------------------------------------------------------------------------

from ct_analyzer.analyzer import analyze_source  # noqa: E402
from metric import (  # noqa: E402
    aggregate,
    load_manifest,
    score_item,
)


def _run_c_go(corpus_dir: Path, manifest_path: Path, include_warnings: bool,
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
        # Cross-function dedup by (file, line, mnemonic): the same source
        # line generally compiles to the same instruction regardless of
        # which caller (Go inlines aggressively, so a vulnerable function
        # called from main() emits the IDIV at the same source line in
        # both kyberslashReduce and main; counting both as separate
        # findings double-counts the vulnerability).
        seen_loc = set()
        loc_deduped = []
        for f in deduped:
            loc_key = (f.get("file") or "", f.get("line") or 0, f["mnemonic"])
            if loc_key[0] and loc_key in seen_loc:
                continue
            seen_loc.add(loc_key)
            loc_deduped.append(f)
        deduped = loc_deduped

        # Post-fusion fuzzy dedup: two findings on the same (function,
        # mnemonic-family) within ~3 source lines are very likely the
        # same logical violation reported at slightly different lines
        # across O0 and O2 (Go's gc-S source attribution shifts +/-1
        # between optimisation passes). Collapse them. Distinct lines
        # > 3 apart in the same function (e.g. naiveModExp's L17 and
        # L20 modular reductions) are kept as separate.
        from ct_analyzer.filters import _mnemonic_family
        fuzzy_kept = []
        for f in deduped:
            fam = _mnemonic_family(f["mnemonic"])
            collapsed = False
            for kept_f in fuzzy_kept:
                if (kept_f["function"] == f["function"]
                        and _mnemonic_family(kept_f["mnemonic"]) == fam
                        and kept_f.get("line") is not None
                        and f.get("line") is not None
                        and abs(kept_f["line"] - f["line"]) <= 2):
                    collapsed = True
                    break
            if not collapsed:
                fuzzy_kept.append(f)
        deduped = fuzzy_kept

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


def main_c_go(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="run_benchmark.py --language={c,go}")
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
    args = ap.parse_args(argv)

    opt_levels = args.opt or ["O2"]
    post_filters: list[str] = []
    for f in args.filter:
        post_filters.extend(s.strip() for s in f.split(",") if s.strip())
    if "all" in post_filters:
        post_filters = ["compiler-helpers", "memcmp-source", "ct-funcs",
                        "non-secret", "div-public", "loop-backedge",
                        "go-bounds-check", "go-stack-grow", "go-public-line",
                        "aggregate"]

    t0 = time.time()
    out = _run_c_go(Path(args.corpus_dir), Path(args.manifest), args.warnings, opt_levels,
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
    return 0


# ---------------------------------------------------------------------------
# Rust path: unchanged from the pre-unification run_benchmark_rust.py.
# ---------------------------------------------------------------------------

ANALYZER = PLUGIN / "ct_analyzer" / "analyzer.py"

# Mapping from ground-truth `kind` strings to the analyzer mnemonics that
# count as a TP. The analyzer reports raw asm mnemonics; the manifest
# uses semantic kinds. We accept any mnemonic in the corresponding set.
_RUST_KIND_TO_MNEMONICS = {
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
class _RustFileResult:
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
class _RustBenchmarkResult:
    """Full benchmark output. JSON-serialised to `--out`."""

    label: str
    timestamp: float
    config: dict = field(default_factory=dict)
    files: list[_RustFileResult] = field(default_factory=list)
    totals: dict = field(default_factory=dict)


def _run_rust_analyzer(
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
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=PLUGIN, timeout=180)
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


def _rust_violations_match_groundtruth(
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
            if not _rust_function_name_matches(fn_name, target):
                continue
            allowed = _RUST_KIND_TO_MNEMONICS.get(gt.get("kind", ""), set())
            if mnemonics & allowed:
                covered_gt.add(gi)
                matches_any_gt = True
        if not matches_any_gt:
            # Only count as FP if this report's function does not appear
            # in any GT entry. Reports inside vulnerable functions whose
            # mnemonic class doesn't match any GT kind ARE FPs (e.g. an
            # extra unrelated branch in a known-vulnerable function).
            in_known_function = any(
                _rust_function_name_matches(fn_name, gt.get("function", ""))
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


def _rust_function_name_matches(reported_name: str, target: str) -> bool:
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


def _rust_evaluate_file(
    file_entry: dict,
    corpus_dir: Path,
    *,
    warnings: bool,
    opts: list[str],
    precise_warnings: bool,
    strict: bool,
) -> _RustFileResult:
    """Run analyzer at each opt level; merge reports across opts.

    The smart-fusion model: an ERROR at any opt level is an ERROR; a
    warning that survives at multiple opt levels is more credible than
    one that only appears at -O0. We union the reported set across
    opts and trust the highest-severity report for each (line, mnemonic).
    """
    src = corpus_dir / file_entry["path"]
    fr = _RustFileResult(
        path=file_entry["path"],
        label=file_entry.get("label", "unknown"),
        ground_truth=file_entry.get("ground_truth_violations", []),
    )
    merged_reports: dict[tuple, dict] = {}
    err_count = 0
    warn_count = 0
    for opt in opts:
        rep = _run_rust_analyzer(
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

    tp, fp, fn = _rust_violations_match_groundtruth(fr.reported, fr.ground_truth)
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
            _rust_function_name_matches(fn_name, gt.get("function", ""))
            for gt in fr.ground_truth
        ):
            continue
        actionable_fp += 1
    fr.fp_actionable = actionable_fp
    return fr


def _rust_aggregate(files: list[_RustFileResult]) -> dict:
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


def main_rust(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="run_benchmark.py --language=rust",
        description="Manifest-driven benchmark runner for Rust constant-time analysis.",
    )
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
    args = p.parse_args(argv)

    opts = args.opt or ["O0", "O2", "O3"]
    precise = args.filter == "all"

    manifest = json.loads(args.manifest.read_text())

    print(f"=== {args.label} ===", file=sys.stderr)
    print(
        f"  config: opts={opts}  filter={args.filter}  warnings={args.warnings}  strict={args.strict}",
        file=sys.stderr,
    )

    files: list[_RustFileResult] = []
    for entry in manifest["files"]:
        fr = _rust_evaluate_file(
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

    totals = _rust_aggregate(files)
    result = _RustBenchmarkResult(
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


# ---------------------------------------------------------------------------
# Top-level dispatcher.
# ---------------------------------------------------------------------------

def main() -> int:
    # Pre-parse only `--language`; the rest of the argv is handed to the
    # language-specific main so its argparse can produce native error
    # messages and `--help` text.
    pre = argparse.ArgumentParser(
        description="Unified constant-time analyzer benchmark runner.",
        add_help=False,
    )
    pre.add_argument(
        "--language", required=True, choices=("c", "go", "rust"),
        help="Source language to benchmark; selects corpus and dispatch path.",
    )
    args, remaining = pre.parse_known_args()
    if args.language in ("c", "go"):
        return main_c_go(remaining)
    return main_rust(remaining)


if __name__ == "__main__":
    sys.exit(main())
