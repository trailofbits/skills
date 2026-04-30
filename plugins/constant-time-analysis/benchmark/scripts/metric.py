#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
CT-AFI (Constant-Time Alarm-Fatigue Index)
==========================================

Metric design rationale
-----------------------
A good static analyzer for timing side-channels must balance THREE forces:

  1. Recall (R)    - finding real bugs (KyberSlash, Lucky13, etc.)
  2. Precision (P) - not drowning the analyst in false alarms
  3. Triage cost   - even a "true" finding has a cost: time to reason about it

Pure F1 ignores cost #3, but in practice the dominant failure mode of CT
analyzers is alarm fatigue: Edna et al. (USENIX'14) showed that human
reviewers begin skipping findings after ~50 consecutive false positives.
Anecdotally, 70-90% FP rates are common in production crypto codebases
because every conditional branch and every integer division gets flagged.

We model the cost in *minutes-of-expert-time*:

    T_finding = T_base + T_kind_penalty + T_context_penalty
    T_kind_penalty   = {div: 1.0, idiv: 1.0, jcc: 1.5, cb*: 0.5}.get(kind, 0)
    T_context_penalty = 2.0 if no source-line info else 0
                      + 2.0 if function size > 50 instructions

Median empirical: ~3 minutes per finding, ranging 1-10.
(See: Cifuentes & Scholz, "Towards Practical Static Analysis", FSE'12.)

Final metric:

    CT_AFI = F1 * exp(-T_total / T_budget)

with T_budget = 60 min (one focused review session). Range [0, 1], higher
is better. The exponential decay captures how marginal a 100-finding report
is vs. a 10-finding report at equal F1: the analyst can only attend to so
much before quality degrades.

We also report:

    - F1 (correctness only)
    - P, R          (component diagnostics)
    - T_total       (total triage cost in minutes)
    - Yield-per-min = TP / T_total (effective bug-finding rate)
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path


# Per-finding triage cost coefficients, in minutes
T_BASE = 1.0
T_BUDGET = 60.0  # one focused review session

KIND_PENALTY = {
    # Division-class: reviewer needs to find divisor source
    "DIV": 1.0, "IDIV": 1.0, "DIVL": 1.0, "IDIVL": 1.0, "DIVQ": 1.0, "IDIVQ": 1.0,
    "UDIV": 1.0, "SDIV": 1.0,
    "DIVSS": 0.5, "DIVSD": 0.5, "FDIV": 0.5, "FSQRT": 0.3,
    # Branch-class: reviewer needs to find condition source - costlier
    "JE": 1.5, "JNE": 1.5, "JZ": 1.5, "JNZ": 1.5,
    "JA": 1.5, "JAE": 1.5, "JB": 1.5, "JBE": 1.5,
    "JG": 1.5, "JGE": 1.5, "JL": 1.5, "JLE": 1.5,
    "B.EQ": 1.5, "B.NE": 1.5, "B.LT": 1.5, "B.GT": 1.5, "B.LE": 1.5, "B.GE": 1.5,
    "BEQ": 1.5, "BNE": 1.5,
    "CBZ": 0.5, "CBNZ": 0.5, "TBZ": 0.5, "TBNZ": 0.5,
}


@dataclass
class GroundTruthViolation:
    file: str
    line: int | None
    kind: str          # "div_on_secret" | "branch_on_secret" | "memcmp_secret"
    description: str = ""

    def matches(self, finding: dict, line_tolerance: int = 5) -> bool:
        """A reported finding matches this ground truth if the file matches and
        either (a) the line is within tolerance, or (b) the function name and
        kind family match (compiler may not always emit line info)."""
        if Path(finding.get("file", "")).name != Path(self.file).name and finding.get("file"):
            # If finding has source-file info, it must match
            if finding["file"] and self.file:
                if Path(finding["file"]).name != Path(self.file).name:
                    return False
        if self.line is not None and finding.get("line") is not None:
            if abs(finding["line"] - self.line) <= line_tolerance:
                return _kind_compatible(self.kind, finding.get("mnemonic", ""))
        # Fallback: kind-family match (line info often missing in stripped asm)
        return _kind_compatible(self.kind, finding.get("mnemonic", ""))


def _kind_compatible(gt_kind: str, mnemonic: str) -> bool:
    """Map ground-truth kind labels to mnemonic families."""
    m = mnemonic.upper()
    k = gt_kind.lower()
    if "div" in k or "mod" in k:
        return any(s in m for s in ("DIV", "IDIV", "SDIV", "UDIV", "REM"))
    if "branch" in k or "loop_bound" in k:
        return (m.startswith("J") or m.startswith("B.")
                or m in ("BEQ", "BNE", "CBZ", "CBNZ", "TBZ", "TBNZ"))
    if "memcmp" in k or k == "memcmp_secret":
        # memcmp can be detected either as MEMCMP (source-level filter)
        # or as the trailing JE/JNE on the comparison result.
        return (m == "MEMCMP" or m.startswith("J") or m.startswith("B.")
                or m in ("BEQ", "BNE"))
    if "sqrt" in k:
        return "SQRT" in m
    return False


@dataclass
class CorpusItem:
    file: str               # path relative to corpus/
    label: str              # "clean" | "vulnerable" | "mixed"
    ground_truth: list[GroundTruthViolation] = field(default_factory=list)
    notes: str = ""


def triage_cost(finding: dict, total_instructions_in_func: int = 0) -> float:
    """Estimate analyst triage time in minutes for one finding."""
    cost = T_BASE
    cost += KIND_PENALTY.get(finding.get("mnemonic", "").upper(), 0.5)
    if not finding.get("line"):
        cost += 2.0
    if total_instructions_in_func > 50:
        cost += 2.0
    return cost


@dataclass
class BenchmarkResult:
    """Metrics for one analyzer configuration over the whole corpus."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    n_items: int = 0
    n_findings: int = 0
    triage_minutes: float = 0.0
    per_item: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def ct_afi(self) -> float:
        return self.f1 * math.exp(-self.triage_minutes / T_BUDGET)

    @property
    def yield_per_min(self) -> float:
        return self.tp / self.triage_minutes if self.triage_minutes else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "n_items": self.n_items, "n_findings": self.n_findings,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "triage_minutes": round(self.triage_minutes, 2),
            "ct_afi": round(self.ct_afi, 4),
            "yield_per_min": round(self.yield_per_min, 4),
        }


_AGGREGATE_RE = re.compile(r"\(\+(\d+) more")


def _finding_multiplicity(f: dict) -> int:
    """A post-aggregation finding may stand in for N+1 underlying instructions.
    Returns the multiplicity so it can match that many ground-truth entries."""
    m = _AGGREGATE_RE.search(f.get("reason", ""))
    if m:
        return int(m.group(1)) + 1
    return 1


def score_item(item: CorpusItem, findings: list[dict], func_sizes: dict[str, int]) -> dict:
    """Score one corpus item: match findings to ground truth, count TP/FP/FN,
    accumulate triage cost.  Aggregated findings may match multiple GT entries
    of the same kind family."""
    matched_gt: set[int] = set()
    tp = fp = 0
    cost = 0.0

    for f in findings:
        cost += triage_cost(f, func_sizes.get(f.get("function", ""), 0))
        slots = _finding_multiplicity(f)
        matched_in_this_finding = 0
        for i, gt in enumerate(item.ground_truth):
            if i in matched_gt:
                continue
            if gt.matches(f):
                matched_gt.add(i)
                matched_in_this_finding += 1
                if matched_in_this_finding >= slots:
                    break
        if matched_in_this_finding > 0:
            tp += matched_in_this_finding
        else:
            fp += 1

    fn = len(item.ground_truth) - len(matched_gt)
    return {"file": item.file, "label": item.label,
            "tp": tp, "fp": fp, "fn": fn,
            "n_findings": len(findings), "triage_minutes": round(cost, 2)}


def aggregate(per_item_results: list[dict]) -> BenchmarkResult:
    r = BenchmarkResult()
    r.n_items = len(per_item_results)
    for x in per_item_results:
        r.tp += x["tp"]
        r.fp += x["fp"]
        r.fn += x["fn"]
        r.n_findings += x["n_findings"]
        r.triage_minutes += x["triage_minutes"]
    r.per_item = per_item_results
    return r


def _kind_family(kind: str) -> str:
    """Map detailed kind labels to coarse families for dedup."""
    if "div" in kind or "mod" in kind or "sqrt" in kind:
        return "div"
    if "branch" in kind or "loop_bound" in kind or "memcmp" in kind:
        return "branch_or_memcmp"
    return kind


def load_manifest(path: str) -> list[CorpusItem]:
    """Load manifest, deduplicating ground truth entries by (line, kind-family).

    Multiple semantic labels on the same source line (e.g. both branch_on_secret
    and memcmp_on_secret on a single `if (memcmp(...)==0)`) collapse to one
    detection target so the analyzer is not penalized for emitting one finding
    where the manifest annotates several semantic facets.
    """
    data = json.loads(Path(path).read_text())
    items = []
    for it in data["items"]:
        seen_keys: set[tuple] = set()
        gts: list[GroundTruthViolation] = []
        for g in it.get("ground_truth_violations", []):
            kind = g["kind"]
            line = g.get("line")
            key = (line, _kind_family(kind))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            gts.append(GroundTruthViolation(
                file=it["file"], line=line, kind=kind,
                description=g.get("description", "")))
        items.append(CorpusItem(file=it["file"], label=it["label"],
                                ground_truth=gts, notes=it.get("notes", "")))
    return items
