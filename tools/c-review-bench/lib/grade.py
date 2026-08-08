"""Grade one arm's findings against a corpus's private ground truth.

The grading rule is inherited from the measured evaluation and unchanged, because
it is the part that survived scrutiny: a finding is a **HIT** when it names the
right file, places itself at the right site (matching function name, or a line
within the window of the recorded site), and its text identifies the actual defect
mechanism. Site proximity alone is not a hit — "there is something wrong around
here" is not a finding.

Five outcomes, not two:

- `HIT` — found and reported to the user.
- `SUPPRESSED` — some reviewer found it and the pipeline dropped it (a judge
  rejected it, dedup buried it, a severity filter ate it). That needs a different
  fix from a miss, and conflating the two is how a recall regression gets
  misdiagnosed as a discovery problem.
- `NEAR_MISS` — right site, mechanism keywords did not match. Read it: either the
  finding describes something else at that line, or the keyword list is stale.
- `AMBIGUOUS` — one finding was the *only* mechanism-matching evidence for this bug
  and for another bug at the same site, so at most one of them was really found and
  the grader cannot say which. Not counted as recall. See `_resolve_ambiguity`: this
  is the fix for a demonstrated recall inflation, not a hypothetical one.
- `MISS` — nothing at that site.

False positives are counted in three buckets, deliberately not one:

- `DECOY_FP` — the finding is at an injected decoy, which is a no-op mutation with
  a recorded safety argument. As close to a certain false positive as this harness
  can get on the bench tree.
- `CONTROL_FP` — on the patched-control corpus, a finding that claims one of the
  injected bugs at the site where that bug *is not present*. Certain by
  construction.
- `UNMATCHED` — everything else. **Not** reported as a false positive: the base code
  may contain real bugs we did not inject, and calling those FPs would punish an arm
  for being right. They are counted and listed for a human.

Every entry point raises rather than returning a zero-denominator score. A recall of
`0/0`, a false-positive rate over no findings, and a breakdown of an empty arm list
are all the same defect: a checker that inspected nothing reporting success.
"""

from __future__ import annotations

import re
from typing import Any

from .recipe import DECOY_CLAIM_TERMS

HIT = "HIT"
SUPPRESSED = "SUPPRESSED"
NEAR_MISS = "NEAR_MISS"
AMBIGUOUS = "AMBIGUOUS"
MISS = "MISS"

DECOY_FP = "DECOY_FP"
CONTROL_FP = "CONTROL_FP"
UNMATCHED = "UNMATCHED"
KNOWN_EXTRA = "KNOWN_EXTRA"

TEXT_FIELDS = (
    "title",
    "description",
    "impact",
    "code",
    "data_flow",
    "reachability",
    "recommendation",
    "bug_class",
    "function",
    "mitigations_checked",
    "severity_rationale",
    "fp_rationale",
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.IGNORECASE)
DEFAULT_WINDOW = 12

# Decoys are graded with a narrower window than bugs. The wide bug window exists because
# a reviewer who names a neighbouring function and points at the right line has still
# found the bug -- the ground truth's own idea of "the enclosing function" is a judgement
# call. A decoy has no such excuse: the recipe validator requires a `function` on every
# decoy specifically so a real claim about it can be checked by name. The demonstrated
# failure mode (`sigil`, ~5 of 11 decoy charges) was the wide window pulling a correct
# finding in a *different* function into a decoy's blast radius. Function-name matching for
# decoys stays unrestricted, as it should be; the line-only fallback -- for a finding that
# gives a line without naming a function -- is kept, but tight enough that it cannot reach
# across an ordinary function boundary the way the 12-line bug window can.
DECOY_WINDOW = 3

# A double-free is textually indistinguishable from a use-after-free in a lot of correct
# prose: freeing a pointer that was already freed *is* touching a dangling pointer, and a
# reviewer who calls that "use-after-free" is describing the same defect as one who calls
# it "double free". `SGL-B11`'s mechanism_all_of demands the literal phrase "double free",
# so a correct finding phrased as a use-after-free scored NEAR_MISS -- and, before the decoy
# fix above, was separately charged as a decoy false positive for the same finding. The
# synonym below is scoped to `bug_class == "double-free"` items and only widens the specific
# "double free" term, not the whole match: an unrelated bug still needs its own literal
# keywords, so proximity plus borrowed vocabulary still cannot manufacture a hit.
DOUBLE_FREE_LITERAL = ("double free", "double-free")
DOUBLE_FREE_SYNONYMS = (
    "use-after-free",
    "use after free",
    "freed twice",
    "freed again",
    "already freed",
    "dangling pointer",
)


class GradeError(Exception):
    """Nothing to grade, or nothing to grade against. Callers exit non-zero."""


def normalise_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def normalise_function(value: Any) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum() or ch == "_")


def file_matches(found: Any, wanted: Any) -> bool:
    """Suffix match anchored on a path segment, so `lib/x.c` never matches `other/x.c`."""
    a, b = normalise_path(found), normalise_path(wanted)
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def finding_text_raw(finding: dict[str, Any]) -> str:
    return " ".join(str(finding.get(field, "")) for field in TEXT_FIELDS)


def finding_text(finding: dict[str, Any]) -> str:
    return finding_text_raw(finding).lower()


SITE_FUNCTION = "function"
SITE_LINE = "line"
SITE_LINE_CROSS_FUNCTION = "line-cross-function"


def site_matches(finding: dict[str, Any], item: dict[str, Any], window: int) -> tuple[bool, str]:
    ok, why, _kind = site_match(finding, item, window)
    return ok, why


def site_match(finding: dict[str, Any], item: dict[str, Any], window: int) -> tuple[bool, str, str]:
    """Is this finding at this bug's site, and on what evidence?

    The rule is the documented one and deliberately an inclusive OR: a matching function
    name, **or** a line within the window. The window is kept because a reviewer who
    names a neighbouring function and points at the right line has found the bug, and the
    ground truth's own idea of "the enclosing function" is a judgement call.

    The third return value says *which* arm of the OR fired, because the two are not
    equally strong and the harness used to lose that distinction. On the shipped `sigil`
    corpus `tags_equal` (SGL-B13, line 87) and `tag_check` (SGL-B14, line 97) are ten
    lines apart in different functions, so every finding naming one of them also lands at
    the other's site by window. That is tolerable when it is visible and resolved in
    favour of the function match, and silently wrong when it is not: in the one real run
    a finding about `sgl_tag_compute` was graded at `tags_equal`'s site.
    """
    function = normalise_function(finding.get("function"))
    wanted = normalise_function(item.get("function"))
    if function and wanted and function == wanted:
        return True, f"function {finding.get('function')}", SITE_FUNCTION
    try:
        line = int(finding.get("line", 0))
    except (TypeError, ValueError):
        line = 0
    anchor = int(item.get("line", 0))
    if line and anchor and abs(line - anchor) <= window:
        kind = SITE_LINE_CROSS_FUNCTION if (function and wanted) else SITE_LINE
        detail = f"line {line} within {window} of {anchor}"
        if kind == SITE_LINE_CROSS_FUNCTION:
            detail += f" but names {finding.get('function')}, not {item.get('function')}"
        return True, detail, kind
    return False, "", ""


def _term_matches(term: str, text: str, bug_class: str) -> bool:
    low = term.lower()
    if low in text:
        return True
    # See DOUBLE_FREE_SYNONYMS above: only a "double free"/"double-free" term on a
    # bug_class == "double-free" item gets the widened equivalence. Every other term, on
    # every other bug class, still needs its own literal keyword.
    if bug_class == "double-free" and low in DOUBLE_FREE_LITERAL:
        return any(synonym in text for synonym in DOUBLE_FREE_SYNONYMS)
    return False


def mechanism_matches(finding: dict[str, Any], item: dict[str, Any]) -> tuple[bool, list[str]]:
    groups = item.get("mechanism_all_of") or []
    if not groups:
        # `all()` over an empty list is True, so an item with no keyword groups would turn
        # every finding merely *near* its site into a HIT — the grader's own rule is that
        # "proximity alone is not a hit", and this is how it would stop being true. The
        # recipe validator rejects an empty group list, but the grader reads
        # ground_truth.json, which is a separate file that can be stale or hand-edited.
        raise GradeError(
            f"ground-truth item {item.get('id')!r} has no mechanism_all_of groups, so its "
            f"mechanism test would accept any finding at its site. A site match is not a hit."
        )
    text = finding_text(finding)
    bug_class = str(item.get("bug_class", ""))
    missing = [
        "/".join(group[:3]) + ("/..." if len(group) > 3 else "")
        for group in groups
        if not any(_term_matches(term, text, bug_class) for term in group)
    ]
    return (not missing), missing


def _best_candidate(
    candidates: list[dict[str, Any]],
    item: dict[str, Any],
    contention: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Which finding to show as the evidence for this bug.

    Not simply the first in file order, which is what this used to be. In both real runs
    of the shipped corpus that picked a finding that described a *different* bug in the
    same function: `SGL-B12` was reported as found by a finding about `SGL-B17`, while the
    finding that actually described B12 sat unmentioned further down the list. A human
    reading REPORT.md to check the grader was shown the wrong evidence for a right answer,
    which is the worst possible combination.

    Preference order, chosen so the result is total and stable:

    1. a function-name match over a line-window match;
    2. **the least contested finding** — one that matches only this bug is better evidence
       for it than one that matches three. This is what separates the two findings in
       `sgl_field_decode`, where both name the function and neither line is near either
       anchor, so a distance tie-break would be coin-flipping on noise;
    3. the closest line, then the id.
    """
    try:
        anchor = int(item.get("line", 0))
    except (TypeError, ValueError):
        anchor = 0
    contention = contention or {}

    def key(candidate: dict[str, Any]) -> tuple[int, int, int, str]:
        strength = 0 if candidate["site_kind"] == SITE_FUNCTION else 1
        contested = contention.get(candidate["id"], 1)
        distance = abs(candidate["line"] - anchor) if (candidate["line"] and anchor) else 10**6
        return (strength, contested, distance, candidate["id"])

    return min(candidates, key=key)


def _reported(finding: dict[str, Any]) -> bool:
    return bool(finding.get("reported", True))


def _resolve_ambiguity(rows: list[dict[str, Any]]) -> None:
    """One finding must not be the *sole* evidence for two different bugs.

    This is the defect that inflated recall on the one real run, and it is invisible in
    the output it produces. Two bugs in the same function are graded against the same
    findings, and the mechanism test is a keyword search over twelve concatenated fields,
    so a single sufficiently discursive finding can satisfy both bugs' keyword groups
    while describing only one of them. Demonstrated on the shipped corpus: delete the one
    finding that actually describes `SGL-B12` (a state-machine bypass) and the run still
    scores it a HIT, on a finding about `SGL-B17` that happens to contain the words
    "state", "before", "tag", "record" and "authentication" somewhere in its prose.

    The rule: if a finding is the only mechanism-matching candidate for more than one bug,
    at most one of those bugs was actually found. The best-supported one keeps its outcome
    and the rest become `AMBIGUOUS` — not `HIT`, because nothing in the run demonstrably
    describes them, and not `MISS`, because something in the run might. A human reads it.

    A bug with a *second*, independent matching finding is untouched: it has evidence that
    does not depend on the contested one. That is why neither real run loses a hit here —
    both filed a separate correct finding for the second bug — and it is exactly the
    distinction that makes this safe to apply retroactively.
    """
    resolvable = [r for r in rows if r["outcome"] in (HIT, SUPPRESSED) and r["matching_findings"]]
    sole: dict[str, list[dict[str, Any]]] = {}
    for row in resolvable:
        if len(row["matching_findings"]) == 1:
            sole.setdefault(row["matching_findings"][0], []).append(row)
    for finding_id, contested in sole.items():
        if len(contested) < 2:
            continue

        # Keep the bug whose own function the finding named, then the closest line, then
        # the lowest id, so the choice is total and does not depend on dict order.
        def key(row: dict[str, Any]) -> tuple[int, int, str]:
            evidence = row["evidence"] or {}
            strength = 0 if evidence.get("site_kind") == SITE_FUNCTION else 1
            distance = (
                abs(evidence.get("line", 0) - row["line"])
                if evidence.get("line") and row["line"]
                else 10**6
            )
            return (strength, distance, str(row["id"]))

        keeper = min(contested, key=key)
        for row in contested:
            if row is keeper:
                continue
            row["outcome"] = AMBIGUOUS
            row["ambiguous_with"] = keeper["id"]
            row["ambiguous_finding"] = finding_id


def grade(
    result: dict[str, Any],
    ground_truth: dict[str, Any],
    window: int = DEFAULT_WINDOW,
) -> dict[str, Any]:
    """Grade one normalised arm result against one corpus manifest."""
    items = ground_truth.get("items") or []
    findings = result.get("findings") or []
    if not items:
        raise GradeError(
            "the ground truth holds zero items, so grading would compare against nothing and "
            "report every arm as 0/0"
        )
    variant = result.get("variant", ground_truth.get("variant", "bench"))
    present = variant != "control"
    if not findings and present:
        raise GradeError(
            f"arm {result.get('arm')!r} on corpus {result.get('corpus')!r} produced zero findings. "
            f"That is a run to investigate, not a recall of 0/{len(items)} — a scorer that "
            f"inspected nothing must not report a score."
        )
    # On the patched control, zero findings is the *correct* outcome and the only perfect
    # one: there is nothing there to find, so every claim would be a false positive. The
    # bench-tree guard above must not fire here, or the first `--tier full` run refuses to
    # score its own best result.
    if "decoys" not in ground_truth:
        raise GradeError(
            "the ground truth has no `decoys` key, so the decoy-false-positive scan would "
            "inspect nothing and report zero decoy hits — which reads identically to an arm "
            "that fell for none of them. Rebuild the corpus."
        )
    if not ground_truth["decoys"]:
        raise GradeError(
            "the ground truth holds zero decoys, so the decoy-false-positive scan would "
            "inspect nothing and report zero decoy hits. Every recipe is required to declare "
            "decoys; a manifest without them was not built by this harness."
        )

    matched: set[str] = set()
    rows: list[dict[str, Any]] = []
    # How many bugs each finding is a mechanism-matching candidate for, computed over the
    # whole item list before any evidence is chosen. A finding that matches one bug is
    # better evidence for that bug than one that matches four.
    contention: dict[str, int] = {}
    for item in items:
        for finding in findings:
            if not file_matches(finding.get("file"), item["file"]):
                continue
            if not site_match(finding, item, window)[0]:
                continue
            if mechanism_matches(finding, item)[0]:
                fid = str(finding.get("id", "?"))
                contention[fid] = contention.get(fid, 0) + 1
    for item in items:
        candidates = []
        for finding in findings:
            if not file_matches(finding.get("file"), item["file"]):
                continue
            at_site, why, site_kind = site_match(finding, item, window)
            if not at_site:
                continue
            ok, missing = mechanism_matches(finding, item)
            try:
                found_line = int(finding.get("line", 0))
            except (TypeError, ValueError):
                found_line = 0
            candidates.append(
                {
                    "id": str(finding.get("id", "?")),
                    "reported": _reported(finding),
                    "mechanism_ok": ok,
                    "missing_mechanism_groups": missing,
                    "site": why,
                    "site_kind": site_kind,
                    "line": found_line,
                    "title": str(finding.get("title", "")),
                    "severity": str(finding.get("severity", "")),
                    "fp_verdict": str(finding.get("fp_verdict", "")),
                    "found_by": str(finding.get("found_by", "")),
                }
            )
        hits = [c for c in candidates if c["mechanism_ok"] and c["reported"]]
        suppressed = [c for c in candidates if c["mechanism_ok"] and not c["reported"]]
        near = [c for c in candidates if not c["mechanism_ok"]]
        if hits:
            outcome, evidence = HIT, _best_candidate(hits, item, contention)
        elif suppressed:
            outcome, evidence = SUPPRESSED, _best_candidate(suppressed, item, contention)
        elif near:
            outcome, evidence = NEAR_MISS, _best_candidate(near, item, contention)
        else:
            outcome, evidence = MISS, None
        # Every finding that describes this bug correctly is attributed to it, not only
        # the one that took the HIT slot: an arm that files the same bug twice was not
        # producing a false positive the second time. A NEAR_MISS is deliberately *not*
        # attributed — it is at the right site describing something else, so it stays
        # eligible to be a decoy hit or an unmatched finding.
        matched.update(c["id"] for c in candidates if c["mechanism_ok"])
        rows.append(
            {
                "id": item["id"],
                "bug_class": item["bug_class"],
                "difficulty": item["difficulty"],
                "file": item["file"],
                "function": item["function"],
                "line": item["line"],
                "outcome": outcome,
                "evidence": evidence,
                "candidate_count": len(candidates),
                "matching_findings": sorted(c["id"] for c in candidates if c["mechanism_ok"]),
            }
        )

    _resolve_ambiguity(rows)

    known = ground_truth.get("known_extra_findings") or []

    def known_extra_for(finding: dict[str, Any]) -> dict[str, Any] | None:
        """A documented weakness of the corpus itself, at that exact function.

        Resolved before the decoy scan, deliberately. A recorded weakness beats the
        coincidence of a decoy living in the same function: the first real run reported
        a genuine key disclosure and was charged for a `widened-type` decoy it never
        mentioned.
        """
        for extra in known:
            if file_matches(finding.get("file"), extra["file"]) and normalise_function(
                finding.get("function")
            ) == normalise_function(extra["function"]):
                return extra
        return None

    decoys = ground_truth.get("decoys") or []
    decoy_hits = []
    for finding in findings:
        # A finding that already matched an injected bug is correct, whatever else it
        # sits near. Counting it as a decoy hit too would charge an arm a false
        # positive for a true positive. Kept deliberately: `matched` is populated whenever
        # a finding's text satisfies *any* item's mechanism_all_of at that item's site, even
        # if `_resolve_ambiguity` later declines to credit it as that item's HIT (it may be
        # the better evidence for a sibling bug in the same function) -- the exemption from
        # decoy scanning tracks "this finding demonstrably describes an injected bug",
        # which does not change when the ambiguity tie-break picks a different bug for it.
        if str(finding.get("id", "?")) in matched or known_extra_for(finding):
            continue
        for decoy in decoys:
            if not file_matches(finding.get("file"), decoy["file"]):
                continue
            # Narrower than the bug-grading `window`: see DECOY_WINDOW above. `min` means a
            # caller who tightens `window` further (e.g. a test) tightens decoy attribution
            # too, but nothing ever widens it past DECOY_WINDOW.
            at_site, _why = site_matches(finding, decoy, min(window, DECOY_WINDOW))
            terms = DECOY_CLAIM_TERMS.get(str(decoy.get("decoy_kind")), [])
            text = finding_text(finding)
            claims_it = any(term.lower() in text for term in terms) if terms else True
            if at_site and claims_it:
                decoy_hits.append(
                    {
                        "finding": str(finding.get("id", "?")),
                        "decoy": decoy["id"],
                        "decoy_kind": decoy["decoy_kind"],
                        "title": str(finding.get("title", "")),
                        "reported": _reported(finding),
                    }
                )
                break

    canaries = [
        {
            "finding": str(finding.get("id", "?")),
            "cves": sorted({c.upper() for c in CVE_RE.findall(finding_text_raw(finding))}),
            "title": str(finding.get("title", "")),
        }
        for finding in findings
        if CVE_RE.search(finding_text_raw(finding))
    ]

    hit_rows = [r for r in rows if r["outcome"] == HIT]
    by_class: dict[str, dict[str, int]] = {}
    by_difficulty: dict[str, dict[str, int]] = {}
    for row in rows:
        for bucket, key in ((by_class, row["bug_class"]), (by_difficulty, row["difficulty"])):
            slot = bucket.setdefault(
                key, {"total": 0, "hits": 0, "suppressed": 0, "near": 0, "ambiguous": 0}
            )
            slot["total"] += 1
            if row["outcome"] == HIT:
                slot["hits"] += 1
            elif row["outcome"] == SUPPRESSED:
                slot["suppressed"] += 1
            elif row["outcome"] == NEAR_MISS:
                slot["near"] += 1
            elif row["outcome"] == AMBIGUOUS:
                slot["ambiguous"] += 1

    reported_findings = [f for f in findings if _reported(f)]
    decoy_ids = {d["finding"] for d in decoy_hits}
    known_extras: list[dict[str, Any]] = []
    unmatched: list[str] = []
    for finding in reported_findings:
        fid = str(finding.get("id", "?"))
        if fid in matched or fid in decoy_ids:
            continue
        hit_known = known_extra_for(finding)
        if hit_known:
            known_extras.append(
                {"finding": fid, "function": hit_known["function"], "note": hit_known["note"]}
            )
        else:
            unmatched.append(fid)

    control_fps = []
    if not present:
        by_id = {str(f.get("id", "?")): f for f in findings}
        for row in rows:
            evidence = row["evidence"]
            if evidence is None or row["outcome"] not in (HIT, SUPPRESSED, AMBIGUOUS):
                continue
            # A control-tree claim is a false positive "certain by construction" only if
            # there is genuinely nothing to find there. Where the recipe itself records a
            # weakness of the clean code at that function, there is: the weakness is present
            # in the control tree by definition. Charging it would penalise an arm for being
            # right, which is the same mistake that was already fixed once for decoys.
            source = by_id.get(evidence["id"])
            if source is not None and known_extra_for(source):
                known_extras.append(
                    {
                        "finding": evidence["id"],
                        "function": row["function"],
                        "note": known_extra_for(source)["note"],
                    }
                )
                continue
            control_fps.append(
                {"finding": evidence["id"], "claimed": row["id"], "title": evidence["title"]}
            )

    return {
        "arm": result.get("arm"),
        "corpus": result.get("corpus"),
        "variant": variant,
        "bugs_present": present,
        "graded_items": len(items),
        "graded_findings": len(findings),
        "reported_findings": len(reported_findings),
        "hits": len(hit_rows),
        "recall": len(hit_rows) / len(items) if present else None,
        "suppressed": sum(1 for r in rows if r["outcome"] == SUPPRESSED),
        "near_misses": sum(1 for r in rows if r["outcome"] == NEAR_MISS),
        "ambiguous": sum(1 for r in rows if r["outcome"] == AMBIGUOUS),
        "misses": sum(1 for r in rows if r["outcome"] == MISS),
        "false_positives": {
            DECOY_FP: decoy_hits,
            CONTROL_FP: control_fps,
            UNMATCHED: unmatched,
            KNOWN_EXTRA: known_extras,
        },
        "canary_cve_citations": canaries,
        "by_class": dict(sorted(by_class.items())),
        "by_difficulty": by_difficulty,
        "results": rows,
    }


# On the control tree the outcome names invert: a "hit" is a claim about a bug that is
# not there. Relabelling only the display keeps the data model one thing and stops the
# table reading as though the arm had succeeded.
CONTROL_LABELS = {
    HIT: "FP_CLAIMED",
    SUPPRESSED: "FP_DROPPED",
    NEAR_MISS: "near-claim",
    AMBIGUOUS: "FP_AMBIG",
    MISS: "silent",
}


def format_grade(scored: dict[str, Any]) -> str:
    control = not scored["bugs_present"]
    lines = [
        f"{scored['arm']} on {scored['corpus']} [{scored['variant']}]: "
        f"{scored['graded_findings']} finding(s) against {scored['graded_items']} injected bug(s)",
        "",
        f"{'BUG':<10} {'CLASS':<32} {'TIER':<7} {'OUTCOME':<11} EVIDENCE",
        f"{'-' * 10} {'-' * 32} {'-' * 7} {'-' * 11} {'-' * 34}",
    ]
    for row in scored["results"]:
        evidence = row["evidence"]
        if evidence is None:
            detail = "—"
        elif row["outcome"] == NEAR_MISS:
            detail = f"{evidence['id']} at {evidence['site']}; missing: " + ", ".join(
                evidence["missing_mechanism_groups"]
            )
        elif row["outcome"] == SUPPRESSED:
            detail = (
                f"{evidence['id']} found, not reported ({evidence['fp_verdict'] or 'no verdict'})"
            )
        elif row["outcome"] == AMBIGUOUS:
            detail = (
                f"only evidence is {row['ambiguous_finding']}, which is also the only evidence "
                f"for {row['ambiguous_with']} — not credited to both"
            )
        else:
            detail = f"{evidence['id']} [{evidence['severity'] or '-'}] {evidence['site']}"
        outcome = CONTROL_LABELS[row["outcome"]] if control else row["outcome"]
        lines.append(
            f"{row['id']:<10} {row['bug_class']:<32} {row['difficulty']:<7} {outcome:<11} {detail}"
        )
    lines.append("")
    if scored["bugs_present"]:
        lines.append(
            f"recall: {scored['hits']}/{scored['graded_items']} = {scored['recall']:.1%}   "
            f"suppressed: {scored['suppressed']}   near-miss: {scored['near_misses']}   "
            f"ambiguous: {scored['ambiguous']}   miss: {scored['misses']}"
        )
        if scored["ambiguous"]:
            lines.append(
                "  AMBIGUOUS means one finding was the only evidence for two bugs at the same "
                "site, so at most one of them was actually found. Read those findings before "
                "quoting the recall figure."
            )
    else:
        lines.append(
            "patched control: every claim of an injected bug here is a false positive "
            "by construction"
        )
    fps = scored["false_positives"]
    lines.append(
        f"false positives: {len(fps[DECOY_FP])} at decoys, {len(fps[CONTROL_FP])} on the control, "
        f"{len(fps[UNMATCHED])} unmatched finding(s) needing human triage, "
        f"{len(fps[KNOWN_EXTRA])} known corpus weakness(es)"
    )
    for extra in fps[KNOWN_EXTRA]:
        lines.append(
            f"  known extra: {extra['finding']} in {extra['function']} — {extra['note'][:90]}"
        )
    for hit in fps[DECOY_FP]:
        lines.append(
            f"  decoy {hit['decoy']} ({hit['decoy_kind']}) reported as "
            f"{hit['finding']}: {hit['title']}"
        )
    for hit in fps[CONTROL_FP]:
        lines.append(f"  control: {hit['finding']} claims {hit['claimed']}, which is not present")
    if scored["canary_cve_citations"]:
        lines.append(
            "CANARY: every bug in this corpus is ours, so a CVE citation is a recalled or "
            "invented attribution, never a lookup that could be right:"
        )
        for canary in scored["canary_cve_citations"]:
            lines.append(f"  {canary['finding']} cites {', '.join(canary['cves'])}")
    if scored["by_difficulty"]:
        lines.append(
            "by difficulty: "
            + "  ".join(
                f"{tier} {slot['hits']}/{slot['total']}"
                for tier, slot in scored["by_difficulty"].items()
            )
        )
    if scored["by_class"]:
        lines.append("by class:")
        for name, slot in scored["by_class"].items():
            lines.append(f"  {name:<34} {slot['hits']}/{slot['total']}")
    return "\n".join(lines)
