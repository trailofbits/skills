"""Convert Wilson's `final_report.json` into the generic finding shape `lib/result.py`
normalises for a non-c-review arm (a dict with a top-level `findings` list, each item
carrying `file`/`line`/`title`/`description` per `lib.result.REQUIRED_FINDING_FIELDS`).

Wilson here means the Claude Code plugin at `skills-internal/plugins/wilson`
(`skills/wilson-audit/SKILL.md`), not the standalone `tob/wilson` CLI — the two have
different output shapes and an earlier version of this converter's design doc analysed
the wrong one. The shape below was read from the plugin's own code, not guessed:
`skills-internal/plugins/wilson/scripts/export_reports.py::normalize_finding()` (the
function that actually builds `final_report.json`), the JSON Schemas under
`skills-internal/plugins/wilson/skills/wilson-audit/references/schemas/` (`report.json`,
`finding.json`, `base.json`), and
`skills-internal/plugins/wilson/scripts/tests/test_export_reports.py`.

Three things about Wilson's shape do not match the harness's generic shape, and each is
handled deliberately here rather than papered over:

1. **No top-level `file`/`line`.** The pre-judge finding schema (`finding.json`) has a
   `location` object, but `export_reports.py::normalize_finding()` does not carry it
   into `final_report.json` at all — read that function: its returned dict has no
   `location` key. A location, if present, survives only inside `evidence[]` items
   (`base.json#/definitions/EvidenceItem`: `path`, `line_start`, `line_end`, `snippet`,
   every one of them individually optional or nullable). This module accepts only an
   evidence item that carries *both* a non-empty `path` and an integer `line_start`;
   anything weaker (a path with no line, a line with no path, or no evidence at all) is
   treated as "no usable location", never as a real file paired with a placeholder
   line. Pairing a fabricated line with a genuine file would be indistinguishable, once
   it reaches `lib/grade.py::site_match`'s +-12-line window, from a real claim — it
   could coincidentally match or miss a real bug for a reason that has nothing to do
   with what Wilson actually reported.
2. **`exploit_scenario`/`attack_vector` are not in `lib/grade.py::TEXT_FIELDS`.** Those
   two fields are where a Wilson hunter states the mechanism most concretely (see
   `skills/hunt-appsec-taossa/SKILL.md`'s required output fields: "exploit_scenario:
   step-by-step", "attack_vector: specific entry point"). `TEXT_FIELDS` is the tuple
   `lib/grade.py::mechanism_matches()` searches for the keyword groups that turn a
   site match into a HIT, and it does not include either field. Leaving them out of the
   converted `description` would make the grader blind to exactly the text that would
   otherwise earn the hit, understating Wilson's recall for a reason that is a
   converter bug, not a Wilson weakness. Both are appended into `description` (which
   *is* in `TEXT_FIELDS`), each under a labelled heading so a human reading
   `collected/*.json` later can still tell Wilson's own description apart from the
   folded-in text.
3. **The zero-item guard.** An input `final_report.json` with `"findings": []` is a
   legitimate clean run — nothing is wrong with the harness or with Wilson's output.
   An input with a *non-empty* `findings` array that converts to zero output findings
   (every entry failed even the minimal "is this a JSON object" check) means the parser
   broke, not that Wilson found nothing, and that must fail loudly rather than emit an
   empty result indistinguishable from a clean one.

A finding with no usable location is not dropped: it is emitted with `file` set to a
sentinel (`NO_LOCATION_FILE_MARKER`) that cannot suffix-match any real corpus path
(`lib/grade.py::file_matches`), so it structurally cannot be scored a HIT/NEAR_MISS at
any site, and `wilson_has_location: false` marks it explicitly. It still counts as a
`graded_finding` and, being unmatched everywhere, lands in `lib/grade.py`'s `UNMATCHED`
bucket for a human to read — silently dropping it would instead overstate precision by
shrinking the denominator of findings a human has to triage. The counts are surfaced in
this module's own output under `wilson_conversion`, not folded away.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Guaranteed not to collide with a real corpus path: no corpus file is named this, and
# `lib/grade.py::file_matches` is a suffix match on path segments, so this only matches
# another finding that used the same marker.
NO_LOCATION_FILE_MARKER = "WILSON-NO-LOCATION-REPORTED"
# Inert given the marker above: `file_matches` fails before `site_match` is ever
# consulted, so this value never participates in the +-12-line window. It exists only
# to satisfy `lib.result.validate_findings`'s "line must be an integer >= 1" check
# without claiming a real line number.
NO_LOCATION_LINE = 1


class WilsonConvertError(Exception):
    """The input could not be converted. Callers exit non-zero."""


def _fold_mechanism_text(raw: dict[str, Any]) -> str:
    """`description` plus the mechanism-bearing prose `TEXT_FIELDS` would otherwise miss."""
    parts = []
    description = str(raw.get("description") or "").strip()
    if description:
        parts.append(description)
    attack_vector = str(raw.get("attack_vector") or "").strip()
    if attack_vector:
        parts.append(f"Attack vector: {attack_vector}")
    exploit_scenario = str(raw.get("exploit_scenario") or "").strip()
    if exploit_scenario:
        parts.append(f"Exploit scenario: {exploit_scenario}")
    return "\n\n".join(parts)


def _extract_location(raw: dict[str, Any]) -> tuple[str, int, str | None] | None:
    """The first `evidence[]` item with both a real path and a real line, or `None`.

    Deliberately does not gate on `evidence[].type` — the plugin's own SARIF exporter
    (`export_reports.py::to_sarif`) does not gate on it either, it only checks `path`
    and `line_start` are present. Gating on `type == "code"` was a mistake carried over
    from reading the unrelated standalone CLI's schema, which uses a different, narrower
    enum for that field.
    """
    evidence = raw.get("evidence")
    if not isinstance(evidence, list):
        return None
    for item in evidence:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if not isinstance(path, str) or not path.strip():
            continue
        try:
            line = int(item.get("line_start"))
        except (TypeError, ValueError):
            continue
        if line < 1:
            continue
        return path.strip(), line, item.get("snippet")
    return None


def _convert_finding(raw: dict[str, Any], index: int) -> dict[str, Any]:
    location = _extract_location(raw)
    if location is None:
        file_value, line_value, code = NO_LOCATION_FILE_MARKER, NO_LOCATION_LINE, None
        has_location = False
    else:
        file_value, line_value, code = location
        has_location = True

    description = _fold_mechanism_text(raw) or "(Wilson finding had no description text)"
    finding: dict[str, Any] = {
        "id": str(raw.get("id") or f"WILSON-{index + 1}"),
        "file": file_value,
        "line": line_value,
        "title": str(raw.get("title") or "").strip() or "Untitled Wilson finding",
        "description": description,
        "impact": str(raw.get("impact") or ""),
        "severity": str(raw.get("severity") or ""),
        "confidence": raw.get("confidence"),
        "found_by": str(raw.get("hunter_name") or ""),
        # final_report.json only ever holds findings that already cleared the run's
        # confidence_threshold filter (export_reports.py::build_report), so unlike
        # c-review's own findings.json (a superset lib.result.normalise_c_review must
        # filter), everything here already is the reported set.
        "reported": True,
        "wilson_has_location": has_location,
    }
    if code:
        finding["code"] = str(code)

    # blocking_controls_checked is Wilson's real analogue of the harness's
    # mitigations_checked field (both record which mitigations were considered and
    # ruled out), so this is a genuine correspondence, not an invented one.
    controls = raw.get("blocking_controls_checked")
    if isinstance(controls, list) and controls:
        finding["mitigations_checked"] = "; ".join(str(c) for c in controls)

    return finding


def convert_report(report: dict[str, Any]) -> dict[str, Any]:
    """Convert one parsed `final_report.json` document into the generic result shape."""
    if not isinstance(report, dict):
        raise WilsonConvertError(
            f"expected a JSON object at the top level, got {type(report).__name__}"
        )
    raw_findings = report.get("findings")
    if raw_findings is None:
        raise WilsonConvertError(
            "input has no 'findings' key. Is this really Wilson's final_report.json?"
        )
    if not isinstance(raw_findings, list):
        raise WilsonConvertError(f"'findings' is a {type(raw_findings).__name__}, expected a list")

    converted: list[dict[str, Any]] = []
    skipped_unparseable = 0
    for index, raw in enumerate(raw_findings):
        if not isinstance(raw, dict):
            skipped_unparseable += 1
            continue
        converted.append(_convert_finding(raw, index))

    if raw_findings and not converted:
        raise WilsonConvertError(
            f"{len(raw_findings)} finding(s) in the input but 0 converted — every entry "
            f"failed to parse as a JSON object. This is a converter or input-shape failure, "
            f"not a clean run: a zero-finding result must come from an empty 'findings' "
            f"array, not from every entry being unparseable."
        )

    with_location = sum(1 for f in converted if f["wilson_has_location"])
    return {
        "findings": converted,
        "wilson_conversion": {
            "input_findings": len(raw_findings),
            "converted_findings": len(converted),
            "skipped_unparseable": skipped_unparseable,
            "with_location": with_location,
            "without_location": len(converted) - with_location,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert Wilson's final_report.json into the c-review-bench generic "
        "result shape."
    )
    parser.add_argument("--input", required=True, type=Path, help="Wilson's final_report.json")
    parser.add_argument(
        "--output", required=True, type=Path, help="where to write the converted result JSON"
    )
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.input.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: {args.input} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    try:
        result = convert_report(report)
    except WilsonConvertError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    stats = result["wilson_conversion"]
    print(
        f"converted {stats['converted_findings']}/{stats['input_findings']} finding(s) "
        f"({stats['with_location']} with a location, {stats['without_location']} without, "
        f"{stats['skipped_unparseable']} unparseable) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
