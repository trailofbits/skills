#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Apply strict confidence gates to zeroize-audit findings.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ADVANCED_MCP_CATEGORIES = {
    "SECRET_COPY",
    "MISSING_ON_ERROR_PATH",
    "NOT_DOMINATING_EXITS",
}

ASM_REQUIRED_CATEGORIES = {
    "STACK_RETENTION",
    "REGISTER_SPILL",
}


def _has_compiler_evidence(finding: dict[str, Any]) -> bool:
    ce = finding.get("compiler_evidence")
    if not isinstance(ce, dict):
        return False
    return any(ce.get(key) for key in ("o0", "o2", "diff_summary"))


def _has_marker(text: str, marker: str) -> bool:
    return marker in text.lower()


def apply_gates(
    report: dict[str, Any],
    mcp_available: bool,
    require_mcp_for_advanced: bool,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = report.get("findings", [])

    for finding in findings:
        category = finding.get("category")
        evidence = (finding.get("evidence") or "").lower()

        if category in {"OPTIMIZED_AWAY_ZEROIZE"} and not _has_compiler_evidence(finding):
            finding["needs_review"] = True
            finding["evidence"] = (
                finding.get("evidence", "")
                + " [gated: missing IR/ASM evidence for optimized-away claim]"
            ).strip()

        if category in ASM_REQUIRED_CATEGORIES and not _has_marker(evidence, "asm"):
            finding["needs_review"] = True
            finding["evidence"] = (
                finding.get("evidence", "") + " [gated: missing assembly evidence]"
            ).strip()

        if require_mcp_for_advanced and not mcp_available and category in ADVANCED_MCP_CATEGORIES:
            finding["needs_review"] = True
            finding["evidence"] = (
                finding.get("evidence", "")
                + " [gated: MCP unavailable for advanced semantic finding]"
            ).strip()

    summary = report.get("summary", {})
    if isinstance(summary, dict):
        summary["issues_found"] = len(findings)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply zeroize-audit confidence gates")
    parser.add_argument("--input", required=True, help="Input output.json path")
    parser.add_argument("--out", required=True, help="Output path")
    parser.add_argument(
        "--mcp-available",
        action="store_true",
        help="Set when MCP semantic evidence is available",
    )
    parser.add_argument(
        "--require-mcp-for-advanced",
        action="store_true",
        help="Downgrade advanced findings when MCP is unavailable",
    )
    args = parser.parse_args()

    report = json.loads(Path(args.input).read_text())
    if not isinstance(report, dict):
        print(
            f"Error: expected JSON object in {args.input}, got {type(report).__name__}",
            file=sys.stderr,
        )
        sys.exit(1)
    updated = apply_gates(
        report=report,
        mcp_available=args.mcp_available,
        require_mcp_for_advanced=args.require_mcp_for_advanced,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(updated, indent=2) + "\n")
    print(f"OK: wrote gated report to {out_path}")


if __name__ == "__main__":
    main()
