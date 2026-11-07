# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    step,
    write_text,
)

METRICS = (
    ("APKs Scanned", "total_apks"),
    ("Vulnerable", "vulnerable_apks"),
    ("Failed to scan", "failed_apks"),
    ("No Firebase config", "untested_apks"),
    ("Total Issues", "total_vulnerabilities"),
)
FIELDS = (
    ("Project ID", "project_ids"),
    ("Database URL", "database_urls"),
    ("Storage Bucket", "storage_buckets"),
    ("API Key", "api_keys"),
    ("Auth Domain", "auth_domains"),
)


@output_type
class Configuration:
    project_ids: list[str]
    database_urls: list[str]
    storage_buckets: list[str]
    api_keys: list[str]
    auth_domains: list[str]


@output_type
class ManualAPK:
    apk: str
    status: Literal["TESTED", "DECOMPILE_FAILED", "NO_CONFIG", "UNTESTED"]
    config: Configuration


@output_type
class Finding:
    apk: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    issue: str
    evidence: str
    remediation: str


@output_type
class Assessment:
    findings: list[Finding]
    discussion: str
    manual_results: list[ManualAPK]


@step
def inspect_scope(target: str) -> list[str]:
    if not target.strip():
        fail("Provide an APK file or directory path.")
    path = Path(target).resolve()
    if path.is_file():
        candidates = [path]
    elif path.is_dir():
        candidates = sorted(
            (p for p in path.iterdir() if p.is_file() and p.suffix in (".apk", ".APK")),
            key=lambda p: p.name,
        )
        if any(not p.resolve().is_relative_to(path) for p in candidates):
            fail("An APK symlink escapes the supplied directory; supply its explicit path.")
    else:
        fail("The supplied target does not exist or is not a file or directory.")
    if not candidates or any(p.suffix not in (".apk", ".APK") for p in candidates):
        fail("The inspection scope contains no supported APK files.")
    return [str(p) for p in candidates]


def checked_rows(rows: Any, names: list[str]) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        fail("Results must contain one record for every APK.")
    if sorted(r.get("apk", "") for r in rows) != sorted(names):
        fail("Reported APKs do not exactly match the inspection scope.")
    return rows


def table(headers: list[str], rows: list[list[str]]) -> str:
    grid = [headers, ["---"] * len(headers), *rows]
    escaped = [[value.replace("|", "\\|").replace("\n", "<br>") for value in row] for row in grid]
    return "\n".join("| " + " | ".join(row) + " |" for row in escaped)


def render(data: dict[str, Any], review: Assessment, scanned: bool) -> str:
    summary = [[label, str(data[key])] for label, key in METRICS]
    parts = ["## Scan Summary", table(["Metric", "Value"], summary)]
    parts.append(
        "Failed scans and NO_CONFIG APKs were not tested by the scanner; "
        "both groups are neither vulnerable nor clean."
    )
    if data["untested_apks"]:
        parts.append(
            "NO_CONFIG means the app may not use Firebase, or its configuration may be "
            "obfuscated or packed beyond what the scanner extracts."
        )
    if scanned:
        parts.append(
            "These metrics are the scanner's counters. It probes Cloud Functions only in "
            "us-central1 and limits authentication, Cloud Functions and Remote Config checks "
            "to its first extracted project ID/API key per APK. Supplemental results and "
            "remaining coverage are discussed below."
        )
    parts.append("## Extracted Configuration")
    for row in data["results"]:
        config = row.get("config", {})
        values = [
            [label, ", ".join(config.get(key, [])) or "Not extracted"] for label, key in FIELDS
        ]
        heading = "### " + row["apk"] + " (" + row["status"] + ")"
        parts += [heading, table(["Field", "Value"], values)]
    parts.append("## Vulnerabilities Found")
    findings = [[f.severity, f.apk + ": " + f.issue, f.evidence] for f in review.findings]
    parts.append(table(["Severity", "Issue", "Evidence"], findings))
    parts.append("## Remediation")
    parts += [f.apk + ": " + f.issue + " — " + f.remediation for f in review.findings]
    parts += ["Secure code examples: `references/vulnerabilities.md`.", review.discussion]
    return "\n\n".join(parts) + "\n"


@recipe(
    name="firebase-apk-scanner",
    version="1",
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="firebase-apk-audit",
)
def firebase_apk_scanner(
    target: str,
    authorization: Literal["explicit-permission"],
    production: Literal["non-production", "written-permission"],
) -> str:
    apks = inspect_scope(target)
    target_path = Path(target).resolve()
    names = [Path(p).name.removesuffix(".apk") for p in apks]
    root = ensure_directory(".", output_files=("report.md",), exclude_roots=tuple(apks))
    work = ensure_directory(
        "worker",
        output_files=(
            "scanner.stdout.txt",
            "scanner.stderr.txt",
            "scan_report.json",
            "scan_report.txt",
        ),
        exclude_roots=tuple(apks),
    )
    if any(work.iterdir()):
        fail("Use a fresh output directory so this audit cannot reuse earlier scan files.")
    script = resource("scanner.sh")
    patterns = resource("references/vulnerabilities.md")
    fallback = resource("references/manual-fallback.md")
    task = json.dumps(
        {
            "target": str(target_path),
            "apk_labels": names,
            "scanner_argv": ["bash", str(script), str(target_path)],
            "authorization": authorization,
            "production_permission": production,
        }
    )
    context = prepare_context(task, files=(patterns,), readable_roots=(patterns,))
    review = agent(
        "worker",
        (
            "Perform the complete authorized audit under the original skill in this session. "
            "Python has enumerated the whole target and prepared the scanner argv. Execute "
            "that unmodified scanner once here; own its dynamic output tree inside this "
            "writable workspace. Capture complete stdout/stderr in scanner.stdout.txt and "
            "scanner.stderr.txt. Copy each existing report byte-for-byte from the exact "
            "directory printed as Results saved to: into this workspace's scan_report.json "
            "and scan_report.txt. Never locate reports with a firebase_scan_* glob. Preserve "
            "reports even after a nonzero exit; never create placeholder report files. "
            "Use manual-fallback.md only if the scanner wrote no report. Understand the "
            "complete vulnerability reference and retain the original reasoning, ordering, "
            "checks, token reuse, cleanup, all-configuration and regional testing guidance. "
            "Search matches and scanner labels do not establish semantic completeness. "
            "Return findings with evidence and specific remediation, plus discussion covering "
            "every scanner finding, supplemental testing, uncertainties and remaining gaps. "
            "Use the supplied APK labels. Return manual_results only when no report exists, "
            "with every APK represented; UNTESTED denotes work that could not be performed. "
            "Use empty configuration arrays only for values not extracted. Do not modify APKs."
        ),
        working_directory=work,
        readable_paths=(target_path, script, fallback),
        writable_paths=(work,),
        required_capabilities=("commands",),
        output=Assessment,
        timeout=3600,
        context=context,
    )
    if not review.discussion.strip() or any(f.apk not in names for f in review.findings):
        fail("The analyst response lacks interpretation or refers to an APK outside the scope.")
    if any(
        not f.issue.strip() or not f.evidence.strip() or not f.remediation.strip()
        for f in review.findings
    ):
        fail("Every finding requires an issue, evidence and specific remediation.")
    json_path, text_path = work / "scan_report.json", work / "scan_report.txt"
    if json_path.is_symlink() or text_path.is_symlink():
        fail("Transported reports must be regular files within the audit workspace.")
    scanned = json_path.is_file() or text_path.is_file()
    if scanned:
        raw = json_path.read_text(encoding="utf-8") if json_path.is_file() else ""
        narrative = text_path.read_text(encoding="utf-8") if text_path.is_file() else ""
        emit(raw, name="scanner-json")
        emit(narrative, name="scanner-narrative")
        if not raw or not narrative or review.manual_results:
            fail("A scanner report exists; preserve both reports and do not use manual fallback.")
        data = json.loads(raw)
        if not isinstance(data, dict) or any(
            type(data.get(key)) is not int or data[key] < 0 for _, key in METRICS
        ):
            fail("Scanner metrics are missing or invalid; the original reports were emitted.")
        checked_rows(data.get("results"), names)
        if data["total_apks"] != len(apks):
            fail("The scanner's total does not match the supplied APK scope.")
    else:
        rows = checked_rows([r.model_dump() for r in review.manual_results], names)
        data = {
            "total_apks": len(apks),
            "vulnerable_apks": len({f.apk for f in review.findings}),
            "failed_apks": sum(r["status"] == "DECOMPILE_FAILED" for r in rows),
            "untested_apks": sum(r["status"] == "NO_CONFIG" for r in rows),
            "total_vulnerabilities": len(review.findings),
            "results": rows,
        }
        emit(data, name="manual-results")
    report = render(data, review, scanned)
    write_text(root / "report.md", report)
    emit(report, name="report")
    if not any(r["status"] in ("TESTED", "SECURE", "VULNERABLE") for r in data["results"]):
        fail("No APK's Firebase endpoints were tested; available results were emitted.")
    return report


if __name__ == "__main__":
    raise SystemExit(firebase_apk_scanner.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("1c63bf5e2a0cfde241eefdc12d20a4df0572d0df96df503a163f7224af137be3"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/manual-fallback.md",
        "sha256": ("2cee4a46c3c3e4685248a6fda92e65983527d322d5f9f68ff474052265212d96"),
        "size": 1511,
        "source": None,
    },
    {
        "path": "references/vulnerabilities.md",
        "sha256": ("7ae89875a6e0f5a0dfc0da6172f1bdfe6d2719e66dcea6b94c62158d5e9ae1fa"),
        "size": 21033,
        "source": None,
    },
    {
        "path": "scanner.sh",
        "sha256": ("90470b72ed4db246fc49ff9f2a70b1e343bc5f804b9e20817720548feff469f0"),
        "size": 52242,
        "source": None,
    },
]
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, target-version py311, and line-length 100. The g"
        "enerated recipe must satisfy those checks, including B007,"
        " B905, and SIM102. Keep the Python 3.13 minimum required b"
        "y Calcifier in its generated PEP 723 header. This skill is"
        " distributed independently: do not require another unmerge"
        "d skill recipe. Referenced prose and explicitly provided r"
        "esources may be packaged, while the generated recipe belon"
        "gs only to the requested skill. Repository contribution ru"
        "le: a checker that inspects zero items must fail with an e"
        "xplanation rather than return a successful clean report. T"
        "his applies to an empty inspection scope, not to a complet"
        "ed inspection that finds zero issues."
    ),
    "sha256": ("12c73b0662a6bdb615688c499f4e3e22540e4788549e5ad24bb7e01f76c25fcc"),
}
_CALCIFIER_SUBRECIPES = []
