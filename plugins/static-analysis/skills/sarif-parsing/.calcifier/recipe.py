# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Process existing SARIF; retain interpretation in one agent session."""

import csv
import io
import json
import sys
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
    run_command,
    step,
    verify_artifact,
    write_json,
    write_text,
)

BRIDGE = """
import copy, json, runpy, sys
from dataclasses import asdict
from pathlib import Path
from urllib.parse import quote
h = runpy.run_path(sys.argv[1])
cfg = json.loads(sys.argv[2])
levels = ("error", "warning", "note", "none")
def check(ok, message):
    if not ok:
        raise ValueError(message)
def load(paths, root=""):
    merged = {"version": "2.1.0", "runs": []}
    for path in paths:
        log = h["load_sarif"](path)
        check(isinstance(log, dict) and log.get("version") == "2.1.0", "Invalid version")
        check(isinstance(log.get("runs"), list), "runs must be an array")
        for run in log["runs"]:
            check(isinstance(run, dict), "Invalid run")
            driver = run.get("tool", {}).get("driver", {})
            check(isinstance(driver.get("name"), str), "Missing driver name")
            rules = driver.get("rules", [])
            check(isinstance(rules, list), "Invalid rules")
            for rule in rules:
                level = rule.get("defaultConfiguration", {}).get("level", "warning")
                check(level in levels, "Invalid rule severity")
            results = run.get("results", [])
            check(isinstance(results, list), "Invalid results")
            for result in results:
                message = result.get("message")
                check(isinstance(message, dict), "Missing result message")
                check(any(isinstance(message.get(k), str) for k in ("text", "markdown")),
                      "Missing message text or markdown")
                check(result.get("level", "warning") in levels, "Invalid result severity")
                kinds = ("fail", "pass", "notApplicable", "review", "open", "informational")
                check(result.get("kind", "fail") in kinds, "Invalid result kind")
                check(isinstance(result.get("locations", []), list), "Invalid locations")
        merged["runs"].extend(log["runs"])
    check(merged["runs"], "Inspection scope contains no analysis runs")
    findings = h["extract_findings"](merged)
    prefix = h["normalize_path"](root).replace(chr(92), "/").rstrip("/")
    for finding in findings:
        if finding.file_path:
            normalized = h["normalize_path"](finding.file_path).replace(chr(92), "/")
            if prefix and normalized.startswith(prefix + "/"):
                normalized = normalized[len(prefix) + 1:]
            finding.file_path = normalized
            if not finding.fingerprint:
                raw = copy.deepcopy(finding.raw)
                location = raw["locations"][0]["physicalLocation"]["artifactLocation"]
                location["uri"] = quote(normalized)
                finding.fingerprint = h["compute_fingerprint"](raw)
        if not finding.message:
            finding.message = finding.raw.get("message", {}).get("markdown", "")
    return merged, findings
fixture_counts = {}
for path in cfg["fixtures"]:
    _, findings = load([path])
    count = len(h["filter_by_level"](findings, "error"))
    check(count == 1, "Expected exactly one error in fixture: " + path)
    fixture_counts[Path(path).name] = count
merged, current = load(cfg["current"], cfg["current_root"])
baseline = load(cfg["baseline"], cfg["baseline_root"])[1] if cfg["baseline"] else []
selected = current
if cfg["levels"]:
    selected = h["filter_by_level"](selected, *cfg["levels"])
if cfg["rules"]:
    selected = h["filter_by_rule"](selected, *cfg["rules"])
if cfg["file_contains"]:
    selected = h["filter_by_file"](selected, cfg["file_contains"])
if cfg["deduplicate"]:
    selected = h["deduplicate"](selected)
selected = h["sort_by_severity"](selected)
keep = {id(f.raw) for f in selected}
comparison = h["diff_findings"](baseline, current) if cfg["baseline"] else ([], [], [])
new, fixed, unchanged = comparison
violations = 0
if cfg["gate"] == "errors":
    violations = len(h["filter_by_level"](current, "error"))
elif cfg["gate"] == "new":
    violations = sum((f.raw.get("kind") or "fail") == "fail" for f in new)
for run in merged["runs"]:
    run["results"] = [r for r in run.get("results", []) if id(r) in keep]
check(sum(len(r["results"]) for r in merged["runs"]) == len(selected),
      "Exported result count differs from selection")
print(json.dumps({
    "summary": h["summary"](current), "selected_summary": h["summary"](selected),
    "baseline_summary": h["summary"](baseline), "fixture_errors": fixture_counts,
    "findings": [asdict(f) for f in selected],
    "comparison": {k: [asdict(f) for f in v] for k, v in (
        ("new", new), ("fixed", fixed), ("unchanged", unchanged))},
    "gate": cfg["gate"], "gate_violations": violations, "parameters": cfg,
    "sarif": merged, "csv_rows": h["to_csv_rows"](selected)
}))
"""


@output_type
class Assessment:
    narrative: str


@step
def process(config: dict[str, Any]) -> dict[str, Any]:
    result = run_command(
        [
            sys.executable,
            "-B",
            "-c",
            BRIDGE,
            str(resource("resources/sarif_helpers.py")),
            json.dumps(config),
        ],
        timeout_seconds=600,
        mutating=False,
    )
    if result.exit_code != 0:
        fail("SARIF processing failed: " + result.stderr)
    data = json.loads(result.stdout)
    if not isinstance(data, dict):
        fail("SARIF helper returned no structured result")
    return data


@recipe(
    name="sarif-parsing",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="sarif-output",
)
def sarif_parsing(
    sarif_paths: list[str],
    request: str = "Analyze these SARIF results and explain actionable findings.",
    baseline_paths: list[str] | None = None,
    levels: list[Literal["error", "warning", "note", "none"]] | None = None,
    rule_ids: list[str] | None = None,
    file_contains: str = "",
    deduplicate_results: bool = False,
    current_root: str = "",
    baseline_root: str = "",
    gate: Literal["none", "errors", "new"] = "none",
    schema_path: str | None = None,
) -> dict[str, Any]:
    if not sarif_paths:
        fail("Empty inspection scope: provide at least one existing SARIF file")
    if gate == "new" and not baseline_paths:
        fail("The new-issue gate requires baseline SARIF input")
    current = [Path(p).resolve() for p in sarif_paths]
    baseline = [Path(p).resolve() for p in baseline_paths or []]
    schema = Path(schema_path).resolve() if schema_path else None
    files = current + baseline + ([schema] if schema else [])
    if any(not path.is_file() for path in files):
        fail("Every SARIF input and optional schema must be an existing regular file")
    outputs = ("findings.json", "processed.sarif", "findings.csv", "report.md")
    ensure_directory(".", output_files=outputs)
    if schema:
        for path in current + baseline:
            result = run_command(
                ["ajv", "validate", "-s", str(schema), "-d", str(path)],
                timeout_seconds=120,
                mutating=False,
            )
            if result.exit_code != 0:
                fail("SARIF schema validation failed: " + result.stdout + result.stderr)
    references = [
        resource("resources/sarif_helpers.py"),
        resource("resources/jq-queries.md"),
        resource("resources/fixtures/codeql-no-level.sarif"),
        resource("resources/fixtures/levels-on-results.sarif"),
    ]
    data = process(
        {
            "current": [str(p) for p in current],
            "baseline": [str(p) for p in baseline],
            "fixtures": [str(p) for p in references[2:]],
            "levels": levels or [],
            "rules": rule_ids or [],
            "file_contains": file_contains,
            "deduplicate": deduplicate_results,
            "gate": gate,
            "current_root": current_root,
            "baseline_root": baseline_root,
        }
    )
    observations = {k: v for k, v in data.items() if k not in ("sarif", "csv_rows")}
    observations["schema_validation"] = bool(schema)
    observations["input_bytes"] = {str(p): p.stat().st_size for p in current + baseline}
    context = prepare_context(
        request,
        prior_results=json.dumps(observations),
        files=tuple(files + references),
        readable_roots=tuple(files + references),
    )
    assessment = agent(
        "worker",
        "Complete the original skill's connected interpretation and checks for the user's "
        "request using the complete input snapshots and references. Python has checked JSON, "
        "version and core shape, exercised both severity fixtures, normalized display paths "
        "and fallback fingerprint inputs, filtered, optionally deduplicated, compared and "
        "rendered data. Original SARIF paths and run metadata remain preserved in the export. "
        "Interpret every declared input; selected matches are not an exhaustive semantic scope. "
        "Explain actionable findings, absent optional data and uncertainty. Respect the skill's "
        "scope exclusions. Schema validation occurred only if observations say so. Helpers "
        "load in memory; assess the 100MB streaming guidance without claiming it was performed. "
        "Use the helper's actual path-sensitive fallback; do not promise environment-independent "
        "matching without justified roots. Discuss fingerprint and tool-version limitations, "
        "non-fail records, and relevant CI integration. Gate counts use all unfiltered current "
        "results; the new-issue gate excludes non-fail records. Keep reasoning internal and "
        "return a complete user-facing narrative addressing the request.",
        working_directory=".",
        readable_paths=tuple(files + references),
        context=context,
        output=Assessment,
        timeout=3600,
    )
    if not assessment.narrative.strip():
        fail("The interpretation session returned no report")
    report = (
        f"Inspected {len(current)} current files; {data['summary']['total']} results.\n\n"
        f"Selected {data['selected_summary']['total']}; gate {gate}: "
        f"{data['gate_violations']} violations.\n\n{assessment.narrative}"
    )
    stream = io.StringIO(newline="")
    csv.writer(stream).writerows(data["csv_rows"])
    write_json("findings.json", observations)
    write_json("processed.sarif", data["sarif"])
    write_text("findings.csv", stream.getvalue())
    write_text("report.md", report)
    paths = [str(verify_artifact(path)) for path in outputs]
    result = emit(
        {"report": report, "observations": observations, "artifacts": paths}, name="sarif-report"
    )
    if data["gate_violations"]:
        fail(f"CI gate failed: {data['gate_violations']} violating results; see emitted report")
    return result


if __name__ == "__main__":
    raise SystemExit(sarif_parsing.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("cc5f008f40ffb8a1ae03ebd32d7234de43e828293955a0bc251b76ba249554fa"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "resources/fixtures/codeql-no-level.sarif",
        "sha256": ("edc92b09e4d8b1247ec87f081c68caa1843d8407063508ad33aab13327ba386a"),
        "size": 2302,
        "source": None,
    },
    {
        "path": "resources/fixtures/levels-on-results.sarif",
        "sha256": ("625e8175a3c68d0d11f7e4c14095dddff5056d52a539e3153180cdb37ce50c6b"),
        "size": 1782,
        "source": None,
    },
    {
        "path": "resources/jq-queries.md",
        "sha256": ("f44ec4e219c93504ec69fdeb2c60668ee3934585e5565fffdaa43f6b224b5d6a"),
        "size": 7868,
        "source": None,
    },
    {
        "path": "resources/sarif_helpers.py",
        "sha256": ("06d8e63849bd2b93baf31b23a33550447eed2ac457c2687f173933039e5ad247"),
        "size": 13027,
        "source": None,
    },
    {
        "path": "resources/test_sarif_helpers.py",
        "sha256": ("5efc4e50f3dbd81ea223049b1892653a46bce0c273904d0b04e43e449343fe17"),
        "size": 14028,
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
