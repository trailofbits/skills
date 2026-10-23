# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Run Trailmark's parser-based structural summary without installing it."""

import json
import re
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
    CommandResult,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    run_command,
)

PREFIXES = (("trailmark",), ("uv", "run", "trailmark"))
DETECT = (
    "import json\nimport sys\n"
    "try:\n"
    "    from trailmark.parse import detect_languages\n"
    "except ModuleNotFoundError:\n"
    "    from trailmark.query.api import detect_languages\n"
    "print(json.dumps(detect_languages(sys.argv[1])))\n"
)
FIELDS = (
    "languages",
    "source_files",
    "source_file_counts",
    "parse_diagnostics",
    "entrypoints",
    "dependencies",
)


@output_type
class Summary:
    target: str
    version: str | None
    format: Literal["json", "text"]
    detected_languages: list[str]
    fields: dict[str, Any]
    inspected_source_files: int | None
    entrypoint_count: int | None
    unavailable_fields: list[str]
    full_summary: str
    stderr: str
    interpretation: str


def invoke(argv: list[str], directory: Path) -> CommandResult:
    try:
        return run_command(
            argv,
            timeout_seconds=300,
            working_directory=directory,
            mutating=argv[0] == "uv",
        )
    except Exception as error:
        if getattr(error, "command_failure", None) not in ("launch", "timeout"):
            raise
        return CommandResult(argv=argv, exit_code=127, stdout="", stderr=str(error))


def count_value(value: Any) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("count", "total"):
            if type(value.get(key)) is int:
                return value[key]
    if isinstance(value, str):
        match = re.match(r"\s*(?:Entrypoints\s*:\s*)?(\d+)\b", value, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def source_count(fields: dict[str, Any]) -> int | None:
    total = count_value(fields.get("source_files"))
    if total is not None:
        return total
    counts = fields.get("source_file_counts")
    if isinstance(counts, dict) and all(type(value) is int for value in counts.values()):
        if any(value < 0 for value in counts.values()):
            fail("Trailmark reported an invalid negative source-file count.")
        return sum(counts.values())
    return None


def text_fields(text: str, languages: list[str]) -> dict[str, Any]:
    fields: dict[str, Any] = {"languages": languages}
    for key, label in (("entrypoints", "Entrypoints"), ("dependencies", "Dependencies")):
        lines = [
            line for line in text.splitlines() if re.match(rf"\s*{label}\s*:", line, re.IGNORECASE)
        ]
        if lines:
            fields[key] = "\n".join(lines)
    match = re.search(r"^\s*Source[ _-]*files\s*:\s*(\d+)\b", text, re.I | re.M)
    if match:
        fields["source_files"] = int(match.group(1))
    return fields


@recipe(
    name="trailmark_summary",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def trailmark_summary(args: str = ".") -> Summary:
    target = Path(args).resolve()
    if not target.is_dir():
        fail(f"Trailmark target is not an existing directory: {target}")

    selected = PREFIXES[0]
    help_text = ""
    for prefix in PREFIXES:
        check = invoke([*prefix, "analyze", "--help"], target)
        if check.exit_code == 0:
            selected = prefix
            help_text = check.stdout + "\n" + check.stderr
            break
    else:
        fail("trailmark is not installed")

    version_result = invoke([*selected, "--version"], target)
    version = None
    if version_result.exit_code == 0:
        version = (version_result.stdout.strip() or version_result.stderr.strip()) or None

    detection = invoke(["python3", "-c", DETECT, str(target)], target)
    if detection.exit_code != 0:
        import_failed = any(
            name in detection.stderr for name in ("ImportError", "ModuleNotFoundError")
        )
        if not import_failed and detection.exit_code != 127:
            fail(f"Trailmark language detection failed:\n{detection.stderr}")
        detection = invoke(
            ["uv", "run", "--with", "trailmark", "python", "-c", DETECT, str(target)],
            target,
        )
    if detection.exit_code != 0:
        fail(f"Trailmark language detection failed:\n{detection.stderr}")
    try:
        languages = json.loads(detection.stdout)
    except json.JSONDecodeError:
        fail("Trailmark language detection did not return valid JSON.")
    if not isinstance(languages, list) or not all(
        isinstance(item, str) and item.strip() for item in languages
    ):
        fail("Trailmark language detection did not return a list of language names.")
    if not languages:
        fail("Trailmark found no supported languages under target")

    release = re.search(r"\b(\d+)\.(\d+)(?:\.\d+)?\b", version or "")
    use_json = "--json" in help_text or (
        release is not None and (int(release.group(1)), int(release.group(2))) >= (0, 7)
    )
    summary = CommandResult(argv=[], exit_code=1, stdout="", stderr="")
    attempted: list[dict[str, Any]] = []
    for prefix in PREFIXES:
        flags = ["analyze", "--language", "auto", "--summary"]
        if use_json:
            flags.append("--json")
        summary = invoke([*prefix, *flags, str(target)], target)
        attempted.append(
            {"argv": summary.argv, "exit_code": summary.exit_code, "stderr": summary.stderr}
        )
        if summary.exit_code == 0:
            if prefix != selected:
                version_result = invoke([*prefix, "--version"], target)
                version = None
                if version_result.exit_code == 0:
                    version = (
                        version_result.stdout.strip() or version_result.stderr.strip()
                    ) or None
            break
    else:
        emit(attempted, name="failed-summary-commands")
        fail("Trailmark summary failed; command diagnostics are attached.")

    full_summary = summary.stdout
    if not full_summary.strip():
        fail("Trailmark returned an empty summary.")
    if use_json:
        try:
            fields = json.loads(full_summary)
        except json.JSONDecodeError:
            fail("Trailmark JSON summary did not return valid JSON.")
        if not isinstance(fields, dict):
            fail("Trailmark JSON summary must be an object.")
    else:
        fields = text_fields(full_summary + "\n" + summary.stderr, languages)

    inspected = source_count(fields)
    if fields.get("languages") == [] or (inspected is not None and inspected <= 0):
        emit({"fields": fields, "summary": full_summary}, name="empty-inspection")
        fail("Trailmark inspected no source files; an empty scope is not a clean report.")
    entrypoints = count_value(fields.get("entrypoints"))
    if entrypoints is not None and entrypoints < 0:
        fail("Trailmark reported an invalid negative entrypoint count.")
    unavailable = [key for key in FIELDS if fields.get(key) is None]
    if inspected is None:
        unavailable.append("inspected_source_files")
    if entrypoints is None:
        unavailable.append("entrypoint_count")
    report = Summary(
        target=str(target),
        version=version,
        format="json" if use_json else "text",
        detected_languages=languages,
        fields=fields,
        inspected_source_files=inspected,
        entrypoint_count=entrypoints,
        unavailable_fields=unavailable,
        full_summary=full_summary,
        stderr=summary.stderr,
        interpretation="",
    )
    context = prepare_context(
        "Interpret this completed Trailmark summary using the original skill instructions. "
        "Execution, language detection, and field extraction are already performed. "
        "Explain parse limitations and unavailable fields alongside source counts, "
        "entrypoints, and dependencies. Counts describe inspected files, not complete "
        "coverage. Preserve the original reasoning guidance. Do not rerun commands "
        "or substitute manual code reading for Trailmark. Return only the interpretive "
        "summary; the recipe retains every supplied field and the complete raw output.",
        prior_results=report.model_dump_json(),
    )
    report.interpretation = agent(
        "worker",
        "Interpret the complete prepared observations and return the summary.",
        working_directory=target,
        readable_paths=(target,),
        context=context,
        output=str,
        timeout=3600,
    )
    if not report.interpretation.strip():
        fail("The summary interpretation is missing.")
    return emit(report, name="trailmark-summary")


if __name__ == "__main__":
    raise SystemExit(trailmark_summary.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("bf6dfdedbb1da5d433ab4550fc5f7f76be2a2a56990d847e14e2fc277ed64825"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
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
