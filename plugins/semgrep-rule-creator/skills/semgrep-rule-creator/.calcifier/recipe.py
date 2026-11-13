# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from pathlib import Path

from calcifier import (
    Budget,
    CommandResult,
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
    tool,
    verify_artifact,
)

DOCS = "https://raw.githubusercontent.com/semgrep/semgrep-docs/refs/heads/main/docs/"
DOC_URLS = (
    DOCS + "writing-rules/rule-syntax.mdx",
    DOCS + "writing-rules/pattern-syntax.mdx",
    DOCS + "writing-rules/testing-rules.mdx",
    DOCS + "writing-rules/data-flow/taint-mode/overview.mdx",
    DOCS + "writing-rules/data-flow/taint-mode/advanced.mdx",
    DOCS + "writing-rules/data-flow/constant-propagation.mdx",
    "https://raw.githubusercontent.com/trailofbits/testing-handbook/refs/heads/main/"
    "content/docs/static-analysis/semgrep/10-advanced.md",
)


@output_type
class WorkReport:
    completed: bool
    report: str


@output_type
class CheckedFiles:
    rule_yaml: str
    test_code: str
    positive_lines: list[int]
    safe_lines: list[int]


@output_type
class RuleResult:
    rule_file: str
    test_file: str
    report: str
    files: CheckedFiles
    checks: dict[str, str]


@step
def fetch_documentation() -> str:
    responses: list[dict[str, object]] = []
    for url in DOC_URLS:
        response = tool(
            "WebFetch",
            url=url,
            prompt="Return the complete document text, without summarizing or omitting sections.",
        )
        if not response:
            fail(f"Required documentation returned no content: {url}")
        responses.append({"url": url, "response": response})
    return json.dumps(responses, ensure_ascii=False)


@step
def inspect_files(directory: Path, rule_id: str, language: str, extension: str) -> CheckedFiles:
    entries = list(directory.iterdir())
    names = {f"{rule_id}.yaml", f"{rule_id}.{extension}"}
    if {entry.name for entry in entries} != names or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        fail("The rule directory must contain exactly the two planned regular files.")
    rule_yaml = verify_artifact(directory / f"{rule_id}.yaml").read_text(encoding="utf-8")
    test_path = verify_artifact(directory / f"{rule_id}.{extension}")
    test_code = test_path.read_text(encoding="utf-8")
    try:
        document = json.loads(rule_yaml)
    except json.JSONDecodeError:
        fail("The .yaml file must use the requested JSON-compatible YAML serialization.")
    rules = document.get("rules") if isinstance(document, dict) else None
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        fail("Expected exactly one Semgrep rule in the YAML file.")
    if rules[0].get("id") != rule_id or rules[0].get("languages") != [language]:
        fail("The rule must use the requested ID and specific target language.")
    if re.search(r"\b(?:todook|todoruleid)\s*:", test_code):
        fail("Deferred test annotations are forbidden.")
    lines = test_code.splitlines()
    positive: list[int] = []
    safe: list[int] = []
    annotation = re.compile(
        r"\s*(?:#|//|--|;|%|!|')\s*(ruleid|ok):\s*" + re.escape(rule_id) + r"\s*"
    )
    for index, line in enumerate(lines):
        match = annotation.fullmatch(line)
        if match is None:
            if re.search(r"^\s*(?:#|//|/\*|<!--|--).*\b(?:ruleid|ok)\s*:", line):
                fail(f"Malformed or block-comment test annotation on line {index + 1}.")
            continue
        if index + 1 >= len(lines) or not lines[index + 1].strip():
            fail("Every annotation must immediately precede its test code.")
        (positive if match.group(1) == "ruleid" else safe).append(index + 2)
    if not positive or not safe:
        fail("Inspection requires nonempty vulnerable and safe annotated test coverage.")
    return CheckedFiles(
        rule_yaml=rule_yaml,
        test_code=test_code,
        positive_lines=positive,
        safe_lines=safe,
    )


@step
def verify_rule(
    directory: Path, rule_id: str, extension: str, expected: list[int]
) -> dict[str, str]:
    config, target = f"{rule_id}.yaml", f"{rule_id}.{extension}"
    commands = (
        ("validation", ["--validate", "--config", config]),
        ("tests", ["--test", "--config", config, target]),
        ("scan", ["--json", "--config", config, target]),
    )
    outputs: dict[str, str] = {}
    for name, arguments in commands:
        result: CommandResult = run_command(
            ["semgrep", "--disable-version-check", "--metrics=off", *arguments],
            working_directory=directory,
            timeout_seconds=180,
            mutating=False,
        )
        if result.exit_code:
            fail(f"Semgrep {name} failed:\n{result.stdout}\n{result.stderr}")
        outputs[name] = result.stdout if name == "scan" else result.stdout + result.stderr
        if name == "tests" and "All tests passed" not in outputs[name]:
            fail("Semgrep did not confirm that all tests passed.")
    try:
        scan = json.loads(outputs["scan"])
    except json.JSONDecodeError:
        fail("The final Semgrep scan did not return valid JSON.")
    findings = scan.get("results", [])
    if scan.get("errors") or not findings:
        fail("The final scan must inspect the test file successfully and find vulnerable cases.")
    if {finding["start"]["line"] for finding in findings} != set(expected):
        fail("Final findings differ from the complete set of vulnerable annotated lines.")
    for finding in findings:
        message = finding.get("extra", {}).get("message", "")
        if not message or re.search(r"\$(?:\.\.\.)?[A-Z_][A-Z0-9_]*", message):
            fail("A final finding has an empty message or an uninterpolated metavariable.")
    return outputs


@recipe(
    name="semgrep-rule-creator",
    version="1",
    agents=("worker",),
    capabilities=("Bash", "WebFetch"),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="semgrep-rules",
)
def create_rule(
    request: str,
    rule_id: str,
    language: str,
    test_extension: str,
    source_directory: str = ".",
) -> RuleResult:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", rule_id):
        fail("Use a lowercase rule ID containing alphanumeric words separated by hyphens.")
    if language.lower() == "generic" or not language.strip():
        fail("Supply a specific Semgrep target language; generic is forbidden.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", test_extension) or test_extension == "yaml":
        fail("Supply a safe test extension distinct from yaml; YAML tests can use yml.")
    project = Path(source_directory).resolve()
    if not project.is_dir():
        fail("The supplied project directory does not exist.")
    documents = fetch_documentation()
    directory = ensure_directory(
        rule_id,
        output_files=(f"{rule_id}.yaml", f"{rule_id}.{test_extension}"),
    )
    references = (
        resource("references/quick-reference.md"),
        resource("references/workflow.md"),
    )
    task = (
        f"Create a custom Semgrep rule for this request:\n{request}\n"
        f"Target language: {language}. The complete project is readable at {project}.\n"
        f"Use only {rule_id}.yaml and {rule_id}.{test_extension} in {directory}.\n"
        "Perform the full authoritative workflow in one connected session. Understand all "
        "seven fetched documents and both complete packaged references before writing code. "
        "Keep test-first design, AST interpretation, rule creation, repairs, optimization "
        "with retests and reverts, and final message checks together using your command tools. "
        "Track the original progress checklist internally. Python will rerun independent checks. "
        "Serialize the .yaml rule as a JSON object, which is valid YAML, for reliable parsing. "
        "Create exactly the two planned files; keep command output and progress off disk. "
        "Preserve required semantic test coverage while debugging. Return completed only when "
        "the entire original workflow has finished; otherwise explain the blocker in report. "
        "The report must include a junior-friendly explanation of the bug and the final result."
    )
    context = prepare_context(
        task,
        prior_results=documents,
        files=references,
        readable_roots=references,
    )
    work: WorkReport = agent(
        "worker",
        context.prompt,
        working_directory=directory,
        readable_paths=(project,),
        writable_paths=(directory,),
        required_capabilities=("commands",),
        output=WorkReport,
        timeout=3000,
        context=context,
    )
    if not work.completed:
        fail(work.report)
    files = inspect_files(directory, rule_id, language, test_extension)
    checks = verify_rule(directory, rule_id, test_extension, files.positive_lines)
    result = RuleResult(
        rule_file=str(directory / f"{rule_id}.yaml"),
        test_file=str(directory / f"{rule_id}.{test_extension}"),
        report=work.report,
        files=files,
        checks=checks,
    )
    return emit(result, name="semgrep-rule")


if __name__ == "__main__":
    raise SystemExit(create_rule.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("6ca2e3b8520ed20af1b0879b7cab318832fcbe89c19c17a9fa347a45a9f28913"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/quick-reference.md",
        "sha256": ("3e87f6e87b7cab07578037c6db1fb7d7cb57be03bbccc793c043720a8c3a435e"),
        "size": 5648,
        "source": None,
    },
    {
        "path": "references/workflow.md",
        "sha256": ("3dab347aa2e2c78b5a7a94ebb0d73d92dcb5c7df87d60ea9ee8f2671eba1c7b9"),
        "size": 7725,
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
