# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from pathlib import Path
from typing import Any, Literal

import calcifier as cf

INSPECT = (
    "import json, pathlib, sys, yaml\n"
    "document = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
    "rules = document['rules']\n"
    "assert isinstance(rules, list) and len(rules) == 1, 'Supply exactly one rule'\n"
    "r = rules[0]\n"
    "print(json.dumps({'rule_id': r['id'], 'languages': r['languages'], "
    "'mode': r.get('mode', 'search'), 'metadata': r.get('metadata') or {}}))\n"
)


@cf.output_type
class Target:
    language: str
    key: str
    extension: str


@cf.output_type
class RuleInfo:
    rule_id: str
    languages: list[str]
    mode: str
    metadata: dict[str, Any]


@cf.output_type
class Decision:
    verdict: Literal["APPLICABLE", "APPLICABLE_WITH_ADAPTATION", "NOT_APPLICABLE"] | None
    semgrepCanAnalyze: bool | None
    reasoning: str
    notes: str


@cf.step
def session(task: str, prior: str, files: tuple[Path, ...], work: Path) -> Decision:
    context = cf.prepare_context(
        task,
        instructions=(
            "Follow the authoritative skill and complete references in their original order. "
            "Read the original rule from its file. Work only on the assigned language. "
            "Use the supplied binary and version; never install or switch Semgrep. Research "
            "API semantics using available command tools. Stop with a configuration explanation "
            "if required research cannot be performed. Confirm the requested language, parser "
            "key, and extension agree; otherwise return unresolved decisions and explain. "
            "Write only the three planned scratch files. Tests precede translation, AST "
            "inspection precedes the rule, and validation ends the cycle. Perform one "
            "validation attempt; Python owns subsequent retries. Report actual parser and "
            "validation failures in notes. Preserve source scope and detection mode. "
            "Return null decisions for unresolved work, with specific reasoning."
        ),
        prior_results=prior,
        files=files,
        readable_roots=files,
    )
    answer = cf.agent(
        "worker",
        context.prompt,
        context=context,
        working_directory=work,
        readable_paths=files,
        writable_paths=(work,),
        required_capabilities=("commands",),
        output=Decision,
        timeout=3600,
    )
    if not answer.reasoning.strip():
        cf.fail("Required applicability reasoning is missing; the assignment is unfinished.")
    return answer


@cf.step
def audit(
    binary: str,
    version: str,
    info: RuleInfo,
    key: str,
    rule: Path,
    test: Path,
    frozen: str,
) -> dict[str, Any]:
    if any(not p.is_file() or p.is_symlink() for p in (rule, test)):
        return {"ok": False, "error": "Required regular rule/test files are missing."}
    text = test.read_text(encoding="utf-8")
    if text != frozen:
        return {"ok": False, "error": "Validation repair changed the test specification."}
    wanted = f"{info.rule_id}-{key}"
    groups: dict[str, list[int]] = {"ruleid": [], "ok": []}
    lines = text.splitlines()
    for n, line in enumerate(lines):
        match = re.search(r"\b(ruleid|ok):\s*(\S+)", line)
        if match and match.group(2) == wanted:
            if (
                n + 1 >= len(lines)
                or not lines[n + 1].strip()
                or re.search(r"\b(?:ruleid|ok):", lines[n + 1])
            ):
                return {"ok": False, "error": "An annotation does not immediately precede code."}
            groups[match.group(1)].append(n + 2)
    if min(len(values) for values in groups.values()) < 2:
        return {"ok": False, "error": "At least two ruleid and two ok cases are required."}
    commands = (
        [binary, "--version"],
        ["python3", "-c", INSPECT, str(rule)],
        [binary, "--dump-ast", "-l", key, str(test)],
        [binary, "--validate", "--config", str(rule)],
        [binary, "--test", "--json", "--config", str(rule), str(test)],
    )
    logs: list[dict[str, Any]] = []
    for index, argv in enumerate(commands):
        result = cf.run_command(argv, timeout_seconds=300, mutating=False)
        logs.append(
            {
                "argv": argv,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        if index == 0 and (result.exit_code or result.stdout.strip() != version):
            cf.fail("The recorded Semgrep version is unavailable or changed.")
        if result.exit_code:
            return {"ok": False, "commands": logs}
    try:
        translated = json.loads(logs[1]["stdout"])
        payload = json.loads(logs[-1]["stdout"])
        checks = [
            (rule_id, check)
            for item in payload.get("results", {}).values()
            for rule_id, check in item.get("checks", {}).items()
        ]
        matches = list(checks[0][1].get("matches", {}).values()) if len(checks) == 1 else []
        passed = (
            translated["rule_id"] == wanted
            and translated["languages"] == [key]
            and translated["mode"] == info.mode
            and translated["metadata"].get("original-rule") == info.rule_id
            and translated["metadata"].get("ported-from") == info.languages
            and len(checks) == 1
            and checks[0][0] == wanted
            and checks[0][1].get("passed") is True
            and len(matches) == 1
            and set(matches[0].get("expected_lines", [])) == set(groups["ruleid"])
            and set(matches[0].get("reported_lines", [])) == set(groups["ruleid"])
            and not payload.get("config_with_errors")
            and not payload.get("config_missing_tests")
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"ok": False, "error": "Unrecognized inspection/test JSON.", "commands": logs}
    return {
        "ok": passed,
        "commands": logs,
        "annotations": groups,
        "error": "" if passed else "Metadata mismatch, failed tests, or zero graded tests.",
    }


@cf.recipe(
    agents=("worker",),
    capabilities=("Bash",),
    budget=cf.Budget(80, 3600),
    output_root="variants",
)
def port_rule(rule_path: str, languages: list[Target]) -> dict[str, Any]:
    cf.emit(
        "I will port each requested language through its ordered test-driven cycle.", name="start"
    )
    if not 1 <= len(languages) <= 8:
        cf.fail("Supply one to eight individual target languages; empty scope cannot pass.")
    source = Path(rule_path).expanduser().resolve(strict=True)
    if not source.is_file() or not source.stat().st_size:
        cf.fail("The original rule must be a nonempty regular file.")
    info = cf.run_command(
        ["python3", "-c", INSPECT, str(source)],
        timeout_seconds=30,
        mutating=False,
        output=RuleInfo,
    )
    if not info.languages or not re.fullmatch(r"[A-Za-z0-9_.-]+", info.rule_id):
        cf.fail("The source needs a language and a rule id suitable for variant filenames.")
    located = cf.run_command(["which", "semgrep"], timeout_seconds=30, mutating=False)
    if located.exit_code or not located.stdout.strip():
        cf.fail("Configure Semgrep and python3 with PyYAML before running this recipe.")
    binary = str(Path(located.stdout.strip()).resolve(strict=True))
    recorded = cf.run_command([binary, "--version"], timeout_seconds=30, mutating=False)
    supported = cf.run_command(
        [binary, "show", "supported-languages"],
        timeout_seconds=30,
        mutating=False,
    )
    if recorded.exit_code or supported.exit_code or not recorded.stdout.strip():
        cf.fail("Cannot record the required Semgrep version and frontend support.")
    version = recorded.stdout.strip()
    files = (
        source,
        cf.resource("references/applicability-analysis.md"),
        cf.resource("references/language-syntax-guide.md"),
        cf.resource("references/workflow.md"),
    )
    keys: set[str] = set()
    report: list[dict[str, Any]] = []
    for target in languages:
        key, extension = target.key.lower(), target.extension.lower().lstrip(".")
        if not re.fullmatch(r"[a-z0-9_+-]+:[a-z0-9]+", f"{key}:{extension}") or key in keys:
            cf.fail("Use distinct literal parser keys and extensions, one language per entry.")
        keys.add(key)
        slug = f"{info.rule_id}-{key}"
        names = (f"{slug}.yaml", f"{slug}.{extension}", f"{slug}.probe.{extension}")
        work = cf.ensure_directory(f"scratch/{slug}", output_files=names, exclude_roots=(source,))
        rule, test, probe = (work / name for name in names)
        specification = json.dumps(
            {
                "language": target.language,
                "key": key,
                "extension": extension,
                "source": str(source),
                "source_info": info.model_dump(),
                "binary": binary,
                "version": version,
                "supported_languages": supported.stdout + supported.stderr,
                "rule": str(rule),
                "test": str(test),
                "probe": str(probe),
                "metadata": {"original-rule": info.rule_id, "ported-from": info.languages},
            }
        )
        trail: list[dict[str, Any]] = []
        decision = session(
            "Complete the assigned language cycle:\n" + specification, "[]", files, work
        )
        trail.append(decision.model_dump())
        if decision.verdict == "NOT_APPLICABLE":
            previous = decision
            decision = session(
                "Independently refute the NOT_APPLICABLE verdict using specific constructs. "
                "Confirm it or overturn it. If overturned, complete the ordered porting cycle.\n"
                + specification,
                json.dumps(trail),
                files,
                work,
            )
            trail.append(decision.model_dump())
            if decision.verdict != previous.verdict:
                cf.emit(
                    {"language": target.language, "change": decision.model_dump()},
                    name="verdict-change",
                )
        state = (
            "stopped"
            if None in (decision.verdict, decision.semgrepCanAnalyze)
            else "cannot_analyze"
            if not decision.semgrepCanAnalyze
            else "not_applicable"
            if decision.verdict == "NOT_APPLICABLE"
            else "failed_validation"
        )
        checked: dict[str, Any] = {}
        if state == "failed_validation":
            frozen = test.read_text(encoding="utf-8") if test.is_file() else ""
            for attempt in range(4):
                checked = audit(binary, version, info, key, rule, test, frozen)
                if checked["ok"]:
                    state = "passed"
                    break
                if attempt == 3:
                    break
                if attempt == 0:
                    cf.emit({"language": target.language, "failure": checked}, name="unfinished")
                repaired = session(
                    "Repair failed validation while preserving applicability and existing tests.\n"
                    + specification,
                    json.dumps({"history": trail, "audit": checked}),
                    files,
                    work,
                )
                if (repaired.verdict, repaired.semgrepCanAnalyze) != (
                    decision.verdict,
                    decision.semgrepCanAnalyze,
                ):
                    cf.fail("A repair changed applicability; independent reanalysis is required.")
                decision = repaired
                trail.append(decision.model_dump())
        written: list[str] = []
        if state == "passed":
            destination = cf.ensure_directory(slug, output_files=names[:2], exclude_roots=(source,))
            for path, name in zip((rule, test), names[:2], strict=True):
                written.append(
                    str(cf.write_text(destination / name, path.read_text(encoding="utf-8")))
                )
        report.append(
            decision.model_dump()
            | {
                "language": target.language,
                "status": state,
                "files": written,
                "validation": checked,
            }
        )
    states = ("passed", "failed_validation", "not_applicable", "cannot_analyze", "stopped")
    groups = {state: [r["language"] for r in report if r["status"] == state] for state in states}
    summary = "; ".join(f"{state}: {', '.join(items) or 'none'}" for state, items in groups.items())
    return cf.emit(
        {
            "summary": summary,
            "semgrep_version": version,
            "variants": report,
            "review": "Passing variants are candidates for review, not exploitability proofs.",
        },
        name="variants",
    )


if __name__ == "__main__":
    raise SystemExit(port_rule.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("a456a7897a8042b1e2be81e10a7ac78f85cedeb22358b3ef9166a4faa058d0de"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/applicability-analysis.md",
        "sha256": ("6908d64fe2e2d84a19ee838a2764b14473ab843d073af3d68961c22e2ecfc7ac"),
        "size": 10259,
        "source": None,
    },
    {
        "path": "references/language-syntax-guide.md",
        "sha256": ("ea5d36318718caf999e3f259878b821e2a2722d178751ac5e584a26e5a66a31d"),
        "size": 7509,
        "source": None,
    },
    {
        "path": "references/workflow.md",
        "sha256": ("dcf5cf90e3d4a31e6f83c0f07871d08777b64c17533f30307361577813b30071"),
        "size": 3970,
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
