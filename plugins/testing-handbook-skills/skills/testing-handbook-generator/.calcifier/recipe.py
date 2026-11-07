# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from pathlib import Path
from typing import Literal

from calcifier import (
    Budget,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    parallel,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
    write_json,
    write_text,
)

Kind = Literal["tool", "fuzzer", "technique", "domain"]
REQUIRED = {
    "tool": ("When to Use", "Quick Reference", "Installation", "Core Workflow"),
    "fuzzer": ("When to Use", "Quick Start", "Writing a Harness", "Related Skills"),
    "technique": ("When to Apply", "Quick Reference", "Tool-Specific Guidance", "Related Skills"),
    "domain": ("Background", "Quick Reference", "Testing Workflow", "Related Skills"),
}


@output_type
class Job:
    name: str
    kind: Kind
    section: str
    related_sections: list[str]
    fetch_ids: list[int]


@output_type
class Plan:
    jobs: list[Job]
    report: str


@output_type
class Final:
    descriptions: dict[str, str]
    groups: dict[str, Kind]
    edges: list[tuple[str, str, Literal["primary", "alternative"]]]
    report: str
    blockers: list[str]
    improvement_commit_message: str


def source_files(docs: Path, job: Job) -> tuple[Path, ...]:
    sections = [docs / value for value in [job.section, *job.related_sections]]
    for section in sections:
        if not section.resolve().is_relative_to(docs) or not section.is_dir():
            fail(f"Unavailable or escaping approved section: {section}")
        if not any(section.rglob("*.md")):
            fail(f"Approved section contains no Markdown: {section}")
    return tuple(sorted({p for section in sections for p in section.rglob("*.md")}))


def resource_urls(files: tuple[Path, ...]) -> list[str]:
    texts = [
        p.read_text(encoding="utf-8")
        for p in files
        if p.name in ("99-resources.md", "91-resources.md")
    ]
    return sorted(set(re.findall(r"https?://[^\s<>\"')\]]+", "\n".join(texts))))


def video(url: str) -> bool:
    return bool(
        re.search(
            r"youtube\.com|youtu\.be|vimeo\.com|twitch\.tv|dailymotion\.com|"
            r"\.(?:mp4|webm|mov)(?:[?#]|$)",
            url,
            re.I,
        )
    )


def inspect(directory: Path, kind: Kind) -> list[str]:
    files = sorted(directory.rglob("*.md"))
    if not files or not (directory / "SKILL.md").is_file():
        return [f"{directory.name}: no inspectable SKILL.md; empty checks cannot pass"]
    errors = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        if len(text.splitlines()) >= 500 or re.search(r"\{\{[<%]|\\`{3}", text):
            errors.append(f"{path}: line limit, shortcode, or escaped fence violation")
        fenced = False
        for line in text.splitlines():
            if line.startswith("```"):
                if not fenced and not line[3:].strip():
                    errors.append(f"{path}: opening code fence lacks a language")
                fenced = not fenced
        if fenced:
            errors.append(f"{path}: unclosed code fence")
    text = (directory / "SKILL.md").read_text(encoding="utf-8")
    for heading in {*REQUIRED[kind], "When to Use"}:
        if f"## {heading}" not in text.splitlines():
            errors.append(f"{directory.name}: missing heading {heading}")
    return errors


@step
def generate_one(job: Job, docs_path: str, skills_path: str, urls: list[str]) -> str:
    docs, destination = Path(docs_path), Path(skills_path) / job.name
    files = source_files(docs, job)
    fetched = []
    for index in job.fetch_ids:
        result = run_command(
            [
                "curl",
                "--max-time",
                "30",
                "--location",
                "--fail",
                "--silent",
                "--show-error",
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                urls[index],
            ],
            timeout_seconds=35,
            mutating=False,
        )
        fetched.append(
            {
                "url": urls[index],
                "exit_code": result.exit_code,
                "content": result.stdout,
                "warning": result.stderr,
            }
        )
    refs = (resource("agent-prompt.md"), resource(f"templates/{job.kind}-skill.md"))
    prior = json.dumps({"job": job.model_dump(), "fetches": fetched})
    for attempt in range(2):
        context = prepare_context(
            "Perform Pass 1 for the approved job. Apply the authoritative workflow, "
            "template, pre-generation validation, splitting rules, and report format. "
            "Complete source understanding remains your responsibility. The host fetched "
            "the approved URLs; failures must remain warnings with URLs and no summaries. "
            "Write only this skill directory. Leave the Pass 2 placeholder. Check YAML, "
            "description quality, exact code preservation, and every original checklist. "
            "Use embedded complete files directly; read backing files when absent. "
            "Return the complete Pass 1 report, including gaps and warnings.",
            prior_results=prior,
            files=(*files, *refs),
            readable_roots=(docs, *refs),
        )
        report = agent(
            "worker",
            context.prompt,
            context=context,
            working_directory=destination,
            readable_paths=(docs, *refs),
            writable_paths=(destination,),
            required_capabilities=("commands",),
            output=str,
            timeout=3600,
        )
        errors = inspect(destination, job.kind)
        if report.strip() and not errors:
            return report
        prior += json.dumps({"attempt": attempt + 1, "report": report, "errors": errors})
    fail(f"Individual Pass 1 failed after two attempts: {job.name}: {prior}")


def render_readme(text: str, jobs: list[Job], result: Final) -> str:
    base = "plugins/testing-handbook-skills/skills/"
    lines = [
        line
        for line in text.splitlines()
        if not any(f"]({base}{job.name}/)" in line for job in jobs)
    ]
    anchors = [
        i
        for i, line in enumerate(lines)
        if line.lstrip().startswith("|") and "[testing-handbook-skills](" in line
    ]
    if len(anchors) != 1:
        fail("README must contain exactly one testing-handbook-skills table row")
    rows = []
    for job in jobs:
        description = result.descriptions[job.name].replace("|", "&#124;").replace("\n", " ")
        rows.append(
            f"| [{job.name}]({base}{job.name}/) | {description} | testing-handbook-generator |"
        )
    lines[anchors[0] + 1 : anchors[0] + 1] = rows
    names = sorted(result.groups)
    ids = {name: f"n{index}" for index, name in enumerate(names)}
    graph = ["flowchart TD"]
    labels = {"tool": "Tools", "fuzzer": "Fuzzers", "technique": "Techniques", "domain": "Domain"}
    for kind, label in labels.items():
        graph.append(f"  subgraph {label}")
        graph.extend(
            f"    {ids[name]}[{json.dumps(name)}]" for name in names if result.groups[name] == kind
        )
        graph.append("  end")
    for source, target, relationship in result.edges:
        arrow = "-->" if relationship == "primary" else "-.->"
        graph.append(f"  {ids[source]} {arrow} {ids[target]}")
    pattern = r"(?ms)(^## Skills Cross-Reference[^\n]*\n.*?```mermaid[^\n]*\n).*?(\n```)"
    updated, count = re.subn(
        pattern, lambda m: m[1] + "\n".join(graph) + m[2], "\n".join(lines) + "\n"
    )
    if count != 1:
        fail("README must contain one Skills Cross-Reference Mermaid block to replace")
    return updated


@recipe(
    name="testing-handbook-generator",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=None, max_wall_seconds=3600),
    output_root="handbook-generation",
)
def generate(
    request: str,
    repository: str = ".",
    handbook_path: str = "",
    mode: Literal["plan", "generate"] = "plan",
    approved_plan_json: str = "",
    allow_clone: bool = False,
) -> str:
    project = Path(repository).resolve()
    skills = project / "plugins/testing-handbook-skills/skills"
    generator = skills / "testing-handbook-generator"
    readme = project / "README.md"
    if skills.resolve() != skills or not generator.is_dir() or readme.is_symlink():
        fail("Provide a repository with the expected plugin and a regular root README.md")
    output = ensure_directory("reports", output_files=("plan.json", "plan.md", "README.md"))
    candidates = (
        [Path(handbook_path).expanduser()]
        if handbook_path
        else [
            project / "testing-handbook",
            project.parent / "testing-handbook",
            Path.home() / "testing-handbook",
        ]
    )
    found = [p for p in candidates if (p / "content/docs").is_dir()]
    if not found and allow_clone:
        target = candidates[0]
        cloned = run_command(
            [
                "git",
                "clone",
                "--depth=1",
                "https://github.com/trailofbits/testing-handbook.git",
                str(target),
            ],
            timeout_seconds=300,
            working_directory=project,
        )
        if cloned.exit_code:
            fail(f"Clone failed; provide a manually cloned handbook: {cloned.stderr}")
        found = [target]
    if not found:
        fail("Provide handbook_path, or explicitly authorize cloning with allow_clone=True")
    docs = (found[0] / "content/docs").resolve()
    files = tuple(sorted(docs.rglob("*.md")))
    if not files:
        fail("Handbook inspection found zero Markdown files")
    urls = resource_urls(files)
    refs = tuple(resource(name) for name in ("agent-prompt.md", "discovery.md", "testing.md"))
    refs += tuple(resource(f"templates/{kind}-skill.md") for kind in REQUIRED)
    if mode == "plan":
        context = prepare_context(
            request,
            instructions="Perform discovery and planning only, including all original "
            "analysis, exclusions, conflicts, prioritization, and pre-generation checks. "
            "Interpret all supplied handbook files and references. Return the original plan "
            "format, including skips, updates, resource counts, warnings, and approval actions. "
            "Jobs use sections relative to content/docs and related_sections as a list. "
            "fetch_ids are zero-based indices into the supplied URL observations: select at "
            "most five non-video URLs per skill, prioritizing official sources. Matches are "
            "observations, not exhaustive semantic candidates; flag extraction gaps. "
            "Do not generate files. The saved plan requires explicit owner approval.",
            prior_results=json.dumps({"urls": urls}),
            files=(*files, *refs),
            readable_roots=(docs, *refs),
        )
        plan = agent(
            "worker",
            context.prompt,
            context=context,
            working_directory=skills,
            readable_paths=(docs, skills, readme, *refs),
            output=Plan,
            timeout=3600,
        )
        write_json(output / "plan.json", plan.model_dump())
        write_text(output / "plan.md", plan.report)
        emit(plan, name="approval-plan")
        return plan.report
    if not approved_plan_json:
        fail("Generation requires explicitly approved plan JSON; run plan mode first")
    jobs = [Job(**item) for item in json.loads(approved_plan_json)["jobs"]]
    if not jobs or len({job.name for job in jobs}) != len(jobs):
        fail("Approved generation scope must contain distinct, nonempty jobs")
    for job in jobs:
        if (
            not re.fullmatch(r"[a-z0-9-]{1,64}", job.name)
            or job.kind not in REQUIRED
            or job.name == "testing-handbook-generator"
            or any(word in job.name for word in ("anthropic", "claude"))
            or (skills / job.name).is_symlink()
        ):
            fail("Invalid or reserved approved skill destination")
        available = set(resource_urls(source_files(docs, job)))
        if len(job.fetch_ids) > 5 or len(set(job.fetch_ids)) != len(job.fetch_ids):
            fail("Each skill may fetch at most five distinct approved URLs")
        for index in job.fetch_ids:
            if not isinstance(index, int) or not 0 <= index < len(urls):
                fail("Approved URL index is outside the current handbook observations")
            if urls[index] not in available or video(urls[index]):
                fail("Approved fetch must reference a non-video resource for this skill")
    run_command(
        ["mkdir", "-p", *[str(skills / job.name) for job in jobs]],
        timeout_seconds=30,
        working_directory=skills,
    )
    reports = parallel(lambda job: generate_one(job, str(docs), str(skills), urls), jobs)
    emit(reports, name="pass-one")
    feedback = ""
    validator = generator / "scripts/validate-skills.py"
    for _attempt in range(2):
        selected = tuple(sorted(skills.rglob("*.md"))) + (readme, *refs)
        if validator.is_file():
            selected += (validator,)
        context = prepare_context(
            "Complete sequential Pass 2 for the approved jobs, then original testing and "
            "post-generation work. Read all sibling skills for relationships; preserve all "
            "original reasoning and checks. Fix only affected skills on retry. Perform actual "
            "activation tests; report unavailable execution routes as blockers, never passes. "
            "Review YAML, links and anchors, code preservation, resources, description anchors, "
            "and every qualitative requirement. If the validator is absent, perform the "
            "documented manual fallback. Capture self-improvement notes and appropriate fixes "
            "inside the generator, with a proposed commit message; do not commit. Return "
            "README row descriptions, all sibling skill groups excluding the generator, "
            "semantically classified edges, and the full generation report. Do not edit README.",
            prior_results=json.dumps(
                {"jobs": [j.model_dump() for j in jobs], "pass_one": reports, "feedback": feedback}
            ),
            files=selected,
            readable_roots=(skills, readme, *refs),
        )
        result = agent(
            "worker",
            context.prompt,
            context=context,
            working_directory=generator,
            readable_paths=(docs, skills, readme, *refs),
            writable_paths=tuple(skills / j.name for j in jobs) + (generator,),
            required_capabilities=("commands",),
            output=Final,
            timeout=3600,
        )
        errors = list(result.blockers)
        logs = []
        for job in jobs:
            errors.extend(inspect(skills / job.name, job.kind))
            if validator.is_file():
                checked = run_command(
                    ["uv", "run", str(validator), "--skill", job.name, "--json"],
                    timeout_seconds=300,
                    working_directory=generator,
                )
                logs.append(checked.stdout + checked.stderr)
                if checked.exit_code:
                    errors.append(f"Validator failed for {job.name}: {logs[-1]}")
        known = {p.parent.name for p in skills.glob("*/SKILL.md") if p.parent != generator}
        if not known or set(result.groups) != known:
            errors.append("Graph classification must cover the complete nonempty sibling scope")
        if any(s not in known or t not in known for s, t, _ in result.edges):
            errors.append("Graph contains nonexistent sibling skill references")
        if any(not result.descriptions.get(j.name, "").strip() for j in jobs):
            errors.append("Missing README descriptions for approved jobs")
        if not result.report.strip():
            errors.append("Missing final generation report")
        if not errors:
            updated = render_readme(readme.read_text(encoding="utf-8"), jobs, result)
            staged = write_text(output / "README.md", updated)
            copied = run_command(["cp", str(staged), str(readme)], timeout_seconds=30)
            if copied.exit_code:
                fail(f"README update failed: {copied.stderr}")
            emit(logs, name="validator-output")
            emit(result, name="generation-report")
            return result.report
        feedback = result.model_dump_json() + json.dumps({"errors": errors, "logs": logs})
    emit(feedback, name="unresolved-results")
    fail("Generation remains incomplete after targeted repair; see unresolved-results")


if __name__ == "__main__":
    raise SystemExit(generate.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("84d2022bff1675f77f71a219aa3999b01dc3fcfeff1666965177195ecf808aaa"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agent-prompt.md",
        "sha256": ("504b2f1ff37f118184085c35029b25d7934e85ec445982a9af12586f526e90e4"),
        "size": 11497,
        "source": None,
    },
    {
        "path": "discovery.md",
        "sha256": ("2bc2412af856e91ffacefb85a9f98811fe7238c99b485c03cf206969fee9dfa1"),
        "size": 15747,
        "source": None,
    },
    {
        "path": "templates/domain-skill.md",
        "sha256": ("da2c65ad7d1795f67846d6c5d844c77727b7da7c82ce82bbd387c2d288eb201f"),
        "size": 17036,
        "source": None,
    },
    {
        "path": "templates/fuzzer-skill.md",
        "sha256": ("d83c4f95b97376a5f146e943fbd981cfbb6a9b786c5342edd2c63c4ca2ea5f78"),
        "size": 11363,
        "source": None,
    },
    {
        "path": "templates/technique-skill.md",
        "sha256": ("565e05f3419c088c852595a918595b844cf2e4db91b9783c3047e431c0802121"),
        "size": 12641,
        "source": None,
    },
    {
        "path": "templates/tool-skill.md",
        "sha256": ("4d36ed99022e09df35a948b45d19251ea44089618eef2da24ca01998cff2ebc2"),
        "size": 9440,
        "source": None,
    },
    {
        "path": "testing.md",
        "sha256": ("3f7b53df6bb98679a7da30420d9e85b1f5fbb728faa425d1b176753870935c64"),
        "size": 16692,
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
        "ed inspection that finds zero issues.\n\nThe complete prio"
        "r candidate is supplied below as reference source. Preserv"
        "e\nits full behavior and make only the specific repository"
        " Ruff B007 correction:\nthe control variable attempt in fo"
        "r attempt in range(2) is unused; rename that\nloop variabl"
        "e to _attempt. Return the complete corrected module, respe"
        "cting\nE,F,I,UP,B,SIM with 100-character lines. The host a"
        "dds provenance; do not emit\n_CALCIFIER_* constants. All e"
        "xact resources are also supplied as compiler data.\n"
    ),
    "sha256": ("3078788877cf97f4fe5899a330fe134df5272fabd482ef507ed00542a29cc60b"),
}
_CALCIFIER_SUBRECIPES = []
