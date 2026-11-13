# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import hashlib
import json
import time
from pathlib import Path
from typing import Literal

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
    write_text,
)

REFERENCES = (
    "references/style-guide.md",
    "references/performance.md",
    "references/strings.md",
    "references/testing.md",
    "references/crx-module.md",
    "references/dex-module.md",
    "workflows/rule-development.md",
    "examples/MAL_Win_Remcos_Jan25.yar",
    "examples/MAL_Mac_ProtonRAT_Jan25.yar",
    "examples/MAL_NPM_SupplyChain_Jan25.yar",
    "examples/SUSP_JS_Obfuscation_Jan25.yar",
    "examples/SUSP_CRX_SuspiciousPermissions.yar",
)
PROGRAMS = (
    "scripts/yara_lint.py",
    "scripts/atom_analyzer.py",
    "scripts/review.sh",
    "scripts/yara_rules.py",
)


@output_type
class Observation:
    label: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    seconds: float


@output_type
class Work:
    report: str
    edits: dict[str, str]


@output_type
class Assessment:
    verdict: Literal["ready", "revise", "blocked"]
    report: str


def collect(value: str, cwd: Path, rules: bool = False) -> tuple[Path | None, list[Path]]:
    if not value:
        return None, []
    root = (cwd / value).resolve()
    if root.is_file():
        files = [root]
    elif root.is_dir():
        entries = sorted(root.rglob("*"))
        if any(p.is_symlink() for p in entries):
            fail(f"Materialize symbolic links before inspecting the complete scope: {root}")
        files = [
            p
            for p in entries
            if p.is_file() and (not rules or p.suffix.lower() in (".yar", ".yara"))
        ]
    else:
        fail(f"Input is not a regular file or directory: {root}")
    if not files:
        fail(f"Empty inspection scope: {root}; nothing was inspected.")
    return root, files


def observe(label: str, argv: list[str], cwd: str) -> Observation:
    started = time.perf_counter()
    result = run_command(argv, timeout_seconds=300, working_directory=cwd, mutating=False)
    return Observation(
        label,
        result.argv,
        result.exit_code,
        result.stdout,
        result.stderr,
        round(time.perf_counter() - started, 6),
    )


@step
def mechanical(target: str, cwd: str) -> list[Observation]:
    recursive = ["--recursive"] if Path(target).is_dir() else []
    results = [
        observe("yr_check", ["yr", "check", *recursive, "--", target], cwd),
        observe("yr_format", ["yr", "fmt", "--check", *recursive, "--", target], cwd),
        observe(
            "lint",
            [
                "uv",
                "run",
                "--quiet",
                str(resource("scripts/yara_lint.py")),
                "--json",
                "--",
                target,
            ],
            cwd,
        ),
        observe(
            "atoms",
            [
                "uv",
                "run",
                "--quiet",
                str(resource("scripts/atom_analyzer.py")),
                "--no-color",
                "--",
                target,
            ],
            cwd,
        ),
    ]
    if any(line.startswith("Error: ") for line in results[2].stderr.splitlines()):
        emit([o.model_dump() for o in results], name="failed-checks")
        fail("The linter could not inspect a nonempty rule scope: " + results[2].stderr)
    return results


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=4, max_wall_seconds=3600),
    output_root="yara-authoring-output",
)
def yara_rule_authoring(
    task: str,
    mode: Literal["review", "author", "optimize", "migrate"] = "review",
    rule_path: str = "",
    sample_path: str = "",
    goodware_path: str = "",
    file_kind: Literal["pe", "crx", "dex", "other"] = "other",
) -> Assessment:
    cwd = Path(".").resolve()
    target, files = collect(rule_path, cwd, True)
    samples, positive = collect(sample_path, cwd)
    goodware, negative = collect(goodware_path, cwd)
    if mode != "author" and target is None:
        fail("An existing rule file or directory is required; nothing was inspected.")
    count = max(1, len(files))
    names = tuple(f"{i:04d}.yar" for i in range(count))
    scratch_names = tuple(f"trial-{i:04d}.yar" for i in range(count)) + (
        "extracted.yar",
        "floss-strings.txt",
    )
    scopes = tuple(p for p in (target, samples, goodware) if p is not None)
    planned = (*(f"rules/{n}" for n in names), *(f"work/{n}" for n in scratch_names))
    ensure_directory(".", output_files=planned, exclude_roots=scopes)
    destination = ensure_directory("rules", output_files=names)
    scratch = ensure_directory("work", output_files=scratch_names)
    # Construct every read and write path before consuming agent-generated content.
    final_files = files if mode == "review" else [destination / name for name in names]
    scan_target = str(target) if mode == "review" else str(destination)
    baseline = mechanical(str(target), str(cwd)) if target is not None else []
    texts = [p.read_text(encoding="utf-8") for p in files] or [""]
    refs = tuple(resource(name) for name in REFERENCES)
    programs = tuple(resource(name) for name in PROGRAMS)
    views = (cwd, *scopes, *refs, *programs)
    preparation = [observe("yr_version", ["yr", "--version"], str(cwd))]
    hashes = {}
    modules = {"pe": ("math", "pe"), "crx": ("crx",), "dex": ("dex",), "other": ()}
    for sample in positive:
        hashes[str(sample)] = hashlib.sha256(sample.read_bytes()).hexdigest()
        preparation.append(observe(f"strings:{sample}", ["strings", str(sample)], str(cwd)))
        for module in modules[file_kind]:
            preparation.append(
                observe(
                    f"dump:{module}:{sample}",
                    ["yr", "dump", "-m", module, str(sample), "--output-format", "yaml"],
                    str(cwd),
                )
            )
    data = {
        "mode": mode,
        "file_kind": file_kind,
        "scope": str(target) if target else None,
        "source_indices": [{"index": i, "path": str(p)} for i, p in enumerate(files)],
        "author_index": 0 if not files else None,
        "positive_files": list(map(str, positive)),
        "goodware_files": list(map(str, negative)),
        "sample_sha256": hashes,
        "baseline": [o.model_dump() for o in baseline],
        "preparation": [o.model_dump() for o in preparation],
        "program_paths": list(map(str, programs)),
        "scratch_files": [str(scratch / n) for n in scratch_names],
    }
    context = prepare_context(
        task,
        prior_results=json.dumps(data),
        files=(*files, *refs),
        readable_roots=views,
        instructions=(
            "Follow the authoritative workflow in order in one session. Python prepared full "
            "inputs and pre-review diagnostics. Understand complete references/examples; search "
            "hits do not bound semantic coverage. Use embedded context or task.txt when absent. "
            "Only write listed scratch files for adaptive extraction, validation and repair. "
            "Return report and edits mapping index strings to full self-contained replacements; "
            "omit unchanged files. New authoring uses '0'; review has no edits. "
            "Quote emitted codes "
            "and identify missing evidence, unavailable provider configuration and remaining work."
        ),
    )
    work = agent(
        "worker",
        "Complete the assigned operation; return the requested report and edits.",
        context=context,
        working_directory=scratch,
        readable_paths=views,
        writable_paths=(scratch,),
        required_capabilities=("commands",),
        output=Work,
        timeout=3600,
    )
    if not work.report.strip() or (mode == "review" and work.edits):
        fail("Missing report or unexpected edits in a read-only review.")
    for index, text in work.edits.items():
        if index not in {str(i) for i in range(count)} or not text.strip():
            fail("Edits require valid source indices and nonempty complete replacement text.")
        texts[int(index)] = text
    if any(not text.strip() for text in texts):
        fail("Authoring returned no complete rule source.")
    final_checks = baseline
    if mode != "review":
        for i, name in enumerate(names):
            write_text(f"rules/{name}", texts[i])
        for path in final_files:
            verify_artifact(path)
        final_checks = mechanical(scan_target, str(cwd))
    scans = []
    if all(o.exit_code == 0 for o in final_checks):
        for label, corpus in (("positive", positive), ("goodware", negative)):
            for item in corpus:
                scans.append(
                    observe(
                        f"{label}:{item}",
                        ["yr", "scan", "-r", "-s", "--", scan_target, str(item)],
                        str(cwd),
                    )
                )
    review_data = dict(data, primary_report=work.report, scope=scan_target)
    review_data["final_checks"] = [o.model_dump() for o in final_checks]
    review_data["corpus_scans"] = [o.model_dump() for o in scans]
    peer_context = prepare_context(
        task,
        prior_results=json.dumps(review_data),
        files=(*final_files, *refs),
        readable_roots=(*views, destination, scratch),
        instructions=(
            "Perform required independent peer review of every final file, all observations and "
            "the primary report under the authoritative workflow and complete references. Quote "
            "actual codes. Only return ready with evidence for every deployment requirement: all "
            "target matches, zero appropriate goodware matches, variant/edge coverage, verified "
            "magic bytes and performance. Report missing evidence and remaining work; observations "
            "and exit codes do not prove semantic completion. Do not change files."
        ),
    )
    peer = agent(
        "worker",
        "Independently review the complete final scope.",
        context=peer_context,
        working_directory=destination,
        readable_paths=(*views, destination, scratch),
        required_capabilities=("commands",),
        output=Assessment,
        timeout=3600,
    )
    checks = final_checks + scans
    verified = bool(positive and negative) and all(o.exit_code == 0 for o in checks)
    verdict = peer.verdict if peer.verdict != "ready" or verified else "blocked"
    answer = Assessment(
        verdict,
        work.report + "\n\nIndependent peer review\n\n" + peer.report,
    )
    emit(dict(data, final_rule_files=list(map(str, final_files))), name="inputs")
    emit([o.model_dump() for o in checks], name="checks")
    emit(answer, name="review")
    if not peer.report.strip() or (mode != "review" and verdict != "ready"):
        fail("Required validation or peer review is incomplete; inspect the emitted report.")
    return answer


if __name__ == "__main__":
    raise SystemExit(yara_rule_authoring.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("ab54de171d618927b39c351e0e297496bf3306a86b63a84a53441f67b261455c"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "examples/MAL_Mac_ProtonRAT_Jan25.yar",
        "sha256": ("3c44693a5f48e3aaf93856f80d13a21c517aec59c8e860923271b7e986cf87ae"),
        "size": 3314,
        "source": None,
    },
    {
        "path": "examples/MAL_NPM_SupplyChain_Jan25.yar",
        "sha256": ("e3d96e3bb2154e337f9621fcd101ffaa1041f6541d2c2dc8fb925daa53940481"),
        "size": 5478,
        "source": None,
    },
    {
        "path": "examples/MAL_Win_Remcos_Jan25.yar",
        "sha256": ("83fc5365924fd816f6f7b7951f64414c88792a555f33b9de9d12b0c3e4849cca"),
        "size": 3210,
        "source": None,
    },
    {
        "path": "examples/SUSP_CRX_SuspiciousPermissions.yar",
        "sha256": ("3dc69d6cc2614b19ad87fe1ad540d26c9ad02d2092641668579b189855c2f953"),
        "size": 4323,
        "source": None,
    },
    {
        "path": "examples/SUSP_JS_Obfuscation_Jan25.yar",
        "sha256": ("126e69eb062a71fd932299b6e0f9dce71835f3e0ae932980a87dc12618c0fc60"),
        "size": 5829,
        "source": None,
    },
    {
        "path": "references/crx-module.md",
        "sha256": ("ed75d8d5942f3d4ac23b172f52af59ff85ddaec167c5df16dfdd6aad653ee8ad"),
        "size": 7500,
        "source": None,
    },
    {
        "path": "references/dex-module.md",
        "sha256": ("1fa7fb3f3d66155fd5f07f0a8f2c4d53d67c6cbd9202ad16a15e89965c9c3568"),
        "size": 10384,
        "source": None,
    },
    {
        "path": "references/performance.md",
        "sha256": ("1a2af39a39c354d7f5db6664f74bb0d938f2a054c61de1821643b94c47388f7e"),
        "size": 8898,
        "source": None,
    },
    {
        "path": "references/strings.md",
        "sha256": ("1a631faa2c8902182cd061818632e670b9a64c3182ea778b6f2870b7393fc5d5"),
        "size": 11868,
        "source": None,
    },
    {
        "path": "references/style-guide.md",
        "sha256": ("8bbd5f52d7a66c44c78a7e941f6c8d9ebc2b3605abcdbc394b9080764f542811"),
        "size": 9484,
        "source": None,
    },
    {
        "path": "references/testing.md",
        "sha256": ("00355d8dd53c6c55ab9ee0ab462bdfd2f5ae441121883775fcb3bdbaef8f97e5"),
        "size": 13376,
        "source": None,
    },
    {
        "path": "scripts/atom_analyzer.py",
        "sha256": ("4623b742f618ae5df9b47f79454b9506296784a6d49c39f403c30ae68ac1923c"),
        "size": 4719,
        "source": None,
    },
    {
        "path": "scripts/pyproject.toml",
        "sha256": ("086b6b265a2eed185c30b7e068b67b4cb1afc8f49f2d5770e21093bdb44b2245"),
        "size": 553,
        "source": None,
    },
    {
        "path": "scripts/review.sh",
        "sha256": ("172b842ce50c28b5c0f80953c22819bae5e667a82ac69df6273fc6771769b2c6"),
        "size": 2967,
        "source": None,
    },
    {
        "path": "scripts/test_yara_rules.py",
        "sha256": ("05ba6635b7eae8ce415faf829fd9143091565e4d0458ef46acdf84994deb9191"),
        "size": 18111,
        "source": None,
    },
    {
        "path": "scripts/uv.lock",
        "sha256": ("fe35066f4a2c13acecd4524c230bf7306ad201859091f43fbe7a32deae88453c"),
        "size": 3527,
        "source": None,
    },
    {
        "path": "scripts/yara_lint.py",
        "sha256": ("aab811af7d690ed4a39117a2520b414a4958752fc82b7719dd951ac5a40586c3"),
        "size": 4849,
        "source": None,
    },
    {
        "path": "scripts/yara_rules.py",
        "sha256": ("59eca803ddecc9f12ce4f7bdeef40af8568e566604c93319df8630279f84f38c"),
        "size": 31124,
        "source": None,
    },
    {
        "path": "workflows/rule-development.md",
        "sha256": ("2b562b3389cd4b33c0990322eb051dd7efda16202a6d7228fd6ec5afcc8a36b1"),
        "size": 13553,
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
