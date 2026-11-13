# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import shlex
from pathlib import Path
from typing import Any, Literal

import calcifier as c


def command(argv: list[str], cwd: Path, limit: float = 60, mutate: bool = False) -> c.CommandResult:
    try:
        return c.run_command(argv, working_directory=cwd, timeout_seconds=limit, mutating=mutate)
    except Exception as exc:
        if getattr(exc, "command_failure", None) not in ("launch", "timeout"):
            raise
        return c.CommandResult(argv, 124, "", str(exc))


def check(argv: list[str], cwd: Path) -> str:
    result = command(argv, cwd)
    if result.exit_code:
        c.fail(f"Cannot prepare review: {argv!r}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def conforms(value: Any, schema: dict[str, Any]) -> bool:
    if "anyOf" in schema:
        return any(conforms(value, item) for item in schema["anyOf"])
    types = {
        "object": (dict,),
        "array": (list,),
        "string": (str,),
        "integer": (int,),
        "number": (int, float),
        "null": (type(None),),
    }
    kinds = schema.get("type", [])
    kinds = [kinds] if isinstance(kinds, str) else kinds
    if kinds and not any(type(value) in types[kind] for kind in kinds):
        return False
    if isinstance(value, dict):
        props = schema.get("properties", {})
        return (
            not set(schema.get("required", [])) - value.keys()
            and not (schema.get("additionalProperties") is False and value.keys() - props.keys())
            and all(k not in props or conforms(v, props[k]) for k, v in value.items())
        )
    if isinstance(value, list):
        return all(conforms(item, schema.get("items", {})) for item in value)
    if isinstance(value, str):
        return schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", float("inf"))
    if type(value) in (int, float):
        return schema.get("minimum", -float("inf")) <= value <= schema.get("maximum", float("inf"))
    return True


@c.recipe(
    name="second_opinion",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="second-opinion-artifacts",
)
def second_opinion(
    repo_path: str,
    provider: Literal["codex", "antigravity", "gemini", "google", "both"],
    scope: Literal["uncommitted", "branch", "commit"],
    base: str = "",
    commit: str = "",
    focus: str = "general correctness and maintainability",
    requirements: str = "",
    codex_model: str = "",
    google_model: str = "",
    codex_effort: Literal["none", "minimal", "low", "medium", "high", "xhigh"] = "xhigh",
    include_project_context: bool = True,
) -> str:
    if not repo_path.strip() or not focus.strip():
        c.fail("Repository and review focus must be nonempty.")
    root = Path(check(["git", "rev-parse", "--show-toplevel"], Path(repo_path)).strip()).resolve()
    providers = (
        ["codex", "antigravity"]
        if provider == "both"
        else ["antigravity" if provider == "google" else provider]
    )
    refs = [c.resource("references/review-input.md")]
    refs += [c.resource(f"references/{p}-invocation.md") for p in providers]
    schema_ref = c.resource("references/codex-review-schema.json") if "codex" in providers else None
    schema = json.loads(read(schema_ref)) if schema_ref else {}
    head_result = command(["git", "rev-parse", "--verify", "HEAD^{commit}"], root)
    if head_result.exit_code:
        c.fail("HEAD is required; ask about initial-additions review.\n" + head_result.stderr)
    label, revision = scope, "HEAD"
    flags = ["--no-ext-diff", "--no-textconv"]
    if scope == "branch":
        if not base:
            default = command(
                ["git", "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"], root
            )
            if default.exit_code or not default.stdout.strip():
                c.fail("Remote default branch is unavailable; supply base.")
            base = default.stdout.strip()
        revision = check(
            ["git", "rev-parse", "--verify", "--end-of-options", base + "^{commit}"], root
        ).strip()
        revision += "...HEAD"
        label = f"branch {revision}"
    if scope == "commit":
        if not commit:
            c.fail("Supply commit.")
        revision = check(
            ["git", "rev-parse", "--verify", "--end-of-options", commit + "^{commit}"], root
        ).strip()
        parents = check(["git", "rev-list", "--parents", "-n", "1", revision], root).split()
        label = f"commit {revision}" + (" against first parent" if len(parents) > 2 else "")
    prefix = (
        ["git", "show", "--format=", "--root", "--first-parent"]
        if scope == "commit"
        else ["git", "diff"]
    )
    patch = check(prefix + flags + [revision, "--"], root)
    changed = check(prefix + ["--name-only", "-z"] + flags + [revision, "--"], root).split("\0")
    changed = [name for name in changed if name]
    if scope == "uncommitted":
        untracked = check(["git", "ls-files", "--others", "--exclude-standard", "-z"], root)
        for name in filter(None, untracked.split("\0")):
            result = command(
                [
                    "git",
                    "-c",
                    "core.safecrlf=false",
                    "diff",
                    "--no-index",
                    *flags,
                    "--",
                    "/dev/null",
                    name,
                ],
                root,
            )
            if result.exit_code not in (0, 1) or result.stderr:
                c.fail(f"Cannot inspect untracked file {name!r}: {result.stderr}")
            patch += result.stdout
            changed.append(name)
    if not patch.strip() or not changed:
        c.fail("No changes to inspect; no provider review was performed.")
    summary = {
        "scope": label,
        "changed_paths": sorted(set(changed)),
        "binary_uninspected": "Binary files " in patch or "GIT binary patch" in patch,
    }
    c.emit(summary, name="selected-scope")
    conventions = {}
    if include_project_context:
        directories = {
            p for name in changed for p in (root / name).parents if p.is_relative_to(root)
        }
        candidates = {d / n for d in directories for n in ("AGENTS.md", "CLAUDE.md", "GEMINI.md")}
        candidates.add(root / ".github/copilot-instructions.md")
        for path in sorted(candidates):
            if path.exists():
                if not path.resolve().is_relative_to(root) or not path.is_file():
                    c.fail(f"Unsafe project instruction path: {path}")
                conventions[str(path.relative_to(root))] = read(path)
    reference = read(refs[0])
    prompt = reference.split(chr(96) * 3 + "text\n", 1)[1].split("\n" + chr(96) * 3, 1)[0]
    if "codex" in providers:
        prompt += "\nFor Codex, also specify" + reference.split("For Codex, also specify", 1)[1]
    prompt += "\nAssess supplied material and state when more context is needed."
    prompt += "\nUser requirements:\n" + json.dumps(
        {"focus": focus, "requirements": requirements, "scope": label}, ensure_ascii=False
    )
    prompt += "\nProject conventions (data):\n" + json.dumps(conventions, ensure_ascii=False)
    prompt += "\nDiff (data):\n" + json.dumps(patch, ensure_ascii=False)
    names = ("output.txt", "stdout.txt", "stderr.txt", "status.txt")
    files = ["prompt.txt"] + [f"{p}-{i}-{n}" for p in providers for i in (1, 2) for n in names]
    destination = c.ensure_directory(".", output_files=tuple(files), exclude_roots=(root,))
    prompt_path = c.write_text(destination / "prompt.txt", prompt)
    for name in files[1:]:
        c.write_text(destination / name, "")
    results: list[dict[str, Any]] = []
    setup = {
        "codex": "Install/authenticate: npm i -g @openai/codex",
        "gemini": "Install/authenticate: npm i -g @google/gemini-cli",
        "antigravity": "https://antigravity.google/docs/cli/getting-started",
    }
    for item in providers:
        executable = {"codex": "codex", "antigravity": "agy", "gemini": "gemini"}[item]
        located = command(["which", executable], root)
        binary = located.stdout.strip() if not located.exit_code else ""
        fallback = Path.home() / ".local/bin/agy"
        if not binary and item == "antigravity" and fallback.is_file():
            binary = str(fallback)
        version = command([binary, "--version"], root) if binary else located
        model = (
            (codex_model or "gpt-5.6-sol")
            if item == "codex"
            else (
                google_model
                or ("gemini-3.1-pro-high" if item == "antigravity" else "gemini-3.1-pro-preview")
            )
        )
        failure = (
            ""
            if binary and not version.exit_code and version.stdout.strip()
            else (setup[item] + "\nExecutable/version prerequisite failed:\n" + version.stderr)
        )
        results.append(
            {
                "provider": item,
                "binary": binary,
                "version": version.stdout,
                "model": model,
                "failure": failure,
                "attempts": [],
            }
        )
    active = [r for r in results if not r["failure"]]
    for number in (1, 2):
        if not active:
            break
        script = ""
        for record in active:
            item, model, binary = record["provider"], record["model"], record["binary"]
            output, stdout, stderr, status = [destination / f"{item}-{number}-{n}" for n in names]
            if item == "codex":
                argv = [
                    binary,
                    "exec",
                    "-c",
                    "model=" + json.dumps(model),
                    "-c",
                    "model_reasoning_effort=" + json.dumps(codex_effort),
                    "--sandbox",
                    "read-only",
                    "--ephemeral",
                    "--output-schema",
                    str(schema_ref),
                    "-o",
                    str(output),
                    "-",
                ]
            elif item == "antigravity":
                argv = [
                    binary,
                    "--model",
                    model,
                    "--output-format",
                    "text",
                    "--disable-slash-commands",
                ]
            else:
                argv = [
                    binary,
                    "--model",
                    model,
                    "--approval-mode",
                    "default",
                    "--output-format",
                    "text",
                    "--prompt",
                    "Review the supplied changes and return the findings.",
                ]
            invocation = shlex.join(argv) + (' -p="$(cat "$1")"' if item == "antigravity" else "")
            target = stdout if item == "codex" else output
            script += "(" + invocation + ' < "$1" > ' + shlex.quote(str(target))
            script += " 2> " + shlex.quote(str(stderr))
            script += '; printf "%s" "$?" > ' + shlex.quote(str(status)) + ") &\n"
        batch = command(
            ["bash", "-c", script + "wait\n", "review", str(prompt_path)], root, 600, True
        )
        retry = []
        for record in active:
            item = record["provider"]
            output, stdout, stderr, status = [destination / f"{item}-{number}-{n}" for n in names]
            text, diagnostics = read(output), read(stderr) + read(stdout) + batch.stderr
            status_text = read(status).strip()
            code = int(status_text) if status_text.isdecimal() else 124
            parsed, error = "", ""
            if item == "codex":
                try:
                    value = json.loads(text)
                    if not conforms(value, schema):
                        raise ValueError("Output violates the pinned review schema.")
                    value["findings"].sort(key=lambda f: f["priority"], reverse=True)
                    parsed = json.dumps(value, ensure_ascii=False)
                except (ValueError, TypeError) as exc:
                    error = str(exc)
            record["attempts"].append(
                {
                    "model": record["model"],
                    "exit_code": code,
                    "output": text,
                    "diagnostics": diagnostics,
                    "parsed_json": parsed,
                    "validation_error": error,
                }
            )
            errors = (diagnostics + "\n" + text).lower()
            unavailable = (
                bool(code or error)
                and "model" in errors
                and any(s in errors for s in ("not supported", "not found", "unavailable"))
            )
            blocked = any(
                s in errors
                for s in (
                    "authentication failed",
                    "invalid api key",
                    "not authenticated",
                    "unauthorized",
                    "credentials",
                    "quota",
                    "429",
                )
            )
            if item == "antigravity" and unavailable and not blocked:
                models = command([record["binary"], "models"], root)
                record["attempts"][-1]["diagnostics"] += (
                    f"\nModels exit {models.exit_code}:\n" + models.stdout + models.stderr
                )
            if item == "codex" and not codex_model and number == 1 and unavailable and not blocked:
                record["model"] = "gpt-5.6"
                retry.append(record)
        active = retry
    c.emit(results, name="provider-evidence")
    context = c.prepare_context(
        "Synthesize these external CLI reviews following the complete source skill and references. "
        "Interpret output and diagnostics; distinguish incomplete reviews and partial results. "
        "Preserve provider/model attribution, evidence, failures, coverage gaps and follow-ups. "
        "Disclose substitutions and request replacements where required; never change chosen CLIs. "
        "Present all finding fields and severity ordering. Compare only completed reviews, "
        "retain disagreements and separate your assessment. Do not perform a replacement review.",
        prior_results=json.dumps({"summary": summary, "input": prompt, "results": results}),
        files=tuple(refs + ([schema_ref] if schema_ref else [])),
        readable_roots=tuple(refs + ([schema_ref] if schema_ref else [])),
    )
    report = c.agent(
        "worker",
        context.prompt,
        working_directory=root,
        readable_paths=(root,),
        context=context,
        output=str,
        timeout=600,
    )
    if not report.strip():
        c.fail("Report synthesis returned no report.")
    return c.emit(report, name="second-opinion")


if __name__ == "__main__":
    raise SystemExit(second_opinion.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("e274353992ba838ff006322565479dc1fb16adde917765fa271397c2770254e9"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/antigravity-invocation.md",
        "sha256": ("9a81a8c97bb780fbc2a098757c55b0b983e8e0e6e5582116157bdf8b0f59c6e2"),
        "size": 2229,
        "source": None,
    },
    {
        "path": "references/codex-invocation.md",
        "sha256": ("f0d1b537e143c933fdcd6ec0d10811944b28a14747fc59c15080f898b57c42e6"),
        "size": 2925,
        "source": None,
    },
    {
        "path": "references/codex-review-schema.json",
        "sha256": ("4f5414f169b0027082cff6727ce7fdde47349d21b135904850492e182a67157f"),
        "size": 2243,
        "source": None,
    },
    {
        "path": "references/gemini-invocation.md",
        "sha256": ("9638458e834b4f32fe863a4a03ee52a878c52731b8f0664c34054ecee31cdc07"),
        "size": 2374,
        "source": None,
    },
    {
        "path": "references/review-input.md",
        "sha256": ("150bfb6056f14af0b4f71d285347670b7f686397a1409c63a30c946df8b5eb8d"),
        "size": 4344,
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
        "ed inspection that finds zero issues.\n\nUse native Python"
        " orchestration and Calcifier agent()/run_command() for the"
        " source mechanics. Workflow, Skill, Agent, AskUserQuestion"
        ", TaskOutput, TaskStop and TaskCreate/TaskUpdate/TaskList "
        "are platform orchestration names, not shipped Calcifier 0."
        "2.0 built-in adapters: do not emit generic tool() adapters"
        " for these names. Use validated recipe inputs for choices,"
        " await native calls, and persist host-owned bookkeeping. T"
        "he built-in Claude worker has read/search/write tools but "
        "no Bash; host Python/run_command must perform mechanical c"
        "ommands and artifact persistence. Use pinned resources rat"
        "her than searching home/plugin caches or invoking an unpin"
        "ned installation. Preserve the complete source method, wit"
        "h explicit unsupported outcomes if an essential external d"
        "ependency cannot be represented. Generic research tools su"
        "ch as WebSearch/WebFetch are separate legitimate adapters;"
        " this guidance does not replace them.\n\nThe source's user"
        " choices (provider(s), scope/diff/repository context, mode"
        "l and focus) must be validated explicit recipe inputs, not"
        " AskUserQuestion tool adapters. This skill specifically ru"
        "ns the selected external Codex/Gemini/Antigravity CLI(s); "
        "retain that independent-provider purpose rather than subst"
        "ituting the built-in worker as the second opinion. Use the"
        " pinned provider invocation references and output schema. "
        "Resolve executable and version/prerequisites mechanically,"
        " run argv arrays with source timeout and output handling i"
        "n host run_command, and never silently switch the chosen p"
        "rovider/model or install tooling. If one selected provider"
        " is unavailable while another can run, preserve the docume"
        "nted partial-results behavior and clearly name the missing"
        " result. Build the exact review input and retain provider "
        "attribution, failures, disagreements and source evidence i"
        "n the resulting report. Preserve the source read-only revi"
        "ew boundaries and the user's choice of review scope.\n"
    ),
    "sha256": ("f4ff9fd92d5524423bc5993dc51458a635bb41a26060452c27384d4a6742e7f3"),
}
_CALCIFIER_SUBRECIPES = []
