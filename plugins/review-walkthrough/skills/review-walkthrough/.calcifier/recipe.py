# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

# ///
# requires-python = ">=3.13"
# dependencies = ["calcifier"]
# ///
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

import calcifier as c


@c.output_type
class Finding:
    severity: Literal["high", "medium", "low"]
    title: str
    body: str
    file: str | None
    line: int | None
    side: Literal["LEFT", "RIGHT"] | None
    end_line: int | None


@c.output_type
class ReviewStep:
    message: str
    file_ids: list[int]
    explanation: str
    findings: list[Finding]


@c.output_type
class Review:
    title: str
    steps: list[ReviewStep]


def git(args: list[str], cwd: Path, accepted: tuple[int, ...] = (0,)) -> str:
    result = c.run_command(
        ["git", *args], working_directory=cwd, timeout_seconds=120, mutating=False
    )
    if result.exit_code not in accepted:
        c.fail(
            f"Git failed: {args!r}\n{result.stderr}\n"
            "If base selection failed, supply an existing, unambiguous base explicitly."
        )
    return result.stdout


def assemble(
    review: Review, paths: list[str], blocks: list[str], meta: dict[str, Any] | None
) -> dict[str, Any]:
    ids = [index for item in review.steps for index in item.file_ids]
    if sorted(ids) != list(range(len(blocks))) or any(not s.file_ids for s in review.steps):
        raise ValueError("Use every file ID exactly once, with no empty steps.")
    steps, explanations, reviews = [], [], []
    for number, item in enumerate(review.steps, 1):
        ordered = sorted(item.file_ids)
        steps.append(
            {
                "sha": f"step-{number}",
                "message": item.message,
                "files": [paths[index] for index in ordered],
                "diff": "".join(blocks[index] for index in ordered),
            }
        )
        explanations.append(item.explanation)
        findings = []
        for finding in item.findings:
            if finding.file is not None and (finding.line is None or finding.side is None):
                raise ValueError("Anchored findings require an explicit line and side.")
            findings.append(
                {key: value for key, value in finding.model_dump().items() if value is not None}
            )
        reviews.append(findings)
    return {
        "title": review.title,
        "steps": steps,
        "explanations": explanations,
        "reviews": reviews,
        "pr_meta": meta,
    }


@c.recipe(
    name="review-walkthrough",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(max_agent_calls=4, max_wall_seconds=3600),
    output_root="/tmp/calcifier-review-walkthrough",
)
def review_walkthrough(
    repository: str,
    base: str = "",
    github: Literal["auto", "skip", "no-pr"] = "auto",
    remote: str = "origin",
    allow_repository_output: bool = False,
) -> dict[str, Any]:
    repo = Path(repository).resolve()
    excluded = () if allow_repository_output else (repo,)
    planned = (
        "captured.patch",
        "head-sources.json",
        "data-1.json",
        "data-2.json",
        "walkthrough-1.html",
        "walkthrough-2.html",
        "renderer/scripts/render_walkthrough.py",
        "renderer/template.html",
    )
    out = c.ensure_directory(".", output_files=planned, exclude_roots=excluded)
    if Path(git(["rev-parse", "--show-toplevel"], repo).strip()).resolve() != repo:
        c.fail("repository must name the checkout root, not a subdirectory.")
    head = git(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"], repo).strip()
    notes: list[str] = []
    pr: dict[str, Any] | None = None
    no_pr = github == "no-pr"
    if github == "auto":
        try:
            lookup = c.run_command(
                [
                    "gh",
                    "pr",
                    "view",
                    "--json",
                    "state,baseRefName,baseRefOid,headRefOid,number,url",
                ],
                working_directory=repo,
                timeout_seconds=120,
                mutating=False,
            )
        except Exception as exc:
            if getattr(exc, "command_failure", None) not in ("launch", "timeout"):
                raise
            notes.append(f"GitHub lookup failed; PR existence is unknown: {exc}")
        else:
            if lookup.exit_code == 0:
                candidate = json.loads(lookup.stdout)
                if candidate.get("state") == "OPEN":
                    pr = candidate
                else:
                    no_pr = True
                    notes.append("The associated PR is not open; using no open PR.")
            elif (
                lookup.exit_code == 1
                and "no pull requests found for branch" in lookup.stderr.lower()
            ):
                no_pr = True
            else:
                notes.append(f"GitHub lookup failed; PR existence is unknown:\n{lookup.stderr}")
    selected = base
    if not selected:
        if pr is not None:
            selected = f"refs/remotes/{remote}/{pr['baseRefName']}"
        elif no_pr:
            selected = git(
                ["symbolic-ref", "--quiet", "--short", f"refs/remotes/{remote}/HEAD"],
                repo,
                (0, 1),
            ).strip()
        else:
            c.fail("Base unresolved. Supply base, or confirm no open PR with github='no-pr'.")
    if not selected:
        c.fail("Remote default branch is unavailable or ambiguous; supply base explicitly.")
    base_sha = git(
        ["rev-parse", "--verify", "--end-of-options", f"{selected}^{{commit}}"], repo
    ).strip()
    ancestors = git(["merge-base", "--all", base_sha, head], repo).splitlines()
    if len(ancestors) != 1:
        c.fail("No unique merge base; supply an unambiguous base.")
    merge_base = ancestors[0]
    flags = ["--no-ext-diff", "--no-textconv", "--no-color", "--src-prefix=a/", "--dst-prefix=b/"]
    patch = git(["diff", *flags, merge_base, head, "--"], repo)
    if not patch.strip():
        c.fail("The committed branch diff is empty; there are no changes to review.")
    status = git(["status", "--porcelain=v1", "--untracked-files=normal"], repo)
    if status:
        notes.append(f"Uncommitted work is excluded from this committed-HEAD review:\n{status}")
    meta = None
    if pr is not None and pr.get("headRefOid") == head and pr.get("baseRefOid") == base_sha:
        match = re.fullmatch(r"https://[^/]+/([^/]+)/([^/]+)/pull/\d+/?", pr.get("url", ""))
        if match:
            meta = {
                "owner": match[1],
                "repo": match[2],
                "pr_number": pr["number"],
                "head_sha": head,
            }
    if meta is None:
        notes.append("Comment export unavailable: no PR metadata matching captured head and base.")
    patch_path = c.write_text(out / "captured.patch", patch)
    blocks = re.split(r"(?=^diff --git )", patch, flags=re.MULTILINE)[1:]
    records = git(["apply", "--numstat", "-z", "--", str(patch_path)], out).split("\0")
    paths = [record.split("\t", 2)[2] for record in records[:-1]]
    if not blocks or records[-1] or len(paths) != len(blocks) or len(set(paths)) != len(paths):
        c.fail("Cannot identify one unique path per complete file diff; recapture the patch.")
    dirty = git(["diff", "--name-only", "-z", head, "--"], repo).split("\0")
    text_files = git(["grep", "-I", "-l", "-z", "-e", "", head, "--"], repo, (0, 1))
    text_paths = {item[len(head) + 1 :] for item in text_files.split("\0") if item}
    sources = {
        path: git(["show", f"{head}:{path}"], repo)
        for path in sorted(set(paths + dirty))
        if path in text_paths
    }
    sources_path = c.write_json(out / "head-sources.json", sources)
    c.ensure_directory(out / "renderer/scripts", output_files=("render_walkthrough.py",))
    pins = {
        "scripts/render_walkthrough.py": "4880c7b6da00867c1a813da727e4c6d8b10e0e3f49fa973126c02"
        "649f010cdb6",
        "template.html": "1f7e456ddc34ea8331c6e9879ad667919a279c180734bdbcc8815cc3deb41742",
    }
    for name, digest in pins.items():
        payload = c.resource(name).read_bytes()
        if sha256(payload).hexdigest() != digest:
            c.fail(f"Packaged resource integrity check failed: {name}")
        c.write_text(out / "renderer" / name, payload.decode("utf-8"))
    task = json.dumps(
        {
            "base_ref": selected,
            "base_sha": base_sha,
            "head_sha": head,
            "merge_base": merge_base,
            "notes": notes,
            "files": [{"id": index, "path": path} for index, path in enumerate(paths)],
        }
    )
    previous: dict[str, Any] | None = None
    error = ""
    for attempt in range(2):
        context = c.prepare_context(
            task,
            instructions=(
                "Carry out the authoritative source skill's complete reasoning, read-only review "
                "and self-checks in one connected session. Full captured.patch and committed text "
                "in head-sources.json override dirty files; read all needed checkout context. "
                "Return ordered logical steps using each zero-based file_id exactly once. Give "
                "substantive explanations, usually 50-150 words. HTML and findings must satisfy "
                "source requirements; anchor fields are explicit or all null. Full references "
                "are in renderer/. On retry retain the review and fix reported input errors. "
                "Ignore untracked work. Never edit source, run tests or install dependencies."
            ),
            prior_results=json.dumps({"previous_review": previous, "input_error": error}),
            files=(patch_path, sources_path),
            readable_roots=(repo, out),
        )
        review = c.agent(
            "worker",
            context.prompt,
            context=context,
            working_directory=repo,
            readable_paths=(repo, out),
            output=Review,
            timeout=3600,
        )
        previous = review.model_dump()
        try:
            data = assemble(review, paths, blocks, meta)
        except ValueError as exc:
            error = str(exc)
            continue
        data_path = c.write_json(out / f"data-{attempt + 1}.json", data)
        page = out / f"walkthrough-{attempt + 1}.html"
        rendered = c.run_command(
            [
                "uv",
                "run",
                "--no-project",
                "--offline",
                "--no-python-downloads",
                "--python",
                sys.executable,
                str(out / "renderer/scripts/render_walkthrough.py"),
                "--input",
                str(data_path),
                "--diff",
                str(patch_path),
                "--output",
                str(page),
            ],
            working_directory=out,
            timeout_seconds=120,
            mutating=True,
        )
        if rendered.exit_code != 0:
            error = rendered.stderr
            continue
        for artifact in (patch_path, sources_path, data_path, page):
            c.verify_artifact(artifact)
        return c.emit(
            {
                "html": str(page),
                "input": str(data_path),
                "patch": str(patch_path),
                "head_sources": str(sources_path),
                "head_sha": head,
                "base_sha": base_sha,
                "merge_base": merge_base,
                "notes": notes,
            },
            name="walkthrough",
        )
    c.fail(f"Walkthrough input remained invalid after two attempts:\n{error}")


if __name__ == "__main__":
    raise SystemExit(review_walkthrough.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("af098bc743979e8130ac5e98db908aec08a13ed5bda1c2288e4e5483c4a108c5"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "scripts/pyproject.toml",
        "sha256": ("e0ba55df7ebe80df6d928b14818744e58897f5977c450f6a54f98abd549d80df"),
        "size": 110,
        "source": None,
    },
    {
        "path": "scripts/render_walkthrough.py",
        "sha256": ("4880c7b6da00867c1a813da727e4c6d8b10e0e3f49fa973126c02649f010cdb6"),
        "size": 10195,
        "source": None,
    },
    {
        "path": "template.html",
        "sha256": ("1f7e456ddc34ea8331c6e9879ad667919a279c180734bdbcc8815cc3deb41742"),
        "size": 56037,
        "source": "template.html",
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
        " this guidance does not replace them.\n\nThe bundled rende"
        "rer and template are part of the required implementation. "
        "Pin scripts/render_walkthrough.py and template.html, prese"
        "rving their relative layout when running the original rend"
        "erer; it resolves the template relative to __file__. Do no"
        "t replace the renderer with a generic HTML emitter or omit"
        " its complete-diff/anchor validation.\nPreserve immutable "
        "base/head and merge-base selection with actual default-bra"
        "nch discovery, explicit disambiguation via inputs when unr"
        "esolved, complete nonempty git diff capture with the sourc"
        "e flags, and exclusion/disclosure of uncommitted work. Hos"
        "t git commands use argv arrays. Optional GitHub enrichment"
        " must match the captured head/base, and lookup failure is "
        "not evidence that no PR exists. The recipe is a review: no"
        " source edits, test execution, dependency installation or "
        "PR writes. Put generated artifacts outside the reviewed re"
        "pository unless the user explicitly chooses otherwise.\nKe"
        "ep every whole-file diff exactly once in logical steps, in"
        "cluding binary/rename/mode changes; preserve the required "
        "steps/explanations/reviews/pr_meta JSON structure and alig"
        "ned arrays. Preserve substantive explanations and all find"
        "ings with valid file/side/range anchors, then run the pinn"
        "ed renderer against the exact full patch. Verify the rende"
        "red HTML and input artifacts exist before reporting them. "
        "Browser opening is optional and must not change the review"
        " result. User choice of base or output path is an input, n"
        "ot an AskUserQuestion adapter.\n"
    ),
    "sha256": ("58fca8bc37aec7740bd9c35a7ca46b7fa804f71cfd6d771358194ddfe70ae012"),
}
_CALCIFIER_SUBRECIPES = []
