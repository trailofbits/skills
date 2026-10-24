# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import hashlib
import json
import re
import shlex
import time
from pathlib import Path
from typing import Any, Literal

import calcifier as c


@c.output_type
class Options:
    allowed_production_paths_json: str
    allowed_test_paths_json: str
    suite_argv_json: str
    regression_argv_json: str
    build_argv_json: str = "[]"
    generated_paths_json: str = "[]"


@c.output_type
class Job:
    paths: dict[str, str]
    data: dict[str, Any]
    logs: list[str]


@c.output_type
class Edit:
    contents: list[str]
    variants: list[tuple[str, Literal["fixed", "not_fixed"], str]]
    review: str


@c.output_type
class Result:
    outcome: Literal["patched", "failed", "inconclusive"]
    record: dict[str, Any]
    paths: dict[str, str]
    reason: str


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def strings(text: str, empty: bool = False) -> list[str]:
    v = json.loads(text)
    need(isinstance(v, list) and (empty or bool(v)), "Expected a nonempty JSON array")
    need(all(isinstance(x, str) and x.strip() and "\0" not in x for x in v), "Invalid strings")
    return v


def safe(root: Path, name: str) -> Path:
    p = Path(name)
    need(bool(p.parts) and not p.is_absolute() and p.as_posix() == name, "Relative path required")
    need(not any(x.lower() in {".git", ".."} for x in p.parts), "Forbidden path component")
    need(not set(name) & set("\\:\t\r\n"), "Forbidden path characters")
    need(not any(x.is_symlink() for x in [root / p, *(root / p).parents]), "Linked path")
    need((root / p).resolve().is_relative_to(root), "Escaped path")
    return root / p


@c.step
def run(s: Job, argv: list[str], cwd: str, mutating: bool) -> dict[str, Any]:
    log = Path(s.paths["aux"]) / f"receipts/{len(s.logs):04d}.json"
    c.ensure_directory(log.parent, output_files=(log.name,))
    s.logs.append(str(log))
    started = time.monotonic()
    d: dict[str, Any] = {"argv": argv, "cwd": cwd, "exit_code": None, "stdout": "", "stderr": ""}
    try:
        got = c.run_command(argv, working_directory=cwd, timeout_seconds=900, mutating=mutating)
        d.update(exit_code=got.exit_code, stdout=got.stdout, stderr=got.stderr)
    except c.RecipeError as exc:
        if getattr(exc, "command_failure", None) not in {"launch", "timeout"}:
            raise
        d["error"] = f"{exc}; command API supplied no complete output capture"
    d["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    c.write_json(log, d)
    return d


def git(s: Job, args: list[str], owned: bool = False, mutating: bool = False) -> str:
    argv = ["git", "--no-optional-locks", "--literal-pathspecs", *args]
    got = run(s, argv, s.paths["wt" if owned else "repo"], mutating)
    need(got["exit_code"] == 0, f"Git failed; see {s.logs[-1]}")
    return got["stdout"]


def check(s: Job, args: list[str]) -> None:
    argv = ["uv", "run", "--no-project", "python", "-B", str(c.resource("scripts/records.py"))]
    got = run(s, [*argv, *args], s.paths["rd"], args[0] == "manifest")
    need(got["exit_code"] == 0, f"Record check: {got['stderr']}; see {s.logs[-1]}")


def setup(repo: str, rd: str, n: int, identity: str, options: Options) -> Job:
    root, out = Path(repo).absolute(), Path(rd).absolute()
    if not all(p.is_dir() and p.resolve() == p and ".git" not in p.parts for p in (root, out)):
        c.fail("Require existing unlinked target_repo/run_dir roots outside .git")
    need(not out.is_relative_to(root) and not root.is_relative_to(out), "Overlapping roots")
    need(bool(identity.strip()) and len(identity) <= 100, "patcher_agent_id: 1..100 characters")
    keys = ("prod", "tests", "suite", "reg", "build", "gen")
    values = [strings(v, i >= 4) for i, v in enumerate(options.model_dump().values())]
    d: dict[str, Any] = dict(zip(keys, values, strict=True))
    edit = [*d["tests"], *d["prod"]]
    need(len(set(edit)) == len(edit), "Repeated or overlapping edit paths")
    need(all(not safe(root, v).is_dir() for v in [*edit, *d["gen"]]), "File paths required")
    need(len(shlex.join(d["suite"])) <= 400, "Suite command exceeds record schema limit")
    p = {
        "repo": str(root),
        "rd": str(out),
        "aux": f"repair/attempt-{n}",
        "stage": f"patch/attempt-{n}",
    }
    need(all(not safe(out, p[k]).exists() for k in ("aux", "stage")), "Attempt already exists")
    need(c.ensure_directory(".", exclude_roots=(root,)) == out, "Set --output-dir RUN_DIR")
    c.ensure_directory(
        p["aux"], output_files=(*(f"content-{i}" for i in range(len(edit))), "plan.json")
    )
    p.update({k: str(out / p[k]) for k in ("aux", "stage")})
    p["wt"] = str(Path(p["aux"]) / "wt")
    return Job(p, dict(d, attempt=n, agent=identity, edit=edit, r={}, diffs=["", ""]), [])


@c.step
def bind(s: Job) -> None:
    d, rd = s.data, Path(s.paths["rd"])
    names = ("run.json", "finding.json", "reproduce/reproduce.json", "validate/validate.json")
    need(all(safe(rd, n).is_file() for n in names), "Required stage records missing")
    need(
        all(safe(rd, n + "/manifest.json").is_file() for n in ("reproduce", "validate")),
        "Required manifests missing",
    )
    state, finding, rep, val = [json.loads((rd / n).read_text(encoding="utf-8")) for n in names]
    need(bool(finding.get("repair_scope", {}).get("cases")), "Empty repair/inspection scope")
    check(s, ["check", "--before-repair", str(rd)])
    need(state["attempts"] == d["attempt"], "Reserve this attempt in run.json first")
    need(
        all((rd / f"patch/attempt-{n}/patch.json").is_file() for n in range(1, d["attempt"])),
        "Prior attempt missing",
    )
    need(rep["outcome"] == "reproduced" and val["outcome"] == "confirmed", "Unconfirmed claim")
    need(rep["agent"] != val["agent"] and d["agent"] != val["agent"], "Reused agent identity")
    base = rep["baseline_commit"]
    need(git(s, ["rev-parse", "--verify", base + "^{commit}"]).strip() == base, "Baseline SHA")
    need(git(s, ["rev-parse", "--show-toplevel"]).strip() == s.paths["repo"], "Use repo root")
    d.update(base=base, finding=finding, original=git(s, ["status", "--porcelain=v1", "-z"]))
    entries = git(s, ["ls-tree", "-rz", "--full-tree", base]).split("\0")
    d["tree"] = {v.split("\t", 1)[1]: v.split("\t", 1)[0] for v in entries if v}
    need(bool(d["tree"]), "Zero inspected baseline files")


def guidance(s: Job) -> None:
    d, rd = s.data, Path(s.paths["rd"])
    roots = ("AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md")
    need(all(d["tree"][n].startswith("100") for n in roots if n in d["tree"]), "Guidance mode")
    texts = {n: git(s, ["show", d["base"] + ":" + n]) for n in roots if n in d["tree"]}
    absent, saved = set(roots) - set(texts), safe(rd, "guidance/" + d["base"])
    if saved.exists():
        source = safe(saved, "source.md").read_text(encoding="utf-8")
        need(set(re.findall("[0-9a-f]{40}", source)) == {d["base"]}, "Guidance source SHA")
        need({n for n in roots if n in source} == absent, "Guidance absence list")
        need(
            all(
                safe(saved, n).read_bytes() == texts[n].encode()
                if n in texts
                else not safe(saved, n).exists()
                for n in roots
            ),
            "Saved guidance mismatch",
        )
    d.update(guidance=texts, absent=sorted(absent))
    conflict = c.agent(
        "worker",
        "Interpret full guidance for approved paths/argv; return "
        "mandatory conflicts or ''. Threat model preserves intended behavior; "
        "it is not an entry gate. " + json.dumps(d),
        working_directory=rd,
        readable_paths=(c.resource("references/records.md"),),
        output=str,
    )
    need(not conflict.strip(), conflict)
    protected = [p for p in rd.rglob("*") if p.is_file() and not p.is_relative_to(rd / "repair")]
    d["hashes"] = {
        str(safe(rd, str(p.relative_to(rd)))): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in protected
    }


def checkout(s: Job) -> None:
    d, wt = s.data, Path(s.paths["wt"])
    c.ensure_directory(wt, output_files=tuple(sorted({*d["tree"], *d["edit"], *d["gen"]})))
    git(s, ["worktree", "add", "--detach", str(wt), d["base"]], mutating=True)
    need((wt / ".git").is_file() and not (wt / ".git").is_symlink(), "Unverified worktree")
    need(git(s, ["rev-parse", "HEAD"], True).strip() == d["base"], "Unpinned checkout")
    need(not git(s, ["status", "--porcelain", "--untracked-files=no"], True), "Dirty checkout")
    need(all(not safe(wt, n).is_dir() for n in d["edit"]), "Unsafe destination")
    d["entered"] = True


def test(s: Job, argv: list[str], label: str) -> dict[str, Any]:
    if s.data["build"]:
        need(run(s, s.data["build"], s.paths["wt"], True)["exit_code"] == 0, "Build failed")
    got = run(s, argv, s.paths["wt"], True)
    lines = [v[18:] for v in got["stdout"].splitlines() if v.startswith("PATCH_TEST_REPORT ")]
    need(len(lines) == 1, f"Require one actual PATCH_TEST_REPORT; see {s.logs[-1]}")
    r = json.loads(lines[0])
    need(set(r) == {"passed", "failed", "skipped", "errors"}, "Report keys")
    need(r["errors"] == [] and isinstance(r["failed"], dict), "Setup error or invalid failures")
    need(all(isinstance(r[k], list) for k in ("passed", "skipped")), "Invalid ID lists")
    ids = [*r["passed"], *r["failed"], *r["skipped"]]
    need(all(isinstance(v, str) and v for v in ids) and len(ids) == len(set(ids)), "Test IDs")
    need(bool(r["passed"] or r["failed"]), "Zero exercised tests or all skipped")
    need(
        all(
            isinstance(v, dict)
            and set(v) == {"kind", "detail"}
            and v["kind"] == "assertion"
            and isinstance(v["detail"], str)
            and v["detail"]
            for v in r["failed"].values()
        ),
        "Failure must be an exercised assertion",
    )
    need(got["exit_code"] == (1 if r["failed"] else 0), "Report/exit mismatch")
    s.data["r"][label] = r
    return r


def propose(s: Job) -> Edit:
    d, p = s.data, s.paths
    need(not git(s, ["diff", "--name-only", d["base"]], True), "Baseline source changed")
    e = c.agent(
        "worker",
        "Follow the complete source workflow read-only. Search the entire "
        "declared boundary for invariant violations. Read all allowed files; return "
        "replacement CONTENT in edit order, every variant/reason, and search coverage. "
        "Outside allowlist: not_fixed. Tests cover the bug, fixed variants and cases. "
        + json.dumps(d),
        working_directory=p["wt"],
        output=Edit,
        timeout=3600,
        readable_paths=(
            p["wt"],
            Path(p["rd"]) / "reproduce",
            Path(p["rd"]) / "validate",
            Path(p["aux"]) / "receipts",
            c.resource("references/records.md"),
        ),
    )
    need(len(e.contents) == len(d["edit"]) and bool(e.review.strip()), "Proposal coverage")
    need(
        bool(e.variants) and all(0 < len(a) <= 400 and 0 < len(r) <= 200 for a, _, r in e.variants),
        "Invalid variant record",
    )
    c.write_json(Path(p["aux"]) / "plan.json", e.model_dump())
    return e


def apply(s: Job, e: Edit, production: bool) -> None:
    d, wt = s.data, Path(s.paths["wt"])
    indices = range(len(d["tests"]), len(d["edit"])) if production else range(len(d["tests"]))
    for i in indices:
        name = d["edit"][i]
        mode = d["tree"].get(name, "100644 blob absent").split()[0]
        need(mode in {"100644", "100755"}, "Only regular source files may be edited")
        safe(wt, name)
        content = c.write_text(Path(s.paths["aux"]) / f"content-{i}", e.contents[i])
        blob = git(s, ["hash-object", "-w", "--no-filters", str(content)], True, True).strip()
        need(re.fullmatch("[0-9a-f]{40}", blob) is not None, "Unverified blob")
        git(s, ["update-index", "--add", "--cacheinfo", mode, blob, name], True, True)
        git(s, ["checkout-index", "--force", "--", name], True, True)


@c.step
def repair(s: Job, e: Edit) -> None:
    d, cases = s.data, s.data["finding"]["repair_scope"]["cases"]
    apply(s, e, False)
    before = test(s, d["reg"], "regression_before")
    need(
        {v["check_id"] for v in cases if v["role"] == "representative"} <= set(before["failed"])
        and {v["check_id"] for v in cases if v["role"] == "control"} <= set(before["passed"]),
        "Require failing baseline representatives and passing controls",
    )
    apply(s, e, True)
    after = test(s, d["reg"], "regression_after")
    need(
        not after["failed"] and {v["check_id"] for v in cases} <= set(after["passed"]),
        "Patched regression coverage failed",
    )
    after, before = test(s, d["suite"], "after"), d["r"]["before"]
    need(all(before["failed"].get(k) == v for k, v in after["failed"].items()), "New suite failure")
    need(
        set(before["passed"]) <= set(after["passed"])
        and set(before["failed"]) <= set(after["passed"]) | set(after["failed"]),
        "Coverage drift",
    )


def commit(s: Job, e: Edit) -> None:
    d, wt = s.data, Path(s.paths["wt"])
    need(
        all(
            safe(wt, d["edit"][i]).read_text(encoding="utf-8") == e.contents[i]
            for i in range(len(d["edit"]))
        ),
        "Tests changed proposed edits",
    )
    need(
        all(
            Path(p).is_file()
            and not Path(p).is_symlink()
            and hashlib.sha256(Path(p).read_bytes()).hexdigest() == h
            for p, h in d["hashes"].items()
        ),
        "Original evidence changed",
    )
    check(s, ["check", s.paths["rd"]])
    changed = set(git(s, ["diff", "--name-only", "-z", d["base"]], True).strip("\0").split("\0"))
    need(
        changed <= set(d["edit"]) and all(changed & set(d[k]) for k in ("prod", "tests")),
        "Escaped scope or missing production/test changes",
    )
    need(not git(s, ["diff", "--name-only"], True), "Unstaged tracked edits")
    git(s, ["add", "--", *[n for n in d["edit"] if n in changed]], True, True)
    git(
        s,
        [
            "-c",
            "core.hooksPath=" + str(Path(s.paths["aux"]) / "disabled-hooks"),
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "Fix validated invariant",
        ],
        True,
        True,
    )
    identity = git(s, ["rev-list", "--parents", "-n", "1", "HEAD"], True).split()
    need(len(identity) == 2 and identity[1] == d["base"], "Require one baseline-child commit")
    d["commit"], rev = identity[0], [d["base"], identity[0]]
    need(
        set(git(s, ["diff", "--name-only", "-z", *rev], True).strip("\0").split("\0"))
        <= set(d["edit"]),
        "Commit scope escaped",
    )
    d["diffs"] = [
        git(s, ["diff", "--binary", "--no-ext-diff", *rev, "--", *d[k]], True)
        for k in ("prod", "tests")
    ]
    need(all(d["diffs"]), "Empty production/test diff")
    stats = [v.split("\t", 2) for v in git(s, ["diff", "--numstat", *rev], True).splitlines()]
    need(bool(stats) and all(a.isdigit() and b.isdigit() for a, b, _ in stats), "Invalid numstat")
    d["stats"] = [len(stats), *[sum(int(v[i]) for v in stats) for i in range(2)]]
    need(git(s, ["status", "--porcelain=v1", "-z"]) == d["original"], "Input checkout changed")


@c.step
def finish(s: Job, e: Edit | None, reason: str) -> Result:
    d, p = s.data, s.paths
    files = [Path(v) for v in s.logs]
    files = [*files, Path(p["aux"]) / "plan.json"] if e else files
    if not d.get("entered") or not all(v.is_file() for v in files):
        return c.emit(Result("inconclusive", {}, p, reason or "Dry run: unverified"), name="patch")
    r = dict(
        zip(
            ("files_changed", "lines_added", "lines_removed"),
            d.get("stats", [0, 0, 0]),
            strict=True,
        )
    )
    r.update(
        schema_version=1,
        attempt=d["attempt"],
        baseline_commit=d["base"],
        patch_commit=d.get("commit"),
        agent=d["agent"],
        variants=[
            {"location": a, "status": b if d.get("commit") else "not_fixed", "reason": v}
            for a, b, v in e.variants
        ]
        if e
        else [],
    )
    for side in ("before", "after"):
        r["suite_" + side] = dict(
            command=shlex.join(d["suite"]),
            **{k: len(d["r"].get(side, {}).get(k, [])) for k in ("passed", "failed", "skipped")},
        )
    names = ("patch.json", "fix.patch", "tests.patch", "manifest.json", "receipts/gate.json")
    stage = c.ensure_directory(
        p["stage"], output_files=(*names, *("receipts/" + v.name for v in files))
    )
    for v in files:
        c.write_text(stage / "receipts" / v.name, v.read_text(encoding="utf-8"))
    c.write_json(
        stage / "receipts/gate.json",
        {
            "reason": reason,
            "reports": d["r"],
            "absent": d.get("absent", []),
            "preexisting": d["r"].get("after", {}).get("failed", {}),
            "unverified": [k for k in ("before", "after") if k not in d["r"]],
        },
    )
    c.write_json(stage / "patch.json", r)
    for name, content in zip(("fix.patch", "tests.patch"), d["diffs"], strict=True):
        c.write_text(stage / name, content)
    try:
        check(s, ["manifest", str(stage)])
        need(all((stage / v).is_file() for v in names), "Stage unverified")
        check(s, ["check", p["rd"]])
    except (ValueError, OSError) as exc:
        reason = f"{reason}; {exc}"
    paths = dict(
        p,
        **{
            k: str(stage / v)
            for k, v in (
                ("record", "patch.json"),
                ("manifest", "manifest.json"),
                ("fix", "fix.patch"),
                ("tests", "tests.patch"),
            )
        },
    )
    return c.emit(Result("failed" if reason else "patched", r, paths, reason), name="patch")


@c.recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(max_agent_calls=4, max_wall_seconds=3600),
    output_root=".",
)
def implement_patch(
    target_repo: str,
    run_dir: str,
    attempt: Literal[1, 2, 3],
    patcher_agent_id: str,
    options: Options,
) -> Result:
    s = setup(target_repo, run_dir, attempt, patcher_agent_id, options)
    e, reason = None, ""
    try:
        bind(s)
        guidance(s)
        checkout(s)
        test(s, s.data["suite"], "before")
        e = propose(s)
        repair(s, e)
        commit(s, e)
    except (ValueError, KeyError, OSError) as exc:
        reason = str(exc)
    return finish(s, e, reason)


if __name__ == "__main__":
    raise SystemExit(implement_patch.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("64d164de3e3981774facafb3187ecc648809a9ce53acb718b0789e9600458fa2"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/records.md",
        "sha256": ("565ad030d31b129b247136daa768fb3780d2dfba67a229b98bf90badfef3a371"),
        "size": 13082,
        "source": "../../references/records.md",
    },
    {
        "path": "schemas/finding.schema.json",
        "sha256": ("ee148944eb7533c775c4c90db2f36a16b1eab108d4e0f0edc9ed14e5e9b69001"),
        "size": 3041,
        "source": "../../schemas/finding.schema.json",
    },
    {
        "path": "schemas/patch.schema.json",
        "sha256": ("0f4baa71309441f4f89d3934dbf5456aa08b4a4f5159d4f70ecb3a5d058dc480"),
        "size": 2763,
        "source": "../../schemas/patch.schema.json",
    },
    {
        "path": "schemas/prove.schema.json",
        "sha256": ("597b39488d5b7a2a9212513dad55c0d26734fc455937367f686b189fe69e73cf"),
        "size": 7313,
        "source": "../../schemas/prove.schema.json",
    },
    {
        "path": "schemas/regression.schema.json",
        "sha256": ("3a596a98708b745e82fb188d63e7f19fc81adb2e6d1f7c7703a913e50651511a"),
        "size": 1205,
        "source": "../../schemas/regression.schema.json",
    },
    {
        "path": "schemas/report-input.schema.json",
        "sha256": ("28b033eda23a17d8828f16c2e7c1ea82b24fc0805afd32848f988d3727a4333d"),
        "size": 2083,
        "source": "../../schemas/report-input.schema.json",
    },
    {
        "path": "schemas/reproduce.schema.json",
        "sha256": ("7f3078d2eff8a9956e7290cece0dc6f81468b99dd67612e73327d92c5d195ff3"),
        "size": 1287,
        "source": "../../schemas/reproduce.schema.json",
    },
    {
        "path": "schemas/run.schema.json",
        "sha256": ("bc38b411eb0978f6c3d70505e0e39732231881fbd25d72dfada15bd5aa641a7f"),
        "size": 1908,
        "source": "../../schemas/run.schema.json",
    },
    {
        "path": "schemas/validate.schema.json",
        "sha256": ("37a76360356fcf50e34e19e637df6d68f4c60908d8b57474372dfe4aad197c64"),
        "size": 510,
        "source": "../../schemas/validate.schema.json",
    },
    {
        "path": "scripts/arms.py",
        "sha256": ("6bc6335eec2558e84f555b81f92511c4baaefb897fed8d1c04130c3e6c8e9d79"),
        "size": 9499,
        "source": "../../scripts/arms.py",
    },
    {
        "path": "scripts/native_proof.py",
        "sha256": ("ba9aa3005bc69b8f289ae76215d52533845940020ebcbbe9c171cc1c9ff4f5b2"),
        "size": 11956,
        "source": "../../scripts/native_proof.py",
    },
    {
        "path": "scripts/records.py",
        "sha256": ("2d76977e89cad6ad57b6fc907fc9b13a32f50af632369b170df249bdadcd27af"),
        "size": 13380,
        "source": "../../scripts/records.py",
    },
    {
        "path": "scripts/render.py",
        "sha256": ("238743119345c939a59736cd1de6e39585a0a12632a4d34965efa7d55bf1bdb4"),
        "size": 10714,
        "source": "../../scripts/render.py",
    },
    {
        "path": "scripts/repair_scope.py",
        "sha256": ("5b643f3c5d7fd957394bf3646a799cbba3de306d7230ed06592ae85be05a107c"),
        "size": 2181,
        "source": "../../scripts/repair_scope.py",
    },
    {
        "path": "scripts/report_sections.py",
        "sha256": ("258e927a4ada0161cd84359815f88f3be044be452b8dcff50baeb93d3c062ca9"),
        "size": 29473,
        "source": "../../scripts/report_sections.py",
    },
    {
        "path": "scripts/report_views.py",
        "sha256": ("72e04ecfbf04686d0abff174c6b753bc6367db8ca42c0cffbdf6e05175e1b694"),
        "size": 10021,
        "source": "../../scripts/report_views.py",
    },
    {
        "path": "scripts/terminal.py",
        "sha256": ("6924c66ee88402420a74a23a5c4288fff3b5535232a136320871683f0c22b01d"),
        "size": 8153,
        "source": "../../scripts/terminal.py",
    },
    {
        "path": "scripts/verdict.py",
        "sha256": ("3d6710bb178d511f93cf960ef875a761cebf4edf67f57f11f2a6e2c52733792e"),
        "size": 4077,
        "source": "../../scripts/verdict.py",
    },
]
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, plus C4, C90, PLR0913 and RUF in both target plu"
        "gin pyproject.toml files, target-version py313, max-comple"
        "xity 8, and line-length 100. Every function must have cycl"
        "omatic complexity at most8 and at most5 arguments; decompo"
        "se the native workflow into small module-level helpers or "
        "steps (Ruff counts nested function complexity inside the o"
        "uter function), and group related inputs in typed records "
        "or caller-supplied structured plans. Do not suppress lint "
        "or use noqa or change repository configuration. The recipe"
        " must satisfy those checks, including B007, B905, and SIM1"
        "02. Keep the Python 3.13 minimum required by Calcifier in "
        "its generated PEP 723 header. Invoke pinned Python helpers"
        " with uv run --no-project python -B SCRIPT so sibling impo"
        "rts cannot create untracked bytecode outside the assigned "
        "work area, including for read-only helper calls. This skil"
        "l is distributed independently: do not require another unm"
        "erged skill recipe. Referenced prose and explicitly provid"
        "ed resources may be packaged, while the generated recipe b"
        "elongs only to the requested skill. Repository contributio"
        "n rule: a checker that inspects zero items must fail with "
        "an explanation rather than return a successful clean repor"
        "t. This applies to an empty inspection scope, not to a com"
        "pleted inspection that finds zero issues.\n\nThis is a sou"
        "rce-heavy execution skill, not an advisory one-model-call "
        "wrapper. Implement actual evidence-bound orchestration in "
        "typed Python @steps; use the read-only worker only for bou"
        "nded semantic review or source proposals. Staged scripts/s"
        "chemas/references contain the real contracts. Read their s"
        "upplied inline contents and call packaged helpers through "
        'resource("scripts/..."). Do not invent helper CLIs or use '
        "platform Task/workflow/Claude adapters. Do not require ano"
        "ther unpublished recipe. Do not emit an always-blocked sub"
        "stitute for supported work.\n\nAll host side-effect select"
        "ors must originate in validated caller inputs, fixed recip"
        "e names, verified Git objects, or packaged resources; neve"
        "r feed a worker-returned path/argv/commit/selector into ru"
        "n_command or a file write. Worker output may be prose, jud"
        "gments, or replacement content associated positionally wit"
        "h host-selected fixed paths. Use only the literal semantic"
        " role worker and filesystem contracts with no writable_pat"
        "hs. Precompute caller-approved argv arrays, source files, "
        "and paths before agent calls. Never let a worker choose ex"
        "ecutable commands. Caller-supplied build/PoC/suite/case ar"
        "gv JSON parameters are appropriate; validate nonempty stri"
        "ng arrays and execute without a shell. A missing required "
        "user command should give an actionable argument error, not"
        " silently mark every run blocked.\n\nUse Git object reads "
        "to bind the real baseline SHA. Before any build/test/PoC, "
        "read every present root AGENTS.md, PATCHING_GUIDELINES.md,"
        " THREAT_MODEL.md from that SHA (Git show), record absent n"
        "ames, and compare any existing guidance/<SHA> copies/sourc"
        "e.md absences to those Git objects. Stop on mismatch. Run "
        "directory must be outside target tracked tree; reject syml"
        "ink/escape/.git paths, require the expected input records "
        "and a nonempty declared case/inspection scope before calli"
        "ng permissive record check. Never mistake records.py check"
        " succeeding on an empty directory for a completed workflow"
        ". Preserve every earlier stage/attempt and do not overwrit"
        "e a completed stage.\n\nAll builds, tests, PoCs, worktree "
        "operations, manifests, Git staging/commits, and helper inv"
        "ocations that create files MUST use mutating=True. Git obj"
        "ect/status/diff reads and genuine native record/proof asse"
        "ssment can be mutating=False. Run_command nonzero exits ar"
        "e CommandResult.exit_code; process launch/timeouts raise R"
        "ecipeError with command_failure=launch/timeout. Retain std"
        "out, stderr, exit_code, elapsed time and exact argv/cwd fo"
        "r successes AND failures; failures cannot become fabricate"
        "d successful receipts. Catch only expected launch/timeout "
        "failures and return honest blocked/inconclusive evidence; "
        "propagate budget exhaustion and unrelated exceptions. Pres"
        "erve raw output bytes/text separately from summaries. Use "
        "explicit output_root, ensure_directory destination preflig"
        "ht, write_text/write_json, and controlled local worktrees."
        " Dry-run absence of simulated files may yield an honest un"
        "verified dry run; do not weaken real execution or fake pro"
        "of to satisfy the stub.\n\nUse bundled record schemas exac"
        "tly, not model approximations. records.py has CLI `manifes"
        "t <step-dir>` and `check [--before-repair] <run-dir>`; no "
        "subcommand to validate one arbitrary record. Helper check "
        "skips absent records, so require your mandatory inputs/out"
        "puts explicitly. Later stages must verify original PoC/man"
        "ifests before and after use. Only reproducer may update fi"
        "nding.status, validator must not edit finding or PoC, prov"
        "er must not edit the patch. Stage agent identity is an exp"
        "licit nonempty recipe argument and must differ from source"
        " identities where independence requires it; use a fresh is"
        "olated model call without prior transcripts. Do not claim "
        "independent validation merely from an alias. Provide a use"
        "ful typed return with actual stage record/manifest/receipt"
        " paths and outcome, not just a Markdown narrative.\n\nExac"
        "tly one @recipe, literal declared agent role worker, Pytho"
        "n>=3.13 PEP723, generous bounded Budget for real builds an"
        "d multiple worker calls; typed data returned from steps. D"
        "o not embed full supplied resource texts as generated cons"
        "tants. Host record assessment may use a fixed literal Pyth"
        "on -c bridge to packaged records/native_proof modules (wit"
        "h trusted resource directory on sys.path), because native_"
        "proof.py has no CLI. No arbitrary runpy/importlib of model"
        " source. Fixed host bridge and user command parameters rem"
        "ain separate from model output.\n\n\nImplement actual inva"
        "riant-level repair in an owned local checkout, not a propo"
        "sal-only wrapper. Expose caller parameters target_repo, ru"
        "n_dir, attempt (1..3), patcher_agent_id, allowed_productio"
        "n_paths_json, allowed_test_paths_json, suite_argv_json, re"
        "gression_argv_json, and any caller-approved build command "
        "necessary for tests. Allowed production/test paths are non"
        "empty, disjoint, caller-owned repo-relative allowlists und"
        "er the repair boundary; .git, absolute, dotdot, linked or "
        "out-of-root paths are rejected. Never let the model select"
        " write destinations, subprocess argv, commit message flags"
        ", or scope expansion. Model outputs replacement CONTENT on"
        "ly for an exactly ordered host-selected list of files (no "
        "output paths), variants with reasons, and bounded analysis"
        "; host checks cardinality and routes content to already se"
        "lected safe paths.\n\nRequire independently confirmed vali"
        "dation and reproduced PoC, distinct patcher/validator iden"
        "tities, manifest integrity, repair_scope with nonempty cas"
        "e plan and bounded_class>=2 distinct representatives+contr"
        "ol, and a consistent run.attempts. Before any editing exec"
        "ute actual records.py check --before-repair run_dir and st"
        "op with its retained errors if it fails. Read pinned root "
        "guidance at reproduction.baseline_commit; create clean rec"
        "ipe-owned detached repair worktree at that baseline, verif"
        "y commit and no tracked changes. Preserve input target che"
        "ckout. Worker receives the repair_scope boundary/exclusion"
        "s, all allowed source files and relevant surrounding evide"
        "nce in read-only mode, and must search the declared invari"
        "ant boundary for every variant (including not_fixed with r"
        "eason); persist search/variant coverage, not just the repo"
        "rted line. Only caller may expand allowed paths; out-of-al"
        "lowlist discoveries are not_fixed with reason, never silen"
        "tly patched.\n\nHost runs real existing suite on clean bas"
        "eline first. Ask read-only worker for proposed regression-"
        "test CONTENT and production replacement CONTENT; apply onl"
        "y tests first to the fixed caller-approved test paths, run"
        " the supplied regression command on baseline and observe a"
        " meaningful failing assertion, not setup error. Do not con"
        "tinue if test never ran, all skipped, or failed only from "
        "missing tools/invalid syntax. Then apply host-guarded prod"
        "uction edits, run regression and full suite after. Derive "
        "suite counts from actual machine-readable report or suppor"
        "ted concrete stdout parser; expose caller report contract "
        "if necessary. Never ask worker to fabricate passed/failed/"
        "skipped counts. Require passed+failed>0, preserve before/a"
        "fter raw receipt comparison, classify pre-existing failure"
        "s from retained baseline evidence, do not silently accept "
        "new failures. Return failed attempt with patch_commit:null"
        " and reason receipts when repair/test gates cannot establi"
        "sh success rather than claim patch complete.\n\nFor an act"
        "ual completed attempt, use host-known static git commands "
        "to stage only explicit allowed changed files and create EX"
        "ACTLY ONE local commit (no push/PR). Verify HEAD's sole pa"
        "rent equals original baseline and all changed names stay w"
        "ithin allowlist. Commit message is fixed host text, never "
        "model text. Derive changed-file/line counts from real git "
        "diff --numstat; do not use worker counts. Create fix.patch"
        " from changed production allowlist and tests.patch from te"
        "st allowlist using baseline..patch_commit; both nonempty f"
        "or successful attempt. Native record patch.json schema_ver"
        "sion1: attempt/baseline_commit/patch_commit/files_changed/"
        "lines_added/lines_removed/variants/suite_before/suite_afte"
        "r/agent. Preserve all variant discoveries as fixed or not_"
        "fixed with <=200char reason. Write patch/attempt-N once, k"
        "eep prior attempts, manifest final record and both patch f"
        "iles plus suite/regression/search receipts, run record val"
        "idator, return actual commit/record/diff paths and failure"
        "s. Do not claim proved patch or create prove record.\n\n\n"
        "Focused source review of the substantive initial candidate"
        " found a deterministic real-execution blocker: ensure_dire"
        'ctory(... output_files=... | {".git"}) always rejects the '
        ".git planned artifact path in published Calcifier 0.2 muta"
        "tions._output_path. Do not plan or write .git through arti"
        "fact APIs. Preflight ordinary checkout files plus known bu"
        "ild outputs; the declared mutating git worktree operation "
        "itself owns its internal Git metadata, and the recipe may "
        "verify that .git file afterward without treating it as an "
        "artifact output. Preserve the real detached owned-worktree"
        " implementation and host hash-object/update-index/checkout"
        "-index edits; do not replace it with a blocked fallback.\n"
        "\nUse calcifier.fail/RecipeError for actionable preflight "
        "guard failures where appropriate, so an impossible stub pa"
        "th yields honest unverified dry-run status instead of chan"
        "ging/removing the real safety guard. Invoke all bundled Py"
        "thon scripts and fixed native import bridges with bytecode"
        " disabled (e.g. uv run --no-project python -B SCRIPT, and "
        "sys.executable -B -c for bridges); native record checks mu"
        "st not create __pycache__ in packaged resources.\n\nRespec"
        "t the plugin-local Ruff config: E,F,I,UP,B,SIM,C4,C90,PLR0"
        "913,RUF, max-complexity 8, at most five function arguments"
        ", target py313. Decompose into module-level helpers/steps "
        "with typed trusted context separated from model records. N"
        "ested helper complexity counts toward its enclosing recipe"
        ". No noqa, ignored rules, config changes, or generic check"
        " bypasses. Preserve actual PATCH_TEST_REPORT execution cou"
        "nts and regression-before-fix gating while decomposing.\n"
        "\n\nFocused repair of latest retained complete candidate: "
        "its two model-derived diagnostics in generic run() are a c"
        "onservative taint propagation issue, not permission to wea"
        'ken enforcement. In commit(), zip(d["edit"], e.contents) t'
        "aints BOTH iteration variables, so the otherwise host-owne"
        "d n is passed to safe(wt,n), tainting the shared safe() re"
        "sult and native paths/context across callers. Instead iter"
        "ate ONLY native indices/host paths, then read e.contents[i"
        "ndex] separately; never pass a model-zipped host binding i"
        "nto any path helper. Similarly keep every shared Job/nativ"
        "e selector context free of model-derived mutations or mixe"
        "d comprehensions; worker proposals remain a separate Edit "
        "object. Preserve the host-fixed allowlist, native Git hash"
        "-object/update-index/checkout-index effects, before-regres"
        "sion/control evidence, full before/after suites, variants,"
        " one actual native commit and all raw receipts. The previo"
        "us internal repair returned a malformed RecipeDraft (unind"
        "ent mismatch line29), so return the COMPLETE valid module "
        "source, using the retained complete source as the behavior"
        "al reference. Follow strict Ruff maxcomplexity8/maxargs5, "
        "no suppression/config changes, list-unpacking for RUF005 a"
        "nd Python-B helpers. Existing honest unverified dry-run gu"
        "ard is accepted.\n\nFOCUSED FINAL REPAIR: Preserve the ent"
        "ire retained source and its runtime behavior. Local Ruff r"
        "eports exactly four C408 dict(...) keyword-constructor cal"
        "ls at the command receipt, setup paths, variant record, an"
        "d gate JSON. Replace only these four with equivalent dicti"
        "onary literals, preserving key/value order, conditionals a"
        "nd comprehension. Do not refactor other functions, change "
        "contracts, imports, resource pins, error handling or workf"
        "low. No lint suppressions. Return full native source.\n"
    ),
    "sha256": ("168ab2d1bbab55b125d800fef0c96e40e523811864db1b0d4a5f667a2560533f"),
}
_CALCIFIER_SUBRECIPES = []
