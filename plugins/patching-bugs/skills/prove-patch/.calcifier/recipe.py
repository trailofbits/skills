# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import hashlib
import json
import re
import time
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
    write_json,
    write_text,
)


@output_type
class CaseSpec:
    check_id: str
    source: str
    argv: list[str]


@output_type
class ProjectCheck:
    check_id: str
    kind: Literal["suite", "behavior", "regression", "security"]
    argv: list[str]
    count_protocol: Literal["PATCH_COUNTS_v1"] = "PATCH_COUNTS_v1"


@output_type
class Plan:
    target_repo: str
    run_dir: str
    attempt: Literal[1, 2, 3]
    prover_agent_id: str
    case_specs: list[CaseSpec]
    project_checks: list[ProjectCheck]
    build_argv: list[str]
    poc_argv: list[str]
    unproven_limits: list[str]
    worktree_output_files: list[str]
    timeout: float = 600.0


@output_type
class Review:
    findings: list[str]
    gaps: list[str]


@output_type
class ProofResult:
    outcome: Literal["complete", "failed", "inconclusive"]
    record: str | None
    manifest: str | None
    receipt_paths: list[str]
    findings: list[str]
    gaps: list[str]


BIND = (
    "import sys,json;from pathlib import Path;sys.path.insert(0,str(Path(sys.argv[1]).parent));fr"
    "om records import load,check;d=Path(sys.argv[2]);n=int(sys.argv[3]);i=sys.argv[4];paths=['ru"
    "n.json','finding.json','reproduce/reproduce.json','validate/validate.json',f'patch/attempt-{"
    "n}/patch.json'];k=['run','finding','reproduce','validate','patch'];x=[load(d/p,t) for p,t in"
    " zip(paths,k,strict=True)];r,f,b,v,p=x;assert f.get('repair_scope',{}).get('cases'),'Declare"
    " nonempty repair_scope';check(d,before_repair=True);assert r['attempts']==n==p['attempt'] an"
    "d p['patch_commit'],'Attempt/commit mismatch';assert b['baseline_commit']==p['baseline_commi"
    "t'],'Baseline mismatch';assert (b['outcome'],v['outcome'])==('reproduced','confirmed'),'Unco"
    "nfirmed reproduction';assert b['agent']!=v['agent'] and i!=p['agent'],'Independent identitie"
    "s required';print(json.dumps(dict(zip('ufbvp',x,strict=True))))"
)
ASSESS = (
    "import sys,json;from pathlib import Path;from dataclasses import asdict;sys.path.insert(0,st"
    "r(Path(sys.argv[1]).parent));from native_proof import assess_proof;from records import load;"
    "r=Path(sys.argv[2]);n=int(sys.argv[3]);d=r/f'prove/attempt-{n}';a=assess_proof(r,n);p=load(d"
    "/'prove.json','prove');g=list(a.gaps);counts={}\ndef j(f):return json.loads(f.read_text(enco"
    "ding='utf-8'))\ndef need(ok,m):\n if not ok:g.append(m)\nneed(p['reverted']=='pass','Three-a"
    "rm behavior failed');need(p['build_identity']==('pass' if p['failure_type']=='runtime' else "
    "'not_applicable'),'Build identity failed')\nfor c in p['project_checks']:\n for side in ('ba"
    "seline','patched'):\n  q=c[side]\n  if q is None:continue\n  t=d/q['stdout'];z=[v[13:] for v"
    " in t.read_text(encoding='utf-8').splitlines() if v.startswith('PATCH_COUNTS ')]\n  try:\n  "
    " v=json.loads(z[0]) if len(z)==1 else {};ok=set(v)=={'passed','failed','skipped'} and all(ty"
    "pe(x)is int and x>=0 for x in v.values()) and v['passed']+v['failed']>0 and (q['exit_code']!"
    "=0 or v['failed']==0)\n  except (ValueError,TypeError,KeyError):ok=False\n  counts[str(t)]=v"
    ";need(ok,f'Executed-item evidence gap: {t}');e=j(d/(q['stdout'].removesuffix('.stdout')+'.ex"
    "it.json'));cwd=str(r/f'prove-work-{n}'/('tree-0' if side=='baseline' else 'tree-1'));need(al"
    "l(e[k]==q[k] for k in q) and e['argv']==c['argv'] and e['cwd']==cwd,f'Project command proven"
    "ance mismatch: {t}')\nfor side in ('baseline','patched','reverted'):\n root=d/'receipts'/sid"
    "e;arm=j(root/'arm.json');b=j(root/'build/exit.json');need(b['exit_code']==arm['build_exit'],"
    "f'Build status mismatch: {root}')\n if p['failure_type']=='runtime':\n  ls=(root/'poc/stdout"
    ".txt').read_text(encoding='utf-8').splitlines();x=j(root/'poc/exit.json');need(ls.count('PAT"
    "CH_REACHED')==1 and ls[-1:]==['PATCH_REACHED'],f'Nonfinal runtime marker: {root}/poc/stdout."
    "txt');need(x['exit_code']==arm['exit_code'],f'PoC status mismatch: {root}')\nprint(json.dump"
    "s(asdict(a)|{'findings':a.findings,'gaps':g,'counts':counts},default=str))"
)


def require(ok: bool, message: str) -> None:
    if not ok:
        fail(message)


def data(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def safe(value: str) -> Path:
    p = Path(value).absolute()
    require(not {"..", ".git"}.intersection(p.parts), f"Unsafe path: {value}")
    require(not any(q.is_symlink() for q in (p, *p.parents)), f"Linked path: {value}")
    return p.resolve()


def argv(value: list[str]) -> list[str]:
    require(bool(value), "Supply a nonempty approved argv array.")
    require(all(0 < len(x) <= 400 and "\x00" not in x for x in value), "Invalid argv argument.")
    return value


def readout(s: dict[str, Any], row: dict[str, Any], proof: bool = False) -> str:
    return (Path(s["proof" if proof else "control"]) / row["stdout"]).read_text(encoding="utf-8")


@step
def execute(
    s: dict[str, Any], cmd: list[str], cwd: str, tag: str = "", write: bool = True
) -> dict[str, Any]:
    root = Path(s["proof" if tag else "control"])
    tag = tag or f"command-{s['seq']}"
    s["seq"] += 1
    names = tuple(f"receipts/{tag}.{x}" for x in ("stdout", "stderr", "exit.json"))
    ensure_directory(root, output_files=names, exclude_roots=(s["repo"],))
    started = time.monotonic()
    try:
        result = run_command(
            cmd, working_directory=cwd, timeout_seconds=s["timeout"], mutating=write
        )
        code, stdout, stderr = result.exit_code, result.stdout, result.stderr
    except Exception as exc:
        if getattr(exc, "command_failure", None) not in {"launch", "timeout"}:
            raise
        code, stdout, stderr = None, "", str(exc)
    row = {
        "exit_code": code,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "stdout": names[0],
        "stderr": names[1],
    }
    write_text(root / names[0], stdout)
    write_text(root / names[1], stderr)
    write_json(
        root / names[2], row | {"argv": cmd, "cwd": cwd, "capture_unavailable": code is None}
    )
    return row


def git(s: dict[str, Any], args: list[str], tree: str = "") -> str:
    r = execute(s, ["git", "-C", tree or s["repo"], *args], s["rd"], write=False)
    require(r["exit_code"] == 0, f"Git inspection failed: {s['control']}/{r['stderr']}")
    return readout(s, r)


def uv(script: str) -> list[str]:
    return ["uv", "run", "--no-project", "python", "-B", str(resource(script))]


def check(s: dict[str, Any], args: list[str], write: bool = False) -> None:
    r = execute(s, uv("scripts/records.py") + args, s["rd"], write=write)
    require(r["exit_code"] == 0, f"Record/manifest check failed: {s['control']}/{r['stderr']}")


def bridge(s: dict[str, Any], code: str) -> dict[str, Any]:
    cmd = [
        "uv",
        "run",
        "--no-project",
        "python",
        "-B",
        "-c",
        code,
        str(resource("scripts/native_proof.py")),
        s["rd"],
        str(s["attempt"]),
        s["prover_agent_id"],
    ]
    r = execute(s, cmd, s["rd"], write=False)
    require(r["exit_code"] == 0, f"Native record assessment failed: {s['control']}/{r['stderr']}")
    return json.loads(readout(s, r))


def unchanged(s: dict[str, Any]) -> bool:
    return all(
        Path(p).is_file() and hashlib.sha256(Path(p).read_bytes()).hexdigest() == h
        for p, h in s["frozen"].items()
    )


@step
def initialize(p: Plan) -> dict[str, Any]:
    repo, rd = safe(p.target_repo), safe(p.run_dir)
    s = p.model_dump()
    require(
        all((repo.is_dir(), rd.is_dir(), not rd.is_relative_to(repo), not repo.is_relative_to(rd))),
        "Use disjoint existing repository/run trees.",
    )
    s.update(
        repo=str(repo),
        rd=str(rd),
        proof=str(rd / f"prove/attempt-{p.attempt}"),
        control=str(rd / f"prove-review-{p.attempt}"),
        seq=0,
        findings=[],
        gaps=[],
        created=[],
    )
    s["trees"] = [str(rd / f"prove-work-{p.attempt}/tree-{i}") for i in range(2)]
    require(
        not any(
            Path(x).exists() for x in (s["proof"], s["control"], str(Path(s["trees"][0]).parent))
        ),
        "Attempt exists; preserve it and use a new attempt.",
    )
    files = list(rd.rglob("*"))
    require(not any(x.is_symlink() or ".git" in x.parts for x in files), "Unsafe run tree.")
    s["frozen"] = {str(x): hashlib.sha256(x.read_bytes()).hexdigest() for x in files if x.is_file()}
    require(
        all(
            (
                bool(p.case_specs),
                bool(p.project_checks),
                bool(p.unproven_limits),
                0 < p.timeout <= 600,
                0 < len(p.prover_agent_id.strip()) <= 100,
                all(0 < len(x.strip()) <= 400 for x in p.unproven_limits),
            )
        ),
        "Supply valid scope, ID and limits.",
    )
    logs = range(128 + 16 * (len(p.case_specs) + len(p.project_checks)))
    ensure_directory(
        s["control"],
        output_files=(
            "pre.json",
            "post.json",
            *(f"receipts/command-{i}.{x}" for i in logs for x in ("stdout", "stderr", "exit.json")),
        ),
    )
    s.update(bridge(s, BIND))
    s["base"], s["final"] = s["b"]["baseline_commit"], s["p"]["patch_commit"]
    require(argv(p.build_argv) == s["b"]["build_argv"], "Approve the original build_argv exactly.")
    require(p.poc_argv == s["b"]["poc_argv"], "Approve the original poc_argv exactly.")
    ids = [c.check_id for c in p.case_specs]
    projects = [c.check_id for c in p.project_checks]
    require(
        all(
            (
                len(set(ids)) == len(ids),
                len(set(projects)) == len(projects),
                set(ids) == {c["check_id"] for c in s["f"]["repair_scope"]["cases"]},
                all(0 < len(x) <= 100 for x in ids + projects),
            )
        ),
        "Supply unique, complete check IDs.",
    )
    s["original"] = [
        git(s, a)
        for a in (
            ["rev-parse", "HEAD"],
            ["status", "--porcelain=v1"],
            ["diff", "--no-ext-diff", "--no-textconv", "HEAD"],
        )
    ]
    return s


@step
def pin(s: dict[str, Any]) -> dict[str, Any]:
    entries = {}
    for sha in (s["base"], s["final"]):
        require(git(s, ["rev-parse", "--verify", sha + "^{commit}"]).strip() == sha, "Invalid SHA.")
        rows = git(s, ["ls-tree", "-rz", sha]).split("\x00")
        require(not any(x.startswith(("120000 ", "160000 ")) for x in rows), "Linked pinned tree.")
        entries[sha] = [x.split("\t", 1)[1] for x in rows if x]
    require(git(s, ["rev-parse", "--show-toplevel"]).strip() == s["repo"], "Use repository root.")
    s["entries"] = entries
    return guidance(s)


def guidance(s: dict[str, Any]) -> dict[str, Any]:
    names = ("AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md")
    g = {n: git(s, ["show", f"{s['base']}:{n}"]) for n in names if n in s["entries"][s["base"]]}
    absent = set(names) - set(g)
    saved = Path(s["rd"]) / "guidance" / s["base"]
    if saved.exists():
        note = (saved / "source.md").read_text(encoding="utf-8")
        require(
            re.findall(r"[0-9a-fA-F]{40,}", note) == [s["base"]], "Saved guidance SHA mismatch."
        )
        require(
            set(re.findall("|".join(re.escape(n) for n in names), note)) == absent,
            "Saved guidance must state exactly the absent root guidance names.",
        )
        for n in names:
            require((saved / n).is_file() == (n in g), f"Guidance presence mismatch: {n}")
            require(
                n not in g or (saved / n).read_bytes() == g[n].encode(), f"Changed guidance: {n}"
            )
    diff = git(s, ["diff", "--no-ext-diff", "--no-textconv", s["base"], s["final"]])
    require(bool(diff.strip()), "Pinned patch changes zero files.")
    return {
        "scope": s["f"]["repair_scope"],
        "invariant": s["f"]["invariant"],
        "diff": diff,
        "guidance": g,
        "absent": sorted(absent),
        "commits": [s["base"], s["final"]],
    }


def arm_paths(s: dict[str, Any]) -> list[str]:
    kinds = ("build", "poc") if s["b"].get("failure_type", "runtime") == "runtime" else ("build",)
    sides = ("baseline", "patched", "reverted")
    return (
        ["receipts/source.json"]
        + [f"receipts/{x}/arm.json" for x in sides]
        + [
            f"receipts/{x}/{k}/{f}"
            for x in sides
            for k in kinds
            for f in ("stdout.txt", "stderr.txt", "exit.json")
        ]
    )


@step
def prepare(s: dict[str, Any]) -> list[dict[str, Any]]:
    tags = [f"build-{j}" for j in range(2)] + [
        f"{k}-{i}-{j}"
        for k, values in (("case", s["case_specs"]), ("project", s["project_checks"]))
        for i in range(len(values))
        for j in range(2)
    ]
    outputs = (
        arm_paths(s)
        + ["prove.json", "manifest.json"]
        + [f"receipts/case-{i}.source" for i in range(len(s["case_specs"]))]
    )
    outputs += [f"receipts/{t}.{x}" for t in tags for x in ("stdout", "stderr", "exit.json")]
    ensure_directory(s["proof"], output_files=tuple(outputs), exclude_roots=(s["repo"],))
    cases = []
    s["harnesses"] = {}
    for i, c in enumerate(s["case_specs"]):
        cmd = argv(c["argv"])
        require(cmd.count("{harness}") == 1, "Use one {harness} argument.")
        require(cmd[0] != "{harness}", "Invoke the retained harness through its interpreter.")
        raw = safe(c["source"]).read_bytes()
        name = f"receipts/case-{i}.source"
        path = Path(s["proof"]) / name
        write_text(path, raw.decode("utf-8"))
        s["harnesses"][str(path)] = hashlib.sha256(raw).hexdigest()
        cases.append(
            {
                "check_id": c["check_id"],
                "source": name,
                "runs": {},
                "argv": argv([str(path) if x == "{harness}" else x for x in cmd]),
            }
        )
    for i, sha in enumerate((s["base"], s["final"])):
        tree = s["trees"][i]
        ensure_directory(
            tree,
            exclude_roots=(s["repo"],),
            output_files=tuple(s["entries"][sha] + s["worktree_output_files"]),
        )
        s["created"].append(tree)
        r = execute(s, ["git", "-C", s["repo"], "worktree", "add", "--detach", tree, sha], s["rd"])
        require(r["exit_code"] == 0, f"Worktree setup failed: {s['control']}/{r['stderr']}")
    require(stable(s), "Owned worktrees are not clean at pinned commits.")
    return cases


@step
def review(s: dict[str, Any], task: str) -> Review:
    files = tuple(
        p
        for root in (s["proof"], s["control"])
        for p in Path(root).rglob("*")
        if p.is_file() and p.name not in {"pre.json", "post.json"}
    )
    context = prepare_context(
        task,
        prior_results=json.dumps(s["packet"]),
        files=files,
        readable_roots=(s["proof"], s["control"]),
    )
    return agent(
        "worker",
        "Use the authoritative workflow for this independent semantic review. "
        "Read complete provided references and assigned pinned sources. No commands or edits. "
        "Inspect relevance, boundaries, guidance, launch provenance and evidence; return object"
        "ions.",
        context=context,
        working_directory=context.directory,
        output=Review,
        timeout=3600,
        readable_paths=(
            *s["trees"],
            resource("references/records.md"),
            resource("scripts/arms.py"),
            resource("scripts/native_proof.py"),
        ),
    )


def stable(s: dict[str, Any]) -> bool:
    rows = [
        [
            git(s, a, t)
            for a in (
                ["rev-parse", "HEAD"],
                ["status", "--porcelain=v1", "--untracked-files=no"],
                ["diff", "--no-ext-diff", "--no-textconv", "HEAD"],
            )
        ]
        for t in s["trees"]
    ]
    ok = rows == [[s["base"] + "\n", "", ""], [s["final"] + "\n", "", ""]]
    if not ok:
        s["gaps"].append(f"Pinned worktree mutated; inspect {s['control']}/receipts.")
    return ok


def builds(s: dict[str, Any]) -> None:
    for j, tree in enumerate(s["trees"]):
        b = execute(s, s["build_argv"], tree, f"build-{j}")
        ok = b["exit_code"] == 0
        if j == 0 and s["b"].get("failure_type", "runtime") == "compile":
            output = readout(s, b, True) + (Path(s["proof"]) / b["stderr"]).read_text(
                encoding="utf-8"
            )
            ok = b["exit_code"] not in (None, 0) and s["b"]["expected_diagnostic"] in output
        if not ok:
            s["gaps"].append(
                f"Pinned build result missing or unexpected: {s['proof']}/{b['stdout']}"
            )


def scoped(s: dict[str, Any]) -> None:
    for i, c in enumerate(s["cases"]):
        c["runs"] = {
            side: execute(s, c["argv"], s["trees"][j], f"case-{i}-{j}")
            for j, side in enumerate(("baseline", "patched"))
        }
        if not unchanged(s | {"frozen": s["harnesses"]}):
            s["gaps"].append(f"Retained harness changed: {s['proof']}/{c['source']}")
            return
        if not stable(s):
            return


def projects(s: dict[str, Any]) -> None:
    for i, spec in enumerate(s["project_checks"]):
        p = {k: spec[k] for k in ("check_id", "kind", "argv")}
        argv(p["argv"])
        p["patched"] = execute(s, p["argv"], s["trees"][1], f"project-{i}-1")
        p["baseline"] = (
            execute(s, p["argv"], s["trees"][0], f"project-{i}-0")
            if p["kind"] != "suite" or p["patched"]["exit_code"] != 0
            else None
        )
        s["projects"].append(p)
        if not stable(s):
            return


@step
def native(s: dict[str, Any]) -> dict[str, Any]:
    builds(s)
    if stable(s):
        scoped(s)
        if stable(s):
            projects(s)
    return {
        "cases": [c for c in s["cases"] if len(c["runs"]) == 2],
        "project_checks": s["projects"],
    }


@step
def prove(s: dict[str, Any]) -> dict[str, Any]:
    require(unchanged(s), "Original stage evidence changed before three-arm proof.")
    b = s["b"]
    kind = b.get("failure_type", "runtime")
    if kind == "runtime":
        sources = {str(p) for p in (Path(s["rd"]) / "reproduce/poc").rglob("*") if p.is_file()}
        require(
            bool(set(argv(s["poc_argv"])) & sources), "PoC must name an absolute retained source."
        )
    cmd = [
        *uv("scripts/arms.py"),
        "run",
        "--repo",
        s["repo"],
        "--baseline",
        s["base"],
        "--patch",
        s["final"],
        "--build",
        json.dumps(s["build_argv"]),
        "--out",
        s["proof"],
    ]
    cmd += (
        [
            "--failure-type",
            "runtime",
            "--poc",
            json.dumps(s["poc_argv"]),
            "--artifact",
            b["target_artifact"],
        ]
        if kind == "runtime"
        else ["--failure-type", "compile", "--expected-diagnostic", b["expected_diagnostic"]]
    )
    r = execute(s | {"timeout": 3500}, cmd, s["rd"])
    if r["exit_code"] != 0:
        s["gaps"].append(f"Three-arm helper failed: {s['control']}/{r['stderr']}")
        return {}
    arm = json.loads(readout(s, r))
    check(s, ["check", s["rd"]])
    record = (
        arm
        | s["packet"]["executions"]
        | {
            "schema_version": 2,
            "attempt": s["attempt"],
            "baseline_commit": s["base"],
            "patch_commit": s["final"],
            "unproven": s["unproven_limits"],
            "agent": s["prover_agent_id"],
        }
    )
    write_json(Path(s["proof"]) / "prove.json", record)
    ensure_directory(s["proof"], output_files=("manifest.json",), overwrite=True)
    check(s, ["manifest", s["proof"]], True)
    check(s, ["check", s["rd"]])
    a = bridge(s, ASSESS)
    merge(s, a)
    return {"prove": record, "assessment": a}


def merge(s: dict[str, Any], result: dict[str, Any]) -> None:
    for k in ("findings", "gaps"):
        s[k].extend(result[k])


@recipe(
    agents=("worker",),
    capabilities=("Bash",),
    output_root=".",
    budget=Budget(max_agent_calls=4, max_wall_seconds=3600),
)
def prove_patch(plan: Plan) -> ProofResult:
    s = initialize(plan)
    record = {}
    try:
        s["packet"] = pin(s)
        s["cases"] = prepare(s)
        s["projects"] = []
        s["packet"].update(
            cases=s["cases"],
            projects=s["project_checks"],
            build=s["build_argv"],
            poc=s["poc_argv"],
            unproven=s["unproven_limits"],
        )
        pre = review(
            s, "Review guidance, complete case plan, harnesses and actual patch before builds."
        )
        write_json(Path(s["control"]) / "pre.json", pre.model_dump())
        merge(s, pre.model_dump())
        if not s["findings"] and not s["gaps"]:
            s["packet"]["executions"] = native(s)
            record = prove(s)
            s["packet"].update(record)
            post = review(
                s,
                "Inspect native assessment and all raw receipts independently; verify "
                "actual harness launches on pinned trees, relevance, loader identity and stated"
                " limits.",
            )
            write_json(Path(s["control"]) / "post.json", post.model_dump())
            merge(s, post.model_dump())
    finally:
        for tree in s["created"]:
            r = execute(s, ["git", "-C", s["repo"], "worktree", "remove", "--force", tree], s["rd"])
            if r["exit_code"] != 0:
                s["gaps"].append(f"Owned worktree cleanup failed: {tree}")
    require(unchanged(s), "Original evidence or guidance changed; investigate retained receipts.")
    now = [
        git(s, a)
        for a in (
            ["rev-parse", "HEAD"],
            ["status", "--porcelain=v1"],
            ["diff", "--no-ext-diff", "--no-textconv", "HEAD"],
        )
    ]
    require(now == s["original"], "Caller checkout changed during proof.")
    paths = sorted(
        str(p) for root in (s["proof"], s["control"]) for p in Path(root).rglob("*") if p.is_file()
    )
    outcome = "failed" if s["findings"] else "inconclusive" if s["gaps"] else "complete"
    return emit(
        ProofResult(
            outcome,
            s["proof"] + "/prove.json" if record else None,
            s["proof"] + "/manifest.json" if record else None,
            paths,
            s["findings"],
            s["gaps"],
        ),
        name="patch-proof",
    )


if __name__ == "__main__":
    raise SystemExit(prove_patch.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("20aa468847e1c0c61525519a49bca1e26dd9fca016f5474ac296544656035bce"),
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
        "ain separate from model output.\n\n\nImplement independent"
        "ly executed scoped proof AND the real packaged three-arm h"
        "elper. Expose target_repo, run_dir, attempt, prover_agent_"
        "id, caller-approved case specifications (one retained harn"
        "ess source+argv per existing repair_scope.check_id), proje"
        "ct_checks specifications (fixed id/kind/argv), timeout and"
        " specific unproven limits. Never let worker output provide"
        " argv, source path, commit selector, output path, or verdi"
        "ct. Require reproduction, confirmed independent validation"
        ", actual patch commit, intact manifests, matching baseline"
        "/patch IDs, 1..3attempt consistency, nonempty case and pro"
        "ject-check scope, and prover identity different from patch"
        "er (and independent fresh context); prove must not edit th"
        "e target patch or validate an uncommitted tree. No reading"
        " patcher conclusion/transcript in worker review packet. St"
        "age only scope/caseplan, actual patch diff/source, native "
        "receipts, guidance and raw checks.\n\nVerify pinned baseli"
        "ne root guidance before commands. Host creates clean owned"
        " baseline and patch worktrees at their exact Git commit ob"
        "jects. Build both with original reproduce.build_argv as re"
        "quired (mutating=True). For every planned unique check_id,"
        " copy caller-supplied unchanged harness to a host-computed"
        " fixed prove/attempt-N/receipts path, then execute the sam"
        "e argv+same source bytes on both trees (only cwd differs; "
        "do not pass arm/side flags to harness). Retain source, std"
        "out/stderr, status, elapsed_ms and exact command. Require "
        "exactly one PATCH_CASE with {input,actual}, matching plann"
        "ed input; PATCH_REACHED exactly once and final stdout line"
        ". Planned representatives fail baseline (actual differs ex"
        "pected) and pass patched(actual equals expected); controls"
        " pass both. Missing/timeouts/setup crashes/ambiguous input"
        "/marker are gaps, never passes; trustworthy patched failed"
        " expectation is a finding. Bounded class must retain >=2 d"
        "istinct representative inputs and passing control, exact_e"
        "xample still nonempty. No zero-case success.\n\nExecute ea"
        "ch caller-approved relevant project check on patch, retain"
        " raw receipts. Behavior checks require baseline comparison"
        "; failed patched checks need baseline receipts to attribut"
        "e existing failures. Passing patched suites can omit basel"
        "ine. Require actual inspected items (e.g. nonzero collecte"
        "d/executed tests) where applicable; all-skipped/zero tests"
        " is not proof. Keep specific nonempty unproven limits. Hav"
        "e an isolated read-only worker assess relevance of chosen "
        "cases and code boundaries from these executed facts, but n"
        "ever replace execution with its conclusion.\n\nInvoke actu"
        "al packaged arms.py CLI with run --repo target_repo --base"
        "line reproduce.baseline_commit --patch patch.patch_commit "
        "--build json.dumps(reproduce.build_argv) --out proof_attem"
        "pt_dir, plus type-specific args. Runtime uses original --p"
        "oc argv and --artifact relativepath; compile uses --failur"
        "e-type compile --expected-diagnostic and no runtime artifa"
        "ct/poc. Note arms.py only exposes the flags in actual main"
        "; no --timeout flag. Original PoC remains outside helper-o"
        "wned trees and unchanged. Host reads helper JSON; require "
        "baseline fail/patch pass/reverted fail behavior and receip"
        "ts/source.json pinned commits and equal baseline/reverted "
        "TREE IDs. Runtime build_identity:pass requires per-arm PAT"
        "CH_LOADED observations of actual loaded file, full hashes "
        "and changed patched artifact; compile build_identity:not_a"
        "pplicable and all hashes:null. Do not implement partial re"
        "vert or report helper exit0 as proof by itself. arms helpe"
        "r writes an interim manifest; add native case/project rece"
        "ipts and prove.json afterward and rewrite the final manife"
        "st.\n\nConstruct prove.json EXACTLY schema_version2 and ac"
        "tual fields: attempt, failure_type, matching commits, reve"
        "rted/build_identity/hashes/reverted_hash_note from helper;"
        " native cases/check_ids/argv/source/runs with elapsed_ms a"
        "nd receipt-relative names; project_checks with kind,argv,b"
        "aseline|null,patched; specific unproven; agent. Manifest c"
        "omplete proof step, run records.py check run_dir, then cal"
        "l actual native_proof.assess_proof(run_dir,attempt) throug"
        "h a FIXED literal Python bridge using trusted packaged res"
        "ource module directory. ProofAssessment has findings and g"
        "aps properties plus arm_gaps/case_findings/case_gaps/proje"
        "ct_findings/project_gaps/case_paths/project_paths. Preserv"
        "e assessment and exact finding/gap receipt paths, and retu"
        "rn complete only when native assessment has NO findings/ga"
        "ps, helper/source/load gates pass, and independent semanti"
        "c case review raises no objection. Any finding or gap retu"
        "rns honest failed/inconclusive result for next attempt. Ne"
        "ver relabel missing evidence as pass, never claim READY (r"
        "egression stage/orchestrator decides readiness), never cre"
        "ate regression/report records. Cleanup only recipe-owned t"
        "emp worktrees; retain all evidence.\n\n\nFocused native so"
        "urce review of the substantive first candidate found these"
        " execution-contract gaps. Preserve the actual native workf"
        "low while repairing them:\n* Do not use worker-returned Re"
        "view.executed_items as the zero-item gate. Derive actual p"
        "roject-check item counts deterministically from a caller-s"
        "elected retained machine-readable report or an explicit ho"
        "st-parsed stdout protocol/supported parser. Counts must be"
        " tied to each actually executed command receipt, with pass"
        "ed+failed>0; all-skipped/zero-collected/missing/ambiguous "
        "counts are evidence gaps. The worker may judge semantic re"
        "levance but cannot manufacture an execution count. Expose "
        "a typed caller report/protocol contract if needed instead "
        "of pretending to support arbitrary tools.\n* Verify saved "
        "guidance source.md absences as the exact set of the three "
        "known root guidance names absent from baseline Git objects"
        ", and the pinned SHA exactly, rather than merely testing t"
        "hat each expected absent name appears somewhere. Reject fa"
        "lse claimed absences and contradictory saved presence.\n* "
        "After all native project checks, verify each recipe-owned "
        "pinned worktree still has its original HEAD and no tracked"
        " source diff. Retain and report any command-induced mutati"
        "on as a gap; never assess changed tracked sources as the p"
        "inned patch.\n* For runtime three-arm receipts, parse each"
        " actual retained poc/stdout.txt and require PATCH_REACHED "
        "exactly once as the final stdout line, in addition to the "
        "helper's real loader/hash and behavior result. arms.py its"
        "elf only checks marker presence; the recipe must preserve "
        "the stronger source contract instead of accepting a later "
        "setup failure after an early marker. Verify receipt comman"
        "d/cwd/status provenance from the actual helper files and k"
        "eep these raw receipts.\n* Respect local plugin Ruff rules"
        " including C901 max-complexity=8 and PLR0913 at most five "
        "arguments, C4 and RUF, target py313. Decompose into module"
        "-level typed helpers/steps; nested helpers still count tow"
        "ard enclosing complexity. Do not add noqa, config exclusio"
        "ns, or suppression.\n\n\nNarrow final repository lint repa"
        "ir: the preserved candidate already passed source-contract"
        " review. Fix exactly the three RUF005 concatenation diagno"
        "stics by iterable unpacking in initialize output_files, re"
        "view readable_paths, and prove arms argv. Preserve all nat"
        "ive scope/binding, independent review, final-line markers,"
        " deterministic counts, actual helper interfaces, cleanup, "
        "receipts, unchanged evidence and worktree guards. Do not s"
        "uppress Ruff or change configuration. No broad workflow re"
        "write.\n"
    ),
    "sha256": ("be226d6948ab29833b3920618df9e77914c5cc60008b92d3621524a46f2574b4"),
}
_CALCIFIER_SUBRECIPES = []
