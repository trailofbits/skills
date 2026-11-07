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

Outcome = Literal["confirmed", "not_confirmed", "inconclusive"]
UV = ["uv", "run", "--no-project", "python", "-B"]
BRIDGE = (
    "import json,sys;from pathlib import Path;sys.path.insert(0,str(Path(sys.argv[1]).parent));from"
    " records import check,load,repair_scope_gaps;p=Path(sys.argv[2]);repo=sys.argv[3];check(p);f=l"
    "oad(p/'finding.json','finding');r=load(p/'reproduce/reproduce.json','reproduce');assert f.get("
    "'repair_scope');assert not repair_scope_gaps(f['repair_scope']);c=json.loads((p/'reproduce/rec"
    "eipts/commands.json').read_bytes());assert c['baseline']==r['baseline_commit'] and c['build']="
    "=r['build_argv'];cases=f['repair_scope']['cases'];assert cases and len(c['commands'])==len(cas"
    "es);src=[str(x) for x in (p/'reproduce/poc').rglob('*') if x.is_file()];assert src;m={k:v for "
    "v in src for k in (v,str(Path(v).relative_to(p)),str(Path(v).relative_to(p/'reproduce')))}\nde"
    "f portable(a):\n assert isinstance(a,list) and a and all(isinstance(x,str) and x.strip() for x"
    " in a), 'Supply nonempty build/PoC/case argv arrays'\n a=[m.get(str(Path(x)),x) for x in a]\n "
    "assert not any(repo in x or '..' in Path(x).parts for x in a)\n assert all(not Path(x.split('="
    "',1)[-1]).is_absolute() or x in src for x in a[1:])\n return a\nargs=[];raw=[str(p/'reproduce/"
    "receipts/commands.json')]\nfor i,a in enumerate(c['commands']):\n b=p/'reproduce/receipts'/f'"
    "case-{i}';t=json.loads(Path(str(b)+'.exit.json').read_bytes())\n assert {'argv','cwd','exit_co"
    "de','error','elapsed_ms'}<=set(t)\n assert t['argv']==a and isinstance(t['cwd'],str) and t['cw"
    "d']\n assert t['exit_code'] is None or type(t['exit_code']) is int\n assert type(t['elapsed_"
    "ms']) is int and t['elapsed_ms']>=0\n for e in ('.stdout','.stderr','.exit.json'):\n  q=Path("
    "str(b)+e);q.read_bytes();raw.append(str(q))\n a=portable(a);assert any(x in src for x in a);a"
    "rgs.append(a)\nfor e in ('.stdout','.stderr','.exit.json'):\n q=p/'reproduce/receipts'/('buil"
    "d'+e)\n if r.get('failure_type','runtime')=='runtime':assert q.is_file()\n if q.is_file():raw"
    ".append(str(q))\nbuild=portable(r['build_argv']);poc=portable(r['poc_argv']) if r.get('failure"
    "_type','runtime')=='runtime' else [];assert not poc or any(x in src for x in poc);print(json."
    "dumps({'f':f,'r':r,'cases':cases,'sources':src,'raw':raw,'args':args,'build':build,'poc':p"
    "oc}))"
)
GATE = (
    "import json,sys;from pathlib import Path;sys.path.insert(0,str(Path(sys.argv[1]).parent));from"
    " native_proof import _case_observation;s=json.loads(Path(sys.argv[2]).read_bytes());r=s['r'];"
    "C,N,I='confirmed','not_confirmed','inconclusive'\ndef judge(x,case=None):\n code=x['exit_code'"
    "];o=x['stdout']\n if code is None or not 0<=code<126:return I\n if r.get('failure_type','runti"
    "me')=='compile':\n  matched=r['expected_diagnostic'] in o+x['stderr'];return C if code>0 and "
    "matched else N if code==0 else I\n try:\n  lines=o.splitlines();assert x['artifact_stable'];a"
    "ssert lines.count('PATCH_REACHED')==1 and lines[-1]=='PATCH_REACHED'\n  l=[json.loads(x[13:]) "
    "for x in lines if x.startswith('PATCH_LOADED ')];assert l==[{'path':s['artifact'],'sha256':s["
    "'hash']}];v=code==0\n  if case is not None:\n   obs=_case_observation(o.encode());assert obs['"
    "input']==case['input'];v=obs['actual']==case['expected']\n  assert v==(code==0);return N if v "
    "else C\n except (AssertionError,ValueError,KeyError,TypeError):return I\ngate=judge(s['runs']"
    "[1]);pairs=zip(s['runs'][2:],s['cases'],strict=True);ok=all(judge(a,b)==(gate if b['role']=='r"
    "epresentative' else N) for a,b in pairs);print(json.dumps(gate if ok else I))"
)


@output_type
class Review:
    outcome: Outcome
    reason: str


@output_type
class Validation:
    outcome: Outcome
    record: str
    manifest: str
    receipts: list[str]
    verified: bool


def need(value: object, reason: str) -> None:
    return None if value else fail(reason)


def safe(value: str) -> Path:
    p = Path(value).absolute()
    need(not {"..", ".git"}.intersection(p.parts), f"Unsafe path: {value}")
    need(not any(x.is_symlink() for x in (p, *p.parents)), f"Linked path: {value}")
    return p.resolve()


def digest(value: str) -> str:
    p = Path(value)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and p.resolve() == p else ""


def snapshot(s: dict[str, Any]) -> dict[str, str]:
    paths = [Path(s["run"]) / n for n in ("run.json", "finding.json")]
    paths.extend((Path(s["run"]) / "reproduce").rglob("*"))
    return {str(p): digest(str(p)) for p in paths if p.is_file() or p.is_symlink()}


def execute(s: dict[str, Any], a: list[str], n: str, m: bool = False) -> dict[str, Any]:
    ends = ("stdout", "stderr", "exit.json")
    root = ensure_directory(s["store"], output_files=tuple(f"{n}.{e}" for e in ends))
    started = time.monotonic()
    row: dict[str, Any] = {"argv": a, "cwd": s["cwd"], "exit_code": None, "error": None}
    row.update(stdout="", stderr="")
    before = digest(s["artifact"]) if s.get("hash") else ""
    try:
        r = run_command(a, timeout_seconds=s["t"], working_directory=s["cwd"], mutating=m)
        row.update(exit_code=r.exit_code, stdout=r.stdout, stderr=r.stderr)
    except Exception as exc:
        if getattr(exc, "command_failure", None) not in {"launch", "timeout"}:
            raise
        row.update(error=str(exc), output_available=False)
    row["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    row["artifact_stable"] = not s.get("hash") or before == s["hash"] == digest(s["artifact"])
    for e in ends[:2]:
        write_text(root / f"{n}.{e}", row[e])
    write_json(root / f"{n}.exit.json", row)
    s["receipts"].extend(str(root / f"{n}.{e}") for e in ends)
    return row


def checked(s: dict[str, Any], a: list[str], n: str, m: bool = False) -> str:
    row = execute(s, a, n, m)
    need(row["exit_code"] == 0, f"{n}: {row.get('error') or row['stderr']}")
    return row["stdout"]


def state(s: dict[str, Any], path: str, label: str, mode: str = "all") -> list[str]:
    specs = (["rev-parse", "HEAD"], ["status", "--porcelain=v1", f"--untracked-files={mode}"])
    return [
        checked(s, ["git", "-C", path, *a], f"{label}-{i}").rstrip("\n")
        for i, a in enumerate(specs)
    ]


@step
def prepare(repo_arg: str, run_arg: str, identity: str, timeout: float) -> dict[str, Any]:
    repo, run = safe(repo_arg), safe(run_arg)
    need(repo.is_dir() and run.is_dir(), "Target/run directories must exist.")
    need(not run.is_relative_to(repo) and not repo.is_relative_to(run), "Run must be external.")
    need(0 < timeout <= 3600 and 0 < len(identity.strip()) <= 100, "Invalid identity or timeout.")
    need(not any(p.is_symlink() or ".git" in p.parts for p in run.rglob("*")), "Unsafe run tree.")
    names = ("run.json", "finding.json", "reproduce/reproduce.json", "reproduce/manifest.json")
    need(all((run / n).is_file() for n in names), "Missing mandatory reproduction records.")
    scratch = run / "scratch/validate-bug"
    need(not (run / "validate").exists() and not scratch.exists(), "Validation already exists.")
    s: dict[str, Any] = {"repo": str(repo), "run": str(run), "scratch": str(scratch), "t": timeout}
    s.update(cwd=str(repo), store=str(scratch / "audit"), id=identity.strip(), receipts=[])
    s.update(git=["git", "-C", str(repo)], runs=[], created=False)
    root = checked(s, [*s["git"], "rev-parse", "--show-toplevel"], "root").strip()
    need(Path(root) == repo, "target_repo must name the Git root.")
    argv = [*UV, "-c", BRIDGE, str(resource("scripts/records.py")), str(run), str(repo)]
    s.update(json.loads(checked(s, argv, "records-input")))
    need(s["id"] != s["r"]["agent"], "Validator identity must differ from reproducer.")
    s.update(tree=str(scratch / "worktrees/baseline"), originals=snapshot(s))
    if s["poc"]:
        p = Path(s["r"]["target_artifact"])
        portable = p.parts and not p.is_absolute() and not {"..", ".git"}.intersection(p.parts)
        need(portable, "Nonportable target_artifact: require a relative baseline worktree file.")
        s["artifact"] = str(Path(s["tree"]) / p)
    s["caller"] = state(s, s["repo"], "caller-before")
    return s


@step
def guidance(s: dict[str, Any]) -> dict[str, Any]:
    sha = s["r"]["baseline_commit"]
    got = checked(s, [*s["git"], "rev-parse", "--verify", f"{sha}^{{commit}}"], "baseline")
    need(got.strip() == sha, "Cannot verify baseline.")
    names = ("AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md")
    listing = checked(s, [*s["git"], "ls-tree", sha, "--", *names], "guidance-list")
    entries = {line.split("\t")[1]: line.split()[:3] for line in listing.splitlines()}
    regular = all(v[0] in {"100644", "100755"} and v[1] == "blob" for v in entries.values())
    need(regular, "Guidance must contain regular Git blobs.")
    texts = {
        n: checked(s, [*s["git"], "show", f"{sha}:{n}"], f"guidance-{n}")
        for n in names
        if n in entries
    }
    absent, saved = [n for n in names if n not in entries], Path(s["run"]) / "guidance" / sha
    if saved.exists():
        source = (saved / "source.md").read_text(encoding="utf-8")
        need(re.findall(r"\b[0-9a-f]{40}\b", source) == [sha], "Guidance provenance mismatch.")
        need({n for n in names if n in source} == set(absent), "Guidance absences mismatch.")
        need(all((saved / n).is_file() == (n in entries) for n in names), "Absence mismatch.")
        for n in texts:
            a = [*s["git"], "hash-object", "--no-filters", str(saved / n)]
            need(checked(s, a, f"copy-{n}").strip() == entries[n][2], "Saved guidance mismatch.")
    return {"baseline": sha, "absent": absent, "texts": texts}


@step
def review(s: dict[str, Any], phase: Literal["preflight", "postflight"]) -> Review:
    need(snapshot(s) == s["originals"], "Original package changed.")
    proof = {
        k: s["r"].get(k)
        for k in ("failure_type", "baseline_commit", "expected_diagnostic", "target_artifact")
    }
    packet = {"finding": s["f"], "guidance": s["guidance"], "proof": proof}
    packet.update(cwd=s["tree"], build=s["build"], poc=s["poc"], cases=s["args"])
    if phase == "postflight":
        packet.update(receipts=s["runs"], artifact=s.get("artifact"), frozen_sha256=s.get("hash"))
    task = (
        "Apply full pinned guidance BEFORE execution. Confirmed approves this exact safe, "
        "compatible command plan; otherwise decline. Never select or alter commands/files."
        if phase == "preflight"
        else "Independently assess exact claim/invariant from unchanged sources and actual raw "
        "reruns. Inspect invocation and observations. Unreliable evidence is inconclusive."
    )
    refs = (resource("references/records.md"), resource("schemas/validate.schema.json"))
    files = (*s["sources"], *s["raw"], *refs)
    context = prepare_context(
        task + " Return outcome and reason of 1 through 400 characters.",
        prior_results=json.dumps(packet),
        files=files,
        readable_roots=files,
    )
    root = ensure_directory(Path(s["scratch"]) / "audit", output_files=(f"{phase}.json",))
    error = ""
    try:
        result = agent(
            "worker",
            "Review the complete blinded packet; read only.",
            context=context,
            working_directory=context.directory,
            readable_paths=(context.directory,),
            output=Review,
            timeout=3600,
        )
    except RuntimeError as exc:
        if type(exc).__name__ not in {"RuntimeError", "AgentError"}:
            raise
        error = str(exc)
        result = Review("inconclusive", error[:400] or "Worker RuntimeError")
    write_json(root / f"{phase}.json", {"review": result.model_dump(), "provider_error": error})
    s["receipts"].append(str(root / f"{phase}.json"))
    need(1 <= len(result.reason) <= 400, "Worker reason must contain 1 through 400 characters.")
    return result


@step
def replay(s: dict[str, Any]) -> Outcome:
    ensure_directory(Path(s["scratch"]) / "worktrees", output_files=("baseline",))
    a = [*s["git"], "worktree", "add", "--detach", s["tree"], s["r"]["baseline_commit"]]
    added = execute(s, a, "add", True)
    s["created"] = added["exit_code"] == 0 and Path(s["tree"]).is_dir()
    if not s["created"]:
        return "inconclusive"
    expected = [s["r"]["baseline_commit"], ""]
    need(state(s, s["tree"], "owned-before", "no") == expected, "Owned baseline is not clean.")
    s["cwd"], s["store"] = s["tree"], str(Path(s["run"]) / "validate/receipts")
    build = execute(s, s["build"], "build", True)
    s["runs"] = [build]
    s["hash"] = digest(s["artifact"]) if s["poc"] and build["exit_code"] == 0 else ""
    if s["poc"] and not s["hash"]:
        return "inconclusive"
    primary = execute(s, s["poc"], "poc", True) if s["poc"] else build
    rows = [execute(s, a, f"case-{i}", True) for i, a in enumerate(s["args"])]
    s["runs"] = [build, primary, *rows]
    data = {k: s.get(k) for k in ("r", "runs", "cases", "artifact", "hash")}
    audit = ensure_directory(Path(s["scratch"]) / "audit", output_files=("native-gate-input.json",))
    path = write_json(audit / "native-gate-input.json", data)
    a = [*UV, "-c", GATE, str(resource("scripts/native_proof.py")), str(path)]
    return json.loads(checked(s, a, "native-gate"))


@step
def finish(s: dict[str, Any], decision: Review, gate: Outcome) -> Validation:
    need(snapshot(s) == s["originals"], "Original package changed.")
    need(state(s, s["repo"], "caller-after") == s["caller"], "Caller HEAD/status changed.")
    if gate == "inconclusive" or (decision.outcome == "confirmed" and gate != "confirmed"):
        reason = decision.reason if decision.outcome == "inconclusive" else "Host replay has gaps."
        decision = Review("inconclusive", reason)
    root = ensure_directory(
        Path(s["run"]) / "validate", output_files=("validate.json", "manifest.json")
    )
    write_json(
        root / "validate.json",
        {
            "schema_version": 1,
            "agent": s["id"],
            "outcome": decision.outcome,
            "reason": decision.reason,
        },
    )
    s["store"], s["cwd"] = str(Path(s["scratch"]) / "audit"), s["repo"]
    helper = [*UV, str(resource("scripts/records.py"))]
    checked(s, [*helper, "manifest", str(root)], "manifest", True)
    verified = all((root / n).is_file() for n in ("validate.json", "manifest.json"))
    if verified:
        checked(s, [*helper, "check", s["run"]], "records-final")
    result = Validation(
        decision.outcome if verified else "inconclusive",
        str(root / "validate.json"),
        str(root / "manifest.json"),
        s["receipts"],
        verified,
    )
    return emit(result, name="validation")


@recipe(
    name="validate-bug",
    agents=("worker",),
    capabilities=("Bash",),
    output_root=".",
    budget=Budget(max_agent_calls=4, max_wall_seconds=3600),
)
def validate_bug(
    target_repo: str, run_dir: str, validator_agent_id: str, execution_timeout: float = 600
) -> Validation:
    s = prepare(target_repo, run_dir, validator_agent_id, execution_timeout)
    s["guidance"] = guidance(s)
    plan = review(s, "preflight")
    if plan.outcome != "confirmed":
        return finish(s, Review("inconclusive", plan.reason), "inconclusive")
    try:
        gate = replay(s)
        expected = [s["r"]["baseline_commit"], ""]
        if s["created"] and state(s, s["tree"], "owned-after", "no") != expected:
            gate = "inconclusive"
    finally:
        s["cwd"] = s["repo"]
        if s["created"]:
            checked(s, [*s["git"], "worktree", "remove", "--force", s["tree"]], "remove", True)
    return finish(s, review(s, "postflight"), gate)


if __name__ == "__main__":
    raise SystemExit(validate_bug.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("b26f141e2674944721c03e2ab8b1bef1c55787497695b011c9c0c4025cee869d"),
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
        "ain separate from model output.\n\n\nImplement an independ"
        "ent rerun, not a worker opinion about reproduce.json. Call"
        "er interface should include target_repo, run_dir, validato"
        "r_agent_id and execution timeout. Commands come from the v"
        "alidated manifest-covered reproduction package (which is e"
        "xplicit caller evidence), not model output. Require findin"
        "g.json, reproduce/reproduce.json, complete valid reproduce"
        " manifest/PoC, nonempty scope and scoped receipts, and cur"
        "rent target Git objects containing reproduce.baseline_comm"
        "it. Validate agent identity differs from reproduce.agent B"
        "EFORE invoking a fresh independent worker. Never read or p"
        "ass the reproducer transcript. Stage a dedicated read-only"
        " review packet containing finding claim/invariant, retaine"
        "d PoC/source, raw execution receipts and pinned root guida"
        "nce, with no previous model transcript or reproducer concl"
        "usion narrative.\n\nHost creates a recipe-owned clean deta"
        "ched baseline worktree under the run's scratch/worktrees a"
        "rea rather than trust the caller working tree. Verify its "
        "HEAD equals the original baseline and read/verify pinned r"
        "oot guidance before target commands. Rerun identical compi"
        "le argv for compile failures; runtime rebuilds using origi"
        "nal build_argv and reruns unchanged manifested PoC plus al"
        "l planned scoped cases and valid controls using the same c"
        "ommand specification. PoC path/bytes must be preserved; an"
        "y necessary absolute path normalization is host-fixed to t"
        "he retained identical source, not worker-derived. Capture "
        "raw stdout, stderr, status, timing, and argv/cwd in valida"
        "te/receipts. Runtime confirmation requires trustworthy PAT"
        "CH_LOADED matching that baseline artifact/hash, exact fina"
        "l PATCH_REACHED and assertion/observations for the claim; "
        "compile confirmation requires actual nonzero compiler resu"
        "lt with the exact expected_diagnostic and no setup failure"
        ". A trustworthy observation showing the bug absent can be "
        "not_confirmed; missing markers, crashes, timeout, setup fa"
        "ilures or inconsistent scoped observations are inconclusiv"
        "e.\n\nOnly then call the read-only fresh worker to indepen"
        "dently assess whether exact invariant/claim is demonstrate"
        "d by the rerun raw receipts. Host evidence gates must domi"
        "nate worker-confirmed; no synthetic rerun evidence or prov"
        "ider capability adapter. Persist validate.json exactly sch"
        "ema_version1: outcome confirmed/not_confirmed/inconclusive"
        ", agent different from reproducer, reason<=400. Do not edi"
        "t finding.json or the reproduction package or repair a PoC"
        " to make it work. Hash-check originals after rerun, manife"
        "st the complete validation dir, run records check, and ret"
        "urn outcome plus retained receipt paths. Remove only recip"
        "e-created temporary worktrees; never reset/delete caller c"
        "hanges. No patch/proof records.\n\n\nUse only portable rep"
        "layed commands against the owned baseline worktree: host-r"
        "esolve the artifact independently as worktree/reproduce.ta"
        "rget_artifact. Never execute/load an absolute target artif"
        "act in the caller original checkout. Retained PoC source r"
        "emains unchanged at an absolute path under the external ru"
        "n directory; cwd-relative target artifact/build inputs fol"
        "low the owned baseline worktree. Reject a nonportable orig"
        "inal target-artifact selector with actual diagnostics; do "
        "not silently validate the original checkout's stale build."
        " Do not read or expose reproducer assessment.json, model r"
        "eview summaries, transcript or conclusion to the independe"
        "nt worker; construct a fresh bounded packet of claim/invar"
        "iant, pinned guidance, unchanged source and actual raw com"
        "mand receipts only. Follow updated strict Ruff and bytecod"
        "e-disabled helper requirements. Expected worker/provider e"
        "rrors can retain raw AgentError diagnostics and produce ho"
        "nest inconclusive output; budget exhaustion and unrelated "
        "failures still propagate.\n\n\nFocused source review of th"
        "e retained compiled candidate found concrete compatibility"
        " bugs; preserve its substantive owned-baseline replay and "
        "blinded packet, repair these narrowly. (1) The generated r"
        "eproduce-bug package writes ordered raw scoped receipts as"
        " reproduce/receipts/case-0.stdout/.stderr/.exit.json, case"
        "-1.*, etc.; each exit metadata has argv/cwd/exit_code/erro"
        "r/elapsed_ms, and manifest-covered reproduce/receipts/comm"
        "ands.json is {baseline,build,commands:[argv0,argv1,...]} i"
        "n finding.repair_scope.cases order. Your candidate instead"
        " requires <check_id> receipt names, so ordinary valid gene"
        "rated packages cannot validate. Support this actual ordere"
        "d index layout, verifying manifest-covered source receipts"
        " and metadata/commands agree and provide exactly one uncha"
        "nged-harness command per declared case; retaining explicit"
        " check_id metadata/names as a compatible alternative is fi"
        "ne. Never infer a zero-case success or invent original obs"
        "ervations. Do not require another unmerged recipe. (2) Fre"
        "eze the actual runtime artifact SHA-256 after successful b"
        "aseline build, then require the artifact stays regular and"
        " identical for primary PoC and every scoped input. Current"
        "ly healthy() recomputes whatever artifact exists each time"
        ", allowing a mutated artifact to masquerade as the built b"
        "aseline. After replay and before confirming, require owned"
        " baseline worktree HEAD remains baseline and no tracked so"
        "urce/index diff appeared; retain raw Git receipts. Also ca"
        "pture/verify caller checkout HEAD/status before/after with"
        "out resetting caller changes. (3) Use actual native record"
        "s.repair_scope_gaps(finding.repair_scope), or equivalent n"
        "ative bound/exact cardinality/control/distinct-input check"
        "s, before executing commands; nonempty cases alone do not "
        "prove the required scope. Preserve distinct validator iden"
        "tity, unchanged original package digests and worker packet"
        " excluding previous model conclusions. (4) Seven actual Ru"
        "ff RUF005 failures at lines183,326,327,353,411,412,413 are"
        " concatenations of UV/git/helper lists; use iterable unpac"
        "king, not noqa/config changes. Preserve strict complexity8"
        "/maxargs5 and bytecode-disabled helpers. Existing dry-run "
        "blocked/unverified is honest and accepted; do not remove r"
        "epo/run guards. Keep model values out of all native select"
        "or contexts.\n\n\nLatest retained candidate source review:"
        " the ordered original receipt bridge, native scope validat"
        "ion, frozen artifact digest, owned baseline/caller immutab"
        "ility and blinded final review are now substantive and mus"
        "t be preserved. One narrow source-contract repair is requi"
        "red: BEFORE any target build/PoC/scoped command, run a fre"
        "sh READ-ONLY semantic preflight worker gate over the full "
        "pinned root guidance, claim/invariant/scope, unchanged ret"
        "ained harness source and the exact host-computed build/PoC"
        "/case argv. Reading guidance on the host and reviewing onl"
        "y afterward cannot apply its natural-language restrictions"
        " before target work. This call can reject an unsafe/incomp"
        "atible command plan and give a bounded reason, but must ne"
        "ver modify/select argv, files, path selectors or git objec"
        "ts. Use the same declared worker role/provider/filesystem "
        "restrictions; budget already allows two calls. Keep its mo"
        "del result separate from native s selector dictionaries. I"
        "f it declines or has a provider RuntimeError, persist its "
        "actual reason/diagnostic at a fixed host-owned audit path "
        "and return an honest inconclusive validation with no claim"
        "ed target rerun, not confirmed. The final fresh independen"
        "t worker packet must still contain only blinded claim/inva"
        "riant/guidance, unchanged sources and actual rerun receipt"
        "s: do not add reproducer narrative/transcript/assessment o"
        "r preflight model conclusions. Preflight and postflight ca"
        "n share a typed shape or use a small typed plan-approval o"
        "bject. Catch only expected RuntimeError around worker call"
        "s if retaining provider diagnostics; BudgetExceeded/unrela"
        "ted failures still propagate. No always-blocked fallback f"
        "or approved commands. Four actual Ruff C408 failures at li"
        "nes101,176,258,386 use dict(key=value) where a dict litera"
        "l is required. Fix those and preserve all strict Ruff rule"
        "s, no suppressions/config edits. Existing BRIDGE literal s"
        "yntax was compiled successfully; preserve it or keep it sy"
        "ntactically valid.\n\n\nNARROW FINAL REPAIR to retained su"
        "bstantive compiled source (strict Ruff currently PASSES; B"
        "RIDGE and GATE fixed literal Python syntax both compile). "
        "Preserve existing complete native behavior, interfaces, gu"
        "ards and new preflight; no broad rewrite. (1) Root source "
        "review found a packet omission: authoritative SKILL step1 "
        "requires the complete schema finding plus original reprodu"
        "ction proof commands/PoC and raw receipts. review() curren"
        "tly gives only claim/invariant/repair_scope and lacks orig"
        "inal raw observations. Both preflight and final independen"
        "t review must receive the full schema-validated finding (n"
        "ot a reduced subset), the original actual manifest-covered"
        " raw build and case-N stdout/stderr/.exit.json command met"
        "adata, and commands.json. Select only fixed expected raw r"
        "eceipt names already established by the ordered package an"
        "d present optional build receipt files; require every orig"
        "inal case tuple; runtime build receipts should be included"
        ". Keep the exact proof type/baseline/expected diagnostic a"
        "nd unchanged harness bytes. Exclude assessment.json, repro"
        "ducer model review/conclusions/transcript and reproduce.js"
        "on observed/blocker prose. Use bounded selected files or a"
        " host-constructed context packet; NEVER expose the whole r"
        "un/reproduce root as worker cwd/readable scope. Full findi"
        "ng.reported is caller source evidence and must be preserve"
        "d. Keep fresh isolated preflight and postflight contexts; "
        "postflight must not read preflight model conclusions. No w"
        "orker-derived selector, argv or native-context mutation. ("
        "2) New GATE bridge passes json.dumps(data) containing ever"
        "y build/PoC/case stdout/stderr as a single argv item. Real"
        " verbose builds can exceed platform ARG_MAX and break othe"
        "rwise valid validation. Preflight a fixed host-owned scrat"
        "ch/audit/native-gate-input.json destination, write the nat"
        "ive data with write_json, and pass only that host-fixed JS"
        "ON file path into the fixed bridge. GATE should read JSON "
        "from that file with Path(...).read_bytes/read_text. The br"
        "idge remains a genuine read-only Python-B assessment; keep"
        " all raw output files and native hash/loader/final marker/"
        "case assertions. Preserve all strict Ruff rules, real exec"
        "ution/cleanup, distinct identity and evidence digests; do "
        "not handwave semantic proof or create an always-blocked fa"
        "llback. Return COMPLETE valid module source.\n"
    ),
    "sha256": ("687919f1e71431e65767ff2dba96998227032d1563f4b1a245cc7d587c71da45"),
}
_CALCIFIER_SUBRECIPES = []
