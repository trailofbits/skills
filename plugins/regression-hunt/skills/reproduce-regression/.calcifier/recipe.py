# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import hashlib
import json
import shlex
from pathlib import Path
from typing import Any, Literal

import calcifier as c

UV = ["uv", "run", "--no-project", "python", "-B"]
DATA = ("poc.py", "workload.json", "configuration.json")
CHECK = """
import json,sys;from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1]).parent));import registry as r
p=Path(sys.argv[2]);aid=sys.argv[3];d=r.load(p);a=r.assigned(d,aid);q=r.require
q(a['id']==aid and a['stage']=='reproduce' and a['agent'],'Invalid bound assignment')
q(a['directory']=='attempts/'+aid and a['state'] in ('running','accepted'),'Inactive')
r.local(p,a['directory']);r.verify_receipt(p,a['launch']);v=a['verification']
q(v in ('isolated','shared-host') and r.receipt_level(a)==v,'Invalid verification')
f=r.agent_binding if v=='shared-host' else r.host_binding
q(f(p,d,a,a['agent'],a['launch']['record'])==a['launch'],'Invalid launch binding')
r.distinct_candidate_agent(d,a,a['agent']);o={'a':a}
try:
 r.candidate_input(d,a);r.prerequisite_changes(p,a['change'],a['inputs'])
 q(r.changes_by_id(r.read(p,d['scope']['file'])['changes'])==d['scope']['changes'],'Scope')
 q(r.inputs_snapshot(p,a['inputs'])==a['input_hashes'],'Changed assigned inputs')
 rs={n:r.accepted(p,n) for n in a['inputs'] if r.local(p,n+'.seal.json').is_file()}
 ps,hs=([(n,z) for n,z in rs.items() if z['stage']==t] for t in ('prepare','hunt'))
 q(len(ps)==len(hs)==1,'Accepted preparation/discovery required');(pn,b),(hn,h)=ps[0],hs[0]
 s=b['source'];cp=d['candidates'][a['candidate']]['file'];z=r.read(p,s)
 q(b['status']==h['status']=='complete' and pn in h['inputs'],'Blocked prerequisites')
 q(s in r.read(p,pn+'.seal.json')['artifacts'],'Unsealed source')
 q(h['candidate_files'][a['candidate']]==cp,'Candidate handoff')
 q(z['repository'] and z['s0']!=z['s1'] and a['change'] in d['scope']['changes'],'Boundary')
 q(all(len(z[k]) in (40,64) and int(z[k],16)>=0 for k in
       ('s0','s1','tree0','tree1')),'Full revision/tree IDs required')
 todo=list(rs);seen=set();fs=set(a['input_hashes'])
 for n in todo:
  if n not in seen:
   seen.add(n);m=r.read(p,n+'.seal.json');fs.update(m['inputs']|m['artifacts'])
   fs.update((n,n+'.seal.json'));todo.extend(m['dependencies'])
 ex=[str(Path(s).parent/t) for t in ('S0','S1')];g={}
 for n in ('AGENTS.md','PATCHING_GUIDELINES.md','THREAT_MODEL.md'):
  f=f"guidance/{a['change']}/{z['s1']}/{n}";old=ex[1]+'/'+n;t=r.local(p,old).exists()
  q(not t or (f in a['input_hashes'] and r.digest(r.local(p,f))==
              r.digest(r.local(p,old))),'Unaccounted guidance');g[n]=f if t else None
 q(all(r.files(p,[e]) and set(r.files(p,[e]))==
       {f for f in fs if f.startswith(e+'/')} for e in ex),'Incomplete sealed exports')
 o.update(source=s,pinned=z,exports=ex,guidance=g,files=sorted(fs),candidate=cp)
except (OSError,ValueError,KeyError,TypeError) as e: o['error']=str(e)
print(json.dumps(o))
"""
CAPTURE = """
import json,os,signal,subprocess,sys
argv,cwd,stem,limit=json.loads(sys.argv[1]),sys.argv[2],sys.argv[3],float(sys.argv[4])
v={'exit_code':None,'timeout':False}
with open(stem+'.stdout','xb') as out,open(stem+'.stderr','xb') as err:
 try:
  p=subprocess.Popen(argv,cwd=cwd,stdout=out,stderr=err,start_new_session=True,
    env={**os.environ,**json.loads(sys.argv[5])});v['pid']=p.pid
  try: v['exit_code']=p.wait(timeout=limit)
  except subprocess.TimeoutExpired:
   v['timeout']=True
   try: os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError: pass
   v['exit_code']=p.wait()
 except OSError as error: v['error']=str(error)
print(json.dumps(v))
"""
COPY = "import json,shutil,sys\nfor s,t in json.loads(sys.argv[1]): shutil.copytree(s,t)\n"


@c.output_type
class Command:
    state: Literal["S0", "S1"]
    phase: Literal["metadata", "setup", "build", "deploy", "cleanup", "resources"]
    argv: list[str]
    timeout: float


@c.output_type
class Plan:
    authorized: bool
    mode: Literal["live", "build_test"]
    commands: list[Command]
    poc_argv: list[str]
    timeout: float
    deployments: list[str]
    data: dict[str, str]
    environment: dict[str, str]
    outputs: list[str]


@c.output_type
class Review:
    security_review: str
    analysis: str
    blocker: str
    behaviors: list[Literal["correct", "failure", "unknown"]]
    citations: list[int]


@c.output_type
class Result:
    status: Literal["complete", "blocked"]
    record: str
    result: str
    blocker: str


def checked(script: str, args: list[str], mutating: bool = False) -> str:
    value = c.run_command(
        [*UV, str(c.resource(script)), *args], timeout_seconds=120, mutating=mutating
    )
    if value.exit_code:
        c.fail(f"Helper exited {value.exit_code}: {value.stderr}\n{value.stdout}")
    return value.stdout


def diagnostic(error: Exception) -> str:
    if type(error).__name__ in ("BudgetExceeded", "UnmaterializedArtifactError"):
        raise error
    return f"{type(error).__name__}: {error}"


def hashes(h: dict[str, Any]) -> dict[str, str]:
    return {f: hashlib.sha256((h["out"] / f).read_bytes()).hexdigest() for f in DATA}


def assess(h: dict[str, Any], prior: str) -> tuple[Review | None, str]:
    root, out, info = h["root"], h["out"], h["info"]
    paths = sorted(
        {
            *info.get("files", []),
            *(
                p.relative_to(root).as_posix()
                for p in out.rglob("*")
                if p.is_file() and not p.is_symlink()
            ),
        }
    )
    refs = tuple(
        c.resource(p)
        for p in (
            "docs/regression-definition.md",
            "references/evidence.md",
            "docs/report-definitions.md",
        )
    )
    guidance = tuple(root / p for p in info.get("guidance", {}).values() if p)
    try:
        context = c.prepare_context(
            "Assess the assigned reproduction using the original workflow.",
            prior_results=json.dumps(
                {"info": info, "evidence": list(enumerate(paths)), "prior": prior}
            ),
            files=(*refs, *guidance),
            readable_roots=(root, *refs),
        )
        answer = c.agent(
            "worker",
            "Read complete pinned guidance, candidate and frozen sources. "
            "Review the whole package, authorized plan, supported interfaces, security scope, "
            "comparability and false positives. Before execution return unknown behaviors. "
            "Afterward interpret actual ordered S0/S1 logs and owned resource disposition; "
            "unknown disposition is a blocker. Build/test mode concerns its supported workflow. "
            "Cite enumerated evidence IDs. Never confirm a regression or invent observations.",
            working_directory=out,
            readable_paths=tuple(root / p for p in paths),
            context=context,
            output=Review,
            timeout=3600,
        )
        if (
            len(answer.behaviors) != 2
            or not all((answer.security_review, answer.analysis, answer.citations))
            or any(i < 0 or i >= len(paths) for i in answer.citations)
        ):
            raise ValueError("Incomplete assessment or invalid evidence IDs")
        return answer, answer.blocker
    except (RuntimeError, c.RecipeError, OSError, ValueError) as error:
        return None, diagnostic(error)


def execute(
    h: dict[str, Any], argv: list[str], task: tuple[int, str, str, float]
) -> dict[str, Any]:
    index, state, phase, limit = task
    out, plan = h["out"], h["plan"]
    for token, value in {
        "{poc}": str(out / DATA[0]),
        "{workload}": str(out / DATA[1]),
        "{deployment}": plan.deployments[state == "S1"],
    }.items():
        argv = [v.replace(token, value) for v in argv]
    stem, cwd = out / f"command-{index}", out if phase == "copy" else out / "build" / state
    value = {
        "state": state,
        "phase": phase,
        "argv": argv,
        "command": shlex.join(argv),
        "cwd": str(cwd),
        "log": stem.relative_to(h["root"]).as_posix() + ".json",
        "diagnostics": [],
    }
    try:
        result = c.run_command(
            [
                *UV,
                "-c",
                CAPTURE,
                json.dumps(argv),
                str(cwd),
                str(stem),
                str(limit),
                json.dumps(plan.environment),
            ],
            timeout_seconds=limit + 20,
            working_directory=out,
            mutating=True,
        )
        value["capture"] = {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        if result.exit_code or not result.stdout.strip():
            raise ValueError("Capture failed or produced no materialized observation")
        value.update(json.loads(result.stdout))
    except (c.RecipeError, OSError, ValueError) as error:
        value["diagnostics"].append(diagnostic(error))
        value["command_failure"] = getattr(error, "command_failure", None)
    try:
        value["hashes"] = hashes(h)
    except (OSError, ValueError) as error:
        value["diagnostics"].append(diagnostic(error))
    try:
        c.write_json(stem.with_suffix(".json"), value)
    except (c.RecipeError, OSError, ValueError) as error:
        value["diagnostics"].append(diagnostic(error))
    return value


def failed(v: dict[str, Any]) -> bool:
    return bool(
        v.get("error")
        or v["diagnostics"]
        or v.get("timeout")
        or v.get("exit_code") is None
        or (v["phase"] != "run" and v["exit_code"] != 0)
    )


def cleanup(h: dict[str, Any], obs: list[dict[str, Any]], errors: list[str]) -> None:
    for i, x in sorted(enumerate(h["plan"].commands), key=lambda p: p[1].phase != "cleanup"):
        if x.phase in ("cleanup", "resources"):
            obs.append(execute(h, x.argv, (i + 1, x.state, x.phase, x.timeout)))
            if failed(obs[-1]):
                errors.append("Cleanup/resource inspection failed: " + obs[-1]["log"])


def state_tasks(
    h: dict[str, Any], obs: list[dict[str, Any]], state: str, frozen: dict[str, str]
) -> None:
    plan = h["plan"]
    tasks = [
        (i + 1, x.phase, x.argv, x.timeout)
        for i, x in enumerate(plan.commands)
        if x.state == state and x.phase not in ("cleanup", "resources")
    ]
    for i, phase, argv, limit in [
        *tasks,
        (len(plan.commands) + 1 + (state == "S1"), "run", plan.poc_argv, plan.timeout),
    ]:
        obs.append(execute(h, argv, (i, state, phase, limit)))
        if failed(obs[-1]) or obs[-1].get("hashes") != frozen:
            raise ValueError(f"{state} {phase}: unfinished or changed immutable data")


def experiment(h: dict[str, Any], obs: list[dict[str, Any]], errors: list[str]) -> None:
    try:
        frozen = hashes(h)
        copies = [
            (str(h["root"] / e), str(h["out"] / "build" / state))
            for state, e in zip(("S0", "S1"), h["info"]["exports"], strict=True)
        ]
        obs.append(execute(h, [*UV, "-c", COPY, json.dumps(copies)], (0, "S0", "copy", 120)))
        if failed(obs[-1]):
            raise ValueError("Source copy failed; inspect command-0.json")
        for state in ("S0", "S1"):
            state_tasks(h, obs, state, frozen)
    except (c.RecipeError, OSError, ValueError) as error:
        errors.append(diagnostic(error))
    finally:
        cleanup(h, obs, errors)


def prepare(h: dict[str, Any]) -> list[str]:
    plan, info = h["plan"], h["info"]
    names = {
        *plan.outputs,
        *DATA,
        "setup.json",
        "analysis.json",
        "observations.json",
        "disposition.json",
        "reproduce.json",
        "reproduce.json.seal.json",
    }
    names.update(
        f"command-{i}.{ext}"
        for i in range(len(plan.commands) + 3)
        for ext in ("json", "stdout", "stderr")
    )
    names.update(
        f"build/{state}/{f[len(e) + 1 :]}"
        for state, e in zip(("S0", "S1"), info.get("exports", []), strict=False)
        for f in info.get("files", [])
        if f.startswith(e + "/")
    )
    c.ensure_directory(info["a"]["directory"], output_files=tuple(sorted(names)))
    for f in DATA:
        c.write_text(h["out"] / f, plan.data.get(f, ""))
    c.write_json(h["out"] / "setup.json", plan.model_dump())
    required = ("metadata", "setup", "build", "cleanup", "resources")
    required = (*required, "deploy") if plan.mode == "live" else required
    valid = (
        plan.authorized
        and len(plan.deployments) == 2
        and all(plan.deployments)
        and plan.timeout > 0
        and all(plan.data.get(f) for f in DATA)
        and all(x.argv and x.timeout > 0 for x in plan.commands)
        and all(any(t in v for v in plan.poc_argv) for t in ("{poc}", "{workload}", "{deployment}"))
        and all(
            any(x.state == s and x.phase == p for x in plan.commands)
            for s in ("S0", "S1")
            for p in required
        )
    )
    return (
        [info["error"]] if info.get("error") else ([] if valid else ["Incomplete authorized plan"])
    )


def finish(h: dict[str, Any], obs: list[dict[str, Any]], errors: list[str], prior: str) -> None:
    root, out, info = h["root"], h["out"], h["info"]
    c.write_json(out / "observations.json", obs)
    c.write_json(
        out / "disposition.json", [v for v in obs if v["phase"] in ("cleanup", "resources")]
    )
    after, error = assess(h, prior + json.dumps(obs)) if obs else (None, "No experiment executed")
    errors.extend([error] if error else [])
    runs = [
        {
            **v,
            "revision": info["pinned"][v["state"].lower()],
            "deployment": h["plan"].deployments[v["state"] == "S1"],
            "behavior": after.behaviors[v["state"] == "S1"] if after else "unknown",
        }
        for v in obs
        if v["phase"] == "run"
    ]
    if len(runs) != 2 or any(p.is_symlink() for p in out.rglob("*")):
        errors.append("Incomplete S0/S1 experiment or symlink evidence; caller action required")
    c.write_json(
        out / "analysis.json",
        {"before": prior, "after": after.model_dump() if after else None, "errors": errors},
    )
    summary = "; ".join(f"{r['state']} {r['behavior']} ({r['log']})" for r in runs)
    a = info["a"]
    c.write_json(
        out / "reproduce.json",
        {
            "stage": "reproduce",
            "agent": a["agent"],
            "attempt": a["id"],
            "change": a["change"],
            "candidate": a["candidate"],
            "inputs": a["inputs"],
            "source": info.get("source"),
            "runs": runs,
            "status": "blocked" if errors else "complete",
            "blocker": "; ".join(errors),
            "summary": summary or "No S0/S1 runs; inspect observations.json and analysis.json.",
            "security_review": after.security_review
            if after
            else "Unverified; inspect analysis.json",
            "setup": a["directory"] + "/setup.json",
            "poc": a["directory"] + "/poc.py",
            "workload": a["directory"] + "/workload.json",
            "build_dirs": sorted(
                p.relative_to(root).as_posix()
                for p in out.rglob("*")
                if p.is_dir() and not p.is_symlink()
            ),
            "artifacts": sorted(
                p.relative_to(root).as_posix()
                for p in out.rglob("*")
                if p.is_file() and not p.is_symlink()
            ),
        },
    )


@c.recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    output_root=".",
    budget=c.Budget(max_agent_calls=4, max_wall_seconds=3600),
)
def reproduce(campaign: str, attempt: str, plan: Plan) -> Result:
    root = Path(campaign).resolve(strict=True)
    probe = c.run_command(
        [*UV, "-c", CHECK, str(c.resource("scripts/registry.py")), str(root), attempt],
        timeout_seconds=120,
        mutating=False,
    )
    if probe.exit_code:
        c.fail(f"Invalid assignment: {probe.exit_code}: {probe.stderr}\n{probe.stdout}")
    info = json.loads(probe.stdout)
    out, name = root / info["a"]["directory"], info["a"]["directory"] + "/reproduce.json"
    new = not (root / name).exists()
    if new:
        if info["a"]["state"] != "running" or (out.exists() and any(out.iterdir())):
            c.fail("Attempt is not fresh; request a new bound assignment")
        if c.ensure_directory(".", output_files=()).resolve() != root:
            c.fail("Set the recipe output directory to the supplied campaign")
        h = {"root": root, "out": out, "info": info, "plan": plan}
        errors, obs = prepare(h), list[dict[str, Any]]()
        if not (out / "setup.json").is_file():
            c.fail("Unmaterialized dry-run artifacts; no execution or verification claimed")
        before, error = assess(h, "") if not errors else (None, "")
        errors.extend([error] if error else [])
        if not errors:
            experiment(h, obs, errors)
        finish(h, obs, errors, before.model_dump_json() if before else "Assessment unavailable")
    for action in ("seal", "verify", "check") if new else ("verify", "check"):
        checked(
            "scripts/registry.py" if action == "check" else "scripts/evidence.py",
            [action, str(root), *([attempt] if action == "check" else []), name],
            action == "seal",
        )
    saved = json.loads((root / name).read_text(encoding="utf-8"))
    return c.emit(Result(saved["status"], name, saved["summary"], saved.get("blocker", "")))


if __name__ == "__main__":
    raise SystemExit(reproduce.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("a78302aebe220778ed35ca27f78f03316fd44fbba1aa819743c512f9847ecfbe"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "docs/regression-definition.md",
        "sha256": ("118e1a2cbb02a73a6e6683bd1e0194be0f7933238bf4fe49c85b20d256863542"),
        "size": 3718,
        "source": "../../docs/regression-definition.md",
    },
    {
        "path": "docs/report-definitions.md",
        "sha256": ("fc407c45bd826d7bd390b29c453f9a3cb0ae962564b41ce3d24d95790a25904d"),
        "size": 2538,
        "source": "../../docs/report-definitions.md",
    },
    {
        "path": "docs/system-flow.md",
        "sha256": ("de9b347ea2c8a9294a0bf8a6d788859247224727c867804f1de7b7deac15f94c"),
        "size": 2640,
        "source": "../../docs/system-flow.md",
    },
    {
        "path": "examples/request.md",
        "sha256": ("1b8c355558ecccd95c4912e31fd95b26b07271e286ded15a02d556c20a6a6983"),
        "size": 969,
        "source": "../../examples/request.md",
    },
    {
        "path": "references/evidence.md",
        "sha256": ("0eadbef231d7234e1c11997c0760598ffcceb4fa58eb8d5ff4278f4d19c49cc4"),
        "size": 16272,
        "source": "../../references/evidence.md",
    },
    {
        "path": "scripts/evidence.py",
        "sha256": ("f8c3bdd09acbce994436fed45a4cdf834d119e6bd359b406227b8cd18b877a5a"),
        "size": 4891,
        "source": "../../scripts/evidence.py",
    },
    {
        "path": "scripts/registry.py",
        "sha256": ("065f14123472ca07474c6b46591852ac71f2e9427b64c35b3c144f8084a54795"),
        "size": 23690,
        "source": "../../scripts/registry.py",
    },
    {
        "path": "scripts/report.py",
        "sha256": ("f062f018265d4b2b84c2b5f563a116c05c2bc59c61fce1c889386f01595e3705"),
        "size": 16096,
        "source": "../../scripts/report.py",
    },
    {
        "path": "scripts/runtime.py",
        "sha256": ("05c742dad0a6ab7ede53d812f4cd61c918f91d7837a5e1f6bda586a423735c89"),
        "size": 7678,
        "source": "../../scripts/runtime.py",
    },
    {
        "path": "scripts/snapshot.py",
        "sha256": ("6371624b39b918b44fc92d2118d67e2abd1748ab6c77b7e80033e6e62d97e6ef"),
        "size": 6903,
        "source": "../../scripts/snapshot.py",
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
        "pleted inspection that finds zero issues.\n\nImplement thi"
        "s one assigned stage as native host Python control flow us"
        "ing the actual pinned helpers. Do not emit a single model "
        "call asking it to run the whole workflow. Producing agent "
        "calls have a read-only filesystem: return analysis/code as"
        " typed data, then host Python persists it only to host-der"
        "ived designated paths. Runtime build, deployment, PoC, cle"
        "anup and metadata-collection commands may be explicit user"
        "-supplied argv/plan inputs; do not execute tainted model-p"
        "roduced argv or use fictional platform adapters. Host run_"
        "command invocations use accurate mutating flags: Git reads"
        "/verify/check are read-only, snapshot/seal/report/candidat"
        "e reservation/build/run/cleanup write. Preserve real exit "
        "codes, stderr, timeouts and partial logs; command errors a"
        "re not empty success. No source execution during generatio"
        "n/dry runs.\n\nRequire a campaign path and exact caller-su"
        "pplied registry assignment/attempt identifier. Read and va"
        "lidate the actual registry.json, frozen scope/hash, stage/"
        "change/candidate/agent/directory/inputs/input_hashes/state"
        " and retained launch evidence; derive allowed source/recor"
        "d selectors and all output names from trusted assignment/p"
        "ackage records. A worker may cite host-enumerated evidence"
        " IDs, not choose arbitrary read/write/command paths. Valid"
        "ate campaign-relative confinement and reject symlink evide"
        "nce. Never invent a launch handle, fresh-context/isolation"
        " receipt or verification level. Caller supplies genuinely "
        "bound assignments; absent/invalid binding blocks the stage"
        ". Use the original registry/evidence/runtime helper semant"
        "ics, not hand-written lookalike receipts. The registry hel"
        "per is version 3 even though part of the prose still says "
        "version 2.\n\nBefore target work verify sealed prerequisit"
        "e packages, assigned hashes and full artifact trees, then "
        "read/apply pinned target-S1 AGENTS.md, PATCHING_GUIDELINES"
        ".md and THREAT_MODEL.md, accounting for each as copied-and"
        "-hash-checked or explicitly absent; fetch unaccounted file"
        "s from immutable Git objects or block. Provide the full gu"
        "idance contents to producing workers. Do not claim securit"
        "y review from filenames alone. Use frozen sources/context;"
        " later fixes/advisories/reviews are excluded from investig"
        "ation.\n\nEach stage owns only its assigned attempt direct"
        "ory. Never overwrite sealed attempts; on intact reusable r"
        "ecords verify and return them, otherwise require a new ass"
        "ignment. Produce the exact stage JSON with assigned identi"
        "ty, exact inputs, status complete/blocked, summary, securi"
        "ty_review and complete artifacts. Seal with evidence.py se"
        "al CAMPAIGN RECORD, verify with evidence.py verify, and re"
        "gistry.py check CAMPAIGN ATTEMPT RECORD before reporting. "
        "Only the coordinator accepts assignments and changes campa"
        "ign.json/progress/receipts: this component must not accept"
        " records, bind/retry agents, rewrite scope/index or fabric"
        "ate host observations. Blockers preserve actual collected "
        "evidence and exact missing prerequisites; completion never"
        " means regression confirmation. Helpers use uv run --no-pr"
        "oject <resource('scripts/NAME.py')> with their actual CLI "
        "argument order; pinned sibling helper files must remain av"
        "ailable. A nonempty investigation scope is required, while"
        " an inspected scope with zero candidates is valid.\n\nOwn "
        "one real reproduction attempt for the assigned candidate. "
        "Require accepted sealed preparation/discovery/candidate in"
        "puts and source.json from preparation. Read actual candida"
        "te details, pinned source, security guidance and prerequis"
        "ites before any target execution. Native host mechanics mu"
        "st build and run actual S0 and S1 through supported interf"
        "aces, including dependencies/services or the supported bui"
        "ld workflow for BUILD_TEST cases. Do not return a harness "
        "that merely asks a model whether a test would pass, and do"
        " not use mocks, extracted helper functions, simulated syst"
        "ems or artificially granted attacker privilege as proof.\n"
        "\nExpose explicit user-authorized structured S0/S1 setup/b"
        "uild/deploy/run/cleanup argv inputs and comparable environ"
        "ment/workload configuration where necessary. Resolve cwd/s"
        "tate choices against host-derived per-attempt build direct"
        "ories; model output may propose PoC source as DATA, but on"
        "ly the host persists it to a fixed PoC path and executes a"
        "n explicit authorized command plan. Never run agent-produc"
        "ed shell text/argv. Copy pristine exports into fresh separ"
        "ate build locations under this attempt; never mutate expor"
        "ts or another attempt/shared build. List EVERY build/deplo"
        "yment directory in build_dirs. Retain source revisions/tre"
        "e identity and tool/dependency versions, sanitized config,"
        " service setup and ownership. Missing authorization/prereq"
        "uisites yields a sealed blocked record with attempted setu"
        "p, not fictional execution.\n\nExecute ONE portable PoC/in"
        "put against BOTH actual live deployments with comparable c"
        "onfiguration. Inputs may select deployment addresses witho"
        "ut embedding revision-specific behavior in the workload. K"
        "eep unchanged PoC/workload hashes during both runs. Captur"
        "e separate nonempty raw stdout/stderr and real exit/timeou"
        "t results, exact argv/commands, versions, revision, deploy"
        "ment/interface and observations; a nonzero PoC exit may be"
        " the observed failure, so preserve it instead of losing th"
        "e logs. Native independent assessment may interpret real h"
        "ost logs plus source to label behavior correct/failure/unk"
        "nown, but cannot invent logs or treat command success alon"
        "e as proof. Check supported-interface reachability and fal"
        "se positives and retain unresolved observations honestly."
        "\n\nWrite reproduce.json stage='reproduce', assigned candi"
        "date, source same frozen source path, setup/poc/workload p"
        "aths and runs in exact S0,S1 order. Each run has state, fu"
        "ll revision, actual deployment, exact executed command, se"
        "parate campaign-relative log and observed behavior. Includ"
        "e all immutable PoC dependencies/input/config/setup/logs i"
        "n artifacts. Status complete means experiment finished eve"
        "n if no differential failure; blockers may have runs=[] an"
        "d retain attempted execution. Track and release actual tem"
        "porary processes/services/locks with host cleanup commands"
        ", preserve evidence, record disposition before seal/verify"
        "/registry check. Return observed before/after behavior, no"
        "t confirmation.\n\nCompilation context clarification after"
        " the provider declined the first call: this request only c"
        "ompiles the generic regression-assessment SKILL.md and its"
        " existing evidence helpers into an auditable Python recipe"
        ". No target repository, vulnerable system, exploit, attack"
        " deployment or live experiment is supplied or requested he"
        "re, and no generated recipe is to be executed or trusted d"
        "uring this task. Runtime execution remains conditioned on "
        "explicit caller authorization and the original evidence/se"
        "curity contracts. Preserve those contracts in the source t"
        "ranslation; do not invent execution results or return a wo"
        "rkflow-delegating baseline as an implementation. Use the s"
        "ame provider and access settings.\n\n\nFocused repair of t"
        "he substantive compiled candidate (reviewed native behavio"
        "r): preserve the candidate's full bound-assignment/source/"
        "prerequisite validation, caller-authorized typed Plan, imm"
        "utable host-persisted PoC/workload/configuration, private "
        "copies, observations with raw command streams, ordered S0/"
        "S1 experiments, independent read-only pre/post assessments"
        ", cleanup and sealed record protocol. Do not replace these"
        " with agent delegation.\n\n1. The plugin-local Ruff config"
        "uration is mandatory, beyond portable Calcifier lint: Ruff"
        " 0.14.13, target py313, line-length100; select E,F,I,UP,B,"
        "SIM,C4,C90,PLR0913,RUF; max-complexity8 and default PLR091"
        "3 argument limit. Current reproduce has C901 complexity25,"
        " RUF005 at list concatenations (166,256,306,315,398), and "
        "C408 at321/381. Decompose native stage control into MODULE"
        "-LEVEL helpers/steps; nested functions count toward their "
        "enclosing function's complexity. Preserve all branches and"
        " evidence. No noqa, suppression, config change, or disable"
        "d check. Use list unpacking and dict literals.\n\n2. Every"
        " pinned original Python helper and inline Python validatio"
        "n/capture/copy wrapper must use the existing UV bytecode-d"
        "isabled interpreter prefix, including CHECK and original r"
        "egistry/evidence helpers. Their sibling imports otherwise "
        "create __pycache__ outside the owned attempt despite mutat"
        "ing=False. Keep actual commands accurately mutating; do no"
        "t alter caller-provided target commands behind the caller'"
        "s back.\n\n3. Ordinary provider/assessment failures must r"
        "etain diagnostics and produce a real blocked sealed record"
        " whenever valid binding/output ownership permits it. Both "
        "before and after assess currently can raise and bypass the"
        " existing retention/sealing path, discarding the ability t"
        "o consume retained raw logs. Handle actual Calcifier provi"
        "der errors: AgentError is a RuntimeError subclass (not top"
        "-level calcifier export); RecipeError is a separate public"
        " class and run_command launch/timeout carries command_fail"
        "ure. Retain stdout/stderr, actual error and partial observ"
        "ations. Do not manufacture an assessment, behavior, build,"
        " successful cleanup, or confirmation after failure. Budget"
        " exhaustion and compiler dry-run unmaterialized-artifact s"
        "uppression must remain honest failures/unverified; do not "
        "swallow them or label suppressed work verified. Keep inval"
        "id/unbound assignment as a hard blocker before any owned w"
        "rites.\n\n4. Ensure finally cleanup keeps attempting the c"
        "aller-authorized owned cleanup/resource inspections after "
        "a partially failing setup/deploy/run and even when diagnos"
        "tic capture/hash observation fails. Retain each actual res"
        "ult; report outstanding resources/unknown disposition as b"
        "locked. Do not allow one failed cleanup to prevent remaini"
        "ng owned cleanup attempts; do not release other workers' r"
        "esources. Preserve evidence files instead of deleting them"
        ".\n\n5. Keep the exact typed Plan interface, required phas"
        "es/protocol, host-derived paths and caller argv. Build/tes"
        "t mode remains a build/test experiment rather than a live "
        "deployment assertion; actual proof gaps stay explicit. All"
        " final summaries must cite observed evidence rather than c"
        "laim confirmation from a model summary.\n\n\nFINAL TWO SMA"
        "LL REPAIRS to the newly reviewed native candidate. Preserv"
        "e its complete behavior, existing typed Plan/protocol, hos"
        "t binding, private source/data copies, exact helper Python"
        " -B prefixes, raw capture and observer hashes, cleanup and"
        " sealed records.\n\n- Pinned local Ruff now reports exactl"
        "y one issue: C901 experiment complexity9>8 at260. Extract "
        "one of its native task/cleanup loops to a MODULE-LEVEL hel"
        "per without changing order, errors, finally cleanup covera"
        "ge or phase observations. No nested helper, suppression, c"
        "onfiguration change, or feature removal.\n- diagnostic() c"
        "urrently rethrows RuntimeError unless type(error).__name__"
        " == AgentError. That incorrectly rethrows actual Transient"
        "AgentError provider timeouts (a subclass of AgentError) an"
        "d bypasses blocked evidence retention. Remove that exact-c"
        "lass-name restriction so ordinary provider RuntimeError su"
        "bclasses are retained as honest diagnostic blockers. Prese"
        "rve propagation of BudgetExceeded and compiler Unmateriali"
        "zedArtifactError; do not relabel a suppressed/unmaterializ"
        "ed dry run or exhausted budget as executed/verified work. "
        "The latter is a RecipeError subclass with its own class na"
        "me; preserve the existing unmaterialized setup.json pre-ex"
        "ecution guard. The AgentError base is not exported at calc"
        "ifier top level, so do not add a nonexistent import.\n\nTh"
        "ese edits require no interface, model, provider, access, j"
        "udgment or workflow changes. Keep all other reviewed candi"
        "date mechanics intact.\n\n\nFinal metadata-only request: t"
        "he complete previous candidate already passed native sourc"
        "e-contract review, portable lint and all strict Ruff rules"
        ". Preserve its entire behavior and typed interface without"
        " changes; return that native module. The host has rephrase"
        "d the earlier interpreter example because wrapped provenan"
        "ce text was falsely detected as a legacy command. Do not c"
        "opy old provenance constants; Calcifier attaches fresh met"
        "adata with this corrected feedback.\n"
    ),
    "sha256": ("bf9af049fb56609ad7d45d368985ada933c7a12b0396ca0ee8bba4b4b5f261db"),
}
_CALCIFIER_SUBRECIPES = []
