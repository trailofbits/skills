# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

from hashlib import sha256
from json import dumps, loads
from pathlib import Path
from shlex import join
from typing import Any, Literal

import calcifier as c


@c.output_type
class Review:
    blocker: str
    result: str
    security_review: str
    released: bool
    reachable: bool
    behaviors: list[Literal["correct", "failure", "unknown"]]
    evidence: list[int]


def respond(state: str, path: str | None, text: str, why: str) -> dict[str, Any]:
    return c.emit({"status": state, "record": path, "result": text, "blocker": why}, name="replay")


def need(value: object, message: str) -> None:
    if not value:
        raise ValueError(message)


def fatal(error: Exception) -> None:
    if type(error).__name__ == "BudgetExceeded":
        raise error


def local(root: Path, name: str) -> Path:
    target = root / (part := Path(name))
    need(bool(part.parts) and not part.is_absolute() and ".." not in part.parts, name)
    need(not any(p.is_symlink() for p in (target, *target.parents)), f"Symlink: {name}")
    return target


def read(root: Path, name: str) -> Any:
    return loads(local(root, name).read_text(encoding="utf-8"))


def command(argv: list[str], cwd: Path, seconds: float, mutating: bool) -> dict[str, Any]:
    try:
        r = c.run_command(argv, working_directory=cwd, timeout_seconds=seconds, mutating=mutating)
        return {"argv": r.argv, "exit_code": r.exit_code, "stdout": r.stdout, "stderr": r.stderr}
    except Exception as error:
        if getattr(error, "command_failure", None) not in ("launch", "timeout"):
            raise
        return {
            "argv": argv,
            "failure": error.command_failure,
            "detail": str(error),
            "stdout": getattr(error, "stdout", None),
            "stderr": getattr(error, "stderr", None),
        }


def helper(root: Path, script: str, args: list[str], mutating: bool = False) -> str:
    result = command(
        [
            "uv",
            "run",
            "--no-project",
            "python",
            "-B",
            str(c.resource(f"scripts/{script}.py")),
            *args,
        ],
        root,
        120,
        mutating,
    )
    need(result.get("exit_code") == 0, dumps(result))
    return result["stdout"]


BINDING = (
    "import json,sys;from pathlib import Path;sys.path.insert(0,str(Path(sys.argv[1]).parent));im"
    "port registry as r;q=r.require;p=Path(sys.argv[2]);d=r.load(p);a=r.assigned(d,sys.argv[3]);r"
    ".verify_receipt(p,a['launch']);r.distinct_candidate_agent(d,a,a['agent']);q(a['verification'"
    "] in r.LEVELS,'Unbound');f=r.host_binding if a['verification']=='isolated' else r.agent_bind"
    "ing;q(f(p,d,a,a['agent'],a['launch']['record'])==a['launch'],'Binding changed');q(r.receipt_"
    "level(a)==a['verification'],'Bad level');r.candidate_input(d,a);q(a['change'] in d['scope']["
    "'changes'] and a['inputs'],'Scope');q(r.inputs_snapshot(p,a['inputs'])==a['input_hashes'],'I"
    "nputs changed');q(r.changes_by_id(r.read(p,d['scope']['file'])['changes'])==d['scope']['chan"
    "ges'],'Scope changed');records={n:r.accepted(p,n) for n in a['inputs'] if r.local(p,n+'.seal"
    ".json').is_file()};print(json.dumps({'a':a,'records':records}))"
)


def assignment(root: Path, attempt: str, handle: str) -> dict[str, Any]:
    result = command(
        [
            "uv",
            "run",
            "--no-project",
            "python",
            "-B",
            "-c",
            BINDING,
            str(c.resource("scripts/registry.py")),
            str(root),
            attempt,
        ],
        root,
        120,
        False,
    )
    need(result.get("exit_code") == 0, dumps(result))
    a = (data := loads(result["stdout"]))["a"]
    need(
        a["id"] == attempt
        and a["stage"] == "replay"
        and a["agent"] == handle
        and handle
        and a["directory"] == f"attempts/{attempt}"
        and a["state"] in ("running", "accepted"),
        "Require exact bound replay assignment",
    )
    return {"root": root, "a": a, "records": data["records"], "own": local(root, a["directory"])}


def prerequisites(s: dict[str, Any]) -> None:
    root, a, known = s["root"], s["a"], s["a"]["input_hashes"]
    records = {v["stage"]: (n, v) for n, v in s["records"].items()}
    need(
        len(records) == len(s["records"]) and set(records) == {"prepare", "hunt", "reproduce"},
        "Require accepted preparation, discovery and reproduction",
    )
    need(
        all(
            set((seal := read(root, n + ".seal.json"))["inputs"] | seal["artifacts"]) <= set(known)
            and v["change"] == a["change"]
            and v["status"] == "complete"
            for n, v in s["records"].items()
        ),
        "Incomplete prerequisite tree or wrong change",
    )
    prep, hunt, repro = (records[k][1] for k in ("prepare", "hunt", "reproduce"))
    need(
        a["candidate"] in hunt["candidates"]
        and repro["candidate"] == a["candidate"]
        and hunt["candidate_files"][a["candidate"]] in a["inputs"]
        and repro["source"] == prep["source"],
        "Wrong candidate or frozen source",
    )
    source = read(root, prep["source"])
    originals = [prep["source"], *(repro[k] for k in ("poc", "workload", "setup"))]
    need(
        all(p in known for p in originals)
        and source["s0"] != source["s1"]
        and all(
            len(source[k]) in (40, 64) and set(source[k]) <= set("0123456789abcdef")
            for k in ("s0", "s1")
        ),
        "Missing originals or full frozen revisions",
    )
    trees, guidance = [str(Path(prep["source"]).parent / v) for v in ("S0", "S1")], {}
    need(all(any(p.startswith(t + "/") for p in known) for t in trees), "Missing source exports")
    for name in ("AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md"):
        original, copy = f"{trees[1]}/{name}", f"guidance/{a['change']}/{source['s1']}/{name}"
        need(not local(root, original).exists() or original in known, "Unaccounted S1 guidance")
        need(copy not in known or known[copy] == known.get(original), "Wrong guidance copy")
        guidance[name] = (
            local(root, original).read_text(encoding="utf-8")
            if original in known
            else "Explicitly absent from complete sealed S1 export."
        )
    s.update(known=known, source=source, trees=trees, guidance=guidance, repro=repro)
    s["base"].update(
        source=prep["source"],
        reproduction=records["reproduce"][0],
        poc=repro["poc"],
        workload=repro["workload"],
    )


def prepare(s: dict[str, Any]) -> None:
    own, plan = s["own"], s["plan"]
    actions = [(v["kind"], v["state"], v["argv"], v["timeout"]) for v in plan["actions"]]
    need(plan["setup"] and plan["access"] and len(plan["interfaces"]) == 2, "Incomplete plan")
    need([v[1] for v in actions if v[0] == "run"] == ["S0", "S1"], "Need ordered S0/S1 runs")
    for state in ("S0", "S1"):
        need(any(v[0] == "cleanup" and v[1] == state for v in actions), "Missing owned cleanup")
    for i, (kind, state, argv, seconds) in enumerate(actions):
        need(
            kind in ("metadata", "build", "deploy", "run", "cleanup")
            and state in ("S0", "S1")
            and isinstance(argv, list)
            and argv
            and 0 < seconds <= 3600
            and all(isinstance(v, str) for v in argv),
            "Invalid caller-authorized command",
        )
        if kind == "run":
            need(
                "{poc}" in argv
                and "{workload}" in argv
                and any(v[0] == "build" and v[1] == state for v in actions[:i]),
                "Build first",
            )
    s["tokens"] = {k: str(own / "immutable" / s["repro"][k]) for k in ("poc", "workload")}
    s["tokens"].update(attempt=str(own), S0=str(own / "build-S0"), S1=str(own / "build-S1"))
    locations = [(p, f"immutable/{p}", "S0") for p in s["known"]]
    locations += [
        (p, f"build-{state}/{p.removeprefix(tree + '/')}", state)
        for state, tree in zip(("S0", "S1"), s["trees"], strict=True)
        for p in s["known"]
        if p.startswith(tree + "/")
    ]
    s["calls"] = [
        ("copy", state, ["cp", str(local(s["root"], p)), str(own / q)], 120)
        for p, q, state in locations
    ] + actions
    outputs = [q for _, q, _ in locations] + plan["output_files"]
    outputs += [f"evidence/command-{i}.json" for i in range(len(s["calls"]))]
    c.ensure_directory(
        own,
        output_files=tuple(outputs),
        exclude_roots=tuple(local(s["root"], t) for t in s["trees"]),
    )
    for _, q, _ in locations:
        c.ensure_directory((own / q).parent, output_files=(Path(q).name,))


def check_originals(s: dict[str, Any]) -> None:
    for root in (s["root"], s["own"] / "immutable"):
        need(
            all(
                sha256(local(root, p).read_bytes()).hexdigest() == h for p, h in s["known"].items()
            ),
            "Immutable input changed; require new attempts",
        )


def act(s: dict[str, Any], call: tuple[str, str, list[str], float]) -> dict[str, Any]:
    kind, state, argv, seconds = call
    for key, value in s["tokens"].items():
        argv = [v.replace("{" + key + "}", value) for v in argv]
    event = {
        "kind": kind,
        "state": state,
        "argv": argv,
        "timeout_seconds": seconds,
        "log": f"{s['a']['directory']}/evidence/command-{len(s['events'])}.json",
    }
    s["events"].append(event)
    cwd = s["own"] if kind in ("copy", "cleanup") else s["own"] / f"build-{state}"
    try:
        event.update(working_directory=str(cwd), **command(argv, cwd, seconds, True))
    finally:
        c.write_json(local(s["root"], event["log"]), event)
    return event


def execute(s: dict[str, Any]) -> None:
    try:
        for call in (v for v in s["calls"] if v[0] != "cleanup"):
            s["active"].add(call[1])
            if call[0] == "run":
                check_originals(s)
            event = act(s, call)
            if call[0] == "run":
                s["base"]["runs"].append(
                    {
                        "state": call[1],
                        "revision": s["source"][call[1].lower()],
                        "deployment": s["plan"]["interfaces"][int(call[1][1])],
                        "command": join(event["argv"]),
                        "log": event["log"],
                        "behavior": "unknown",
                    }
                )
            need(
                "failure" not in event and (call[0] == "run" or event["exit_code"] == 0),
                dumps(event),
            )
    finally:
        for call in (v for v in s["calls"] if v[0] == "cleanup" and v[1] in s["active"]):
            try:
                need(act(s, call).get("exit_code") == 0, "Owned cleanup failed")
            except Exception as error:
                fatal(error)
                s["errors"].append(f"Verify/release owned resources; cleanup failed: {error}")


def assessment(s: dict[str, Any], phase: str, prior: str = "") -> Review:
    paths = sorted(
        set(s["known"])
        | {p.relative_to(s["root"]).as_posix() for p in s["own"].rglob("*") if p.is_file()}
    )
    info = {k: s[k] for k in ("a", "guidance", "plan", "tokens", "events", "base")}
    info.update(index=list(enumerate(paths)), phase=phase, prior=prior)
    c.write_json(s["own"] / "evidence" / f"index-{phase}.json", info["index"])
    context = c.prepare_context(
        "Apply original replay instructions to full source/guidance/setup/PoC/input/dependencies. "
        "Preflight checks plan. Postflight cites new log IDs, access, cleanup. No later fixes. "
        "Return blockers, security review and one result sentence.",
        prior_results=dumps(info),
    )
    review = c.agent(
        "worker",
        "Read-only replay interpretation: {phase}.",
        phase=phase,
        context=context,
        working_directory=s["own"],
        readable_paths=tuple(local(s["root"], p) for p in paths),
        output=Review,
    )
    c.write_json(s["own"] / "evidence" / f"review-{phase}.json", review.model_dump())
    need(
        review.result.strip()
        and review.security_review.strip()
        and review.evidence
        and all(0 <= i < len(paths) for i in review.evidence),
        "Missing/invalid review evidence",
    )
    if phase == "post":
        logs = [e["log"] for e in s["events"] if e["kind"] in ("run", "cleanup")]
        need(all(paths.index(p) in review.evidence for p in logs), "Inspect new execution logs")
        need(
            len(review.behaviors) == 2
            and "unknown" not in review.behaviors
            and review.reachable
            and review.released,
            "Unresolved execution/access/release",
        )
    need(not review.blocker, review.blocker)
    return review


def finish(s: dict[str, Any], review: Review | None) -> dict[str, Any]:
    root, own, base = s["root"], s["own"], s["a"]["directory"]
    value = {**s["base"], "blocker": "\n".join(s["errors"])}
    if s["active"] and review is None:
        value["blocker"] += "\nInspect cleanup logs and verify/release owned resources."
    if review is not None:
        value.update(summary=review.result, security_review=review.security_review)
        value["runs"] = [
            {**r, "behavior": b} for r, b in zip(value["runs"], review.behaviors, strict=True)
        ]
    value["status"] = "blocked" if value["blocker"] else "complete"
    value["build_dirs"] = [
        f"{base}/build-{v}" for v in ("S0", "S1") if (own / f"build-{v}").exists()
    ]
    value["artifacts"] = [
        p.relative_to(root).as_posix()
        for p in own.iterdir()
        if p.name not in ("replay.json", "replay.json.seal.json")
    ]
    record = f"{base}/replay.json"
    value["resources"] = {
        "states": sorted(s["active"]),
        "events": s["events"],
        "released": review.released if review else False,
    }
    c.write_json(own / "replay.json", value)
    try:
        helper(root, "evidence", ["seal", str(root), record], True)
        helper(root, "evidence", ["verify", str(root), record])
        helper(root, "registry", ["check", str(root), s["a"]["id"], record])
    except Exception as error:
        fatal(error)
        return respond("blocked", None, "Evidence retained.", f"{record} not validated: {error}")
    return respond(value["status"], record, value["summary"], value["blocker"])


@c.recipe(
    name="replay_regression",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(max_agent_calls=4, max_wall_seconds=3600),
    output_root=".",
)
def replay(campaign: str, attempt: str, bound_agent: str, plan: dict[str, Any]) -> dict[str, Any]:
    try:
        s = assignment(Path(campaign).resolve(strict=True), attempt, bound_agent)
        record = f"{s['a']['directory']}/replay.json"
        if local(s["root"], record).exists() or local(s["root"], record + ".seal.json").exists():
            old = loads(helper(s["root"], "registry", ["check", str(s["root"]), attempt, record]))
            return respond(old["status"], record, old["summary"], old.get("blocker", ""))
        need(
            s["a"]["state"] == "running"
            and (not s["own"].exists() or not list(s["own"].iterdir())),
            "Need a fresh assignment",
        )
        files = (
            "replay.json",
            "replay.json.seal.json",
            *(
                f"evidence/{n}.json"
                for n in ["plan", "review-pre", "review-post", "index-pre", "index-post"]
            ),
        )
        c.ensure_directory(s["own"], output_files=files)
        c.ensure_directory(s["own"] / "evidence", output_files=tuple(p[9:] for p in files[2:]))
    except Exception as error:
        fatal(error)
        return respond("blocked", None, "Replay blocked.", str(error))
    base = {k: s["a"][k] for k in ("stage", "change", "candidate", "inputs", "agent")}
    base.update(
        attempt=attempt,
        summary="Replay blocked.",
        security_review="Review incomplete.",
        runs=[],
        setup=f"{s['a']['directory']}/evidence/plan.json",
    )
    s.update(base=base, plan=plan, events=[], active=set(), errors=[])
    review: Review | None = None
    try:
        c.write_json(s["own"] / "evidence" / "plan.json", plan)
        prerequisites(s)
        prepare(s)
        preflight = assessment(s, "pre")
        execute(s)
        check_originals(s)
        review = assessment(s, "post", preflight.model_dump_json())
    except Exception as error:
        fatal(error)
        s["errors"].append(str(error))
    return finish(s, review)


if __name__ == "__main__":
    raise SystemExit(replay.cli())


# --- calcifier metadata (skill provenance + sha256) ---


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("ff7afd6c9a06d6ac7de8c436a0bb1179d48c40116722bb371f12971c3ac313b8"),
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
        "independent replay of one existing reproduction, not autho"
        "ring/repairing its PoC. Require the entire accepted sealed"
        " reproduction tree along with accepted candidate, preparat"
        "ion, discovery and identical source.json; records alone ar"
        "e insufficient. Check the bound fresh-context agent handle"
        " differs from this candidate's reproducer and prior replay"
        "/adjudication attempts using original registry/runtime rul"
        "es. Do not invent a new handle or isolated verification le"
        "vel. If the caller cannot supply a genuinely bound indepen"
        "dent assignment, block.\n\nRead setup, pinned security gui"
        "dance, original actual PoC, immutable dependencies and wor"
        "kload. Hash-check them against the seals. Do not call a pr"
        "oducing worker to rewrite or fix the PoC: any change must "
        "be returned as a reproduction prerequisite, requiring new "
        "reproduction/replay attempts. Explicit user-authorized str"
        "uctured build/deploy/run/cleanup argv inputs may locate in"
        "terfaces for this fresh environment; run the unchanged PoC"
        " and identical workload against fresh real S0 and S1 deplo"
        "yments. Copy sources into YOUR fresh per-attempt build dir"
        "s only, never reuse a reproducer's build output, services,"
        " mutable config/logs, or mutate sealed source exports. Lis"
        "t every build/deploy location in build_dirs.\n\nThe host e"
        "xecutes the actual authorized commands with correct mutati"
        "on flags, captures real exit/timeout/stderr and separate f"
        "resh nonempty S0/S1 logs, saves versions/sanitized configu"
        "ration/setup and actual deployment/interface. Read-only wo"
        "rkers may assess actual logs/source for correct/failure/un"
        "known and claimed-user reachability, but a previous summar"
        "y/log or a generic agent assertion is not your own executi"
        "on. Preserve disagreement, nondeterminism and blockers; st"
        "atus complete means the replay attempt finished, not a con"
        "firmed regression. Execute only with the claimed user's/at"
        "tacker's access. Missing prerequisites or independent exec"
        "ution evidence blocks without inventing success.\n\nWrite "
        "replay.json stage='replay' with the exact assigned candida"
        "te, SAME source path, explicit reproduction record input, "
        "original poc/workload references (or byte-identical copies"
        " with retained digests), independent setup and build_dirs,"
        " runs exactly S0 then S1 when complete. Run revisions must"
        " match source.json, logs must differ from each other and f"
        "rom reproduction logs, and every referenced artifact must "
        "be bound in exact inputs/artifacts. Verify original PoC/wo"
        "rkload hashes after replay. Release only resources actuall"
        "y owned by this attempt, keep evidence, record disposition"
        ", then seal/verify/registry check. Return observed agreeme"
        "nt/divergence or exact blocker; do not issue final adjudic"
        "ation or silently retry with modified PoC.\n\nFocused repa"
        "ir of the substantive supplied prior candidate; preserve a"
        "ll native replay/evidence behavior:\n- The actual local Ru"
        "ff rules are E,F,I,UP,B,SIM,C4,C90,PLR0913,RUF, Python 3.1"
        "3, line length 100, max-complexity=8. Existing replay comp"
        "lexity is 22 and C408 flags dict() calls at lines 68,73,32"
        "6,383. Decompose into MODULE-LEVEL helpers/steps (nested h"
        "elper complexity is counted against the enclosing function"
        "), use dict literals, keep helper argument counts within t"
        "he rule, and do not add suppressions/noqa or alter configu"
        "ration.\n- Every arbitrary caller-supplied project/build/d"
        "eployment/PoC/version command is potentially mutating and "
        "must be marked mutating=True, including actions called 'me"
        "tadata'. Only literal host-derived proven read-only Git/pi"
        "nned verification commands may be mutating=False. A user l"
        "abel cannot turn project code into a dry-run-safe read.\n-"
        " Cleanup must run in a finally path after ANY attempted re"
        "source-producing action, including a deployment that fails"
        " or times out after starting a service and later command/l"
        "ogging/assessment exceptions. Use the explicit caller-owne"
        "d cleanup plan; do not clean unrelated services. Persist c"
        "leanup attempts, exit/timeout/logs and honest disposition;"
        " inability to establish release is a blocker with the call"
        "er action, never asserted success. Keep sealed prerequisit"
        "e trees immutable. Materialize byte-identical PoC/workload"
        "/dependency copies into this own attempt when execution co"
        "uld write sidecars beside the originals; retain original d"
        "igests/references and never repair their content.\n- Requi"
        "re actual distinct new S0/S1 execution logs and retain the"
        "ir full command/exit/timeout data. Post-run interpretation"
        " must cite the host-enumerated new log IDs and inspect the"
        "ir content, not only earlier summaries. Preserve 'unknown'"
        " and inconclusive observations as blocked/uncertain. Missi"
        "ng fields, provider/context failure or resource errors aft"
        "er a valid assignment must retain attempted setup/logs and"
        " produce a sealed blocked replay record where possible, no"
        "t simply discard all stage evidence with Record:none.\n- K"
        "eep all existing real assignment/independence/input-seal/o"
        "riginal-hash checks and final seal/verify/registry check; "
        "strengthen own launch verification with original helper bi"
        "nding semantics if decomposing this code. No fake receipts"
        " or platform adapters.\n\n\nONE MECHANICAL REPAIR of the r"
        "eviewed substantive compiled candidate. Its native control"
        " flow, typed read-only assessments, genuine bound assignme"
        "nt/original receipt checking, copied immutable dependency "
        "tree, host-derived tokens, original byte-hash checks, actu"
        "al mutating caller commands, raw observation retention, fi"
        "nally cleanup, independent run logs and sealed blocked/com"
        "plete outputs are reviewed and must be preserved byte-for-"
        "byte where unrelated. The candidate passes strict plugin-l"
        "ocal Ruff 0.14.13.\n\nIn helper(), original Python resourc"
        "es are still invoked as [uv,run,--no-project,<resource>,.."
        ".]. Change that helper prefix to [uv,run,--no-project,pyth"
        "on,-B,<resource>,...] so original registry/evidence siblin"
        "g imports do not write __pycache__ outside the assigned at"
        "tempt. The inline BINDING validator already uses python -B"
        " and should stay unchanged. Apply the same prefix only to "
        "other ORIGINAL Python-helper invocations if any; do not re"
        "write user-provided target argv. No other behavior, interf"
        "ace, prompt, stage validation, evidence or output changes "
        "are requested. Keep strict local Ruff rules and module-lev"
        "el decomposition; no suppressions/config edits.\n"
    ),
    "sha256": ("df30e80e9a3dc31ca2d9093b4b8926ff704c66eb6d5a80876d3df415d69dfb3d"),
}
_CALCIFIER_SUBRECIPES = []
