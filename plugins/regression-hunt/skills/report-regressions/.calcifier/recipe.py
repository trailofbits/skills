# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import hashlib
import json
import posixpath
import re
from html import unescape
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

import calcifier as c

OUTCOMES = (
    "REPRODUCED_REGRESSION",
    "INCOMPLETE_FIX",
    "LATENT_BUG",
    "PREEXISTING_BUG",
    "REJECTED",
    "UNRESOLVED",
)
GUIDANCE = ("AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md")
FIELDS = ("category", "severity", "likelihood", "severity_reason", "likelihood_reason")
SHA = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
Status = Literal["complete", "blocked"]
CHECK = (
    "import json,sys;from pathlib import Path\n"
    "sys.path.insert(0,str(Path(sys.argv[1]).parent));import registry as r,report as t\n"
    "p=Path(sys.argv[2]);d=r.load(p);a=r.assigned(d,sys.argv[3]);q=r.require\n"
    "q(d['scope']['file']=='scope.json','Wrong frozen scope')\n"
    "q((a['id'],a['stage'],a['change'],a['candidate'])=="
    "(sys.argv[3],'report','campaign',None),'Wrong assignment')\n"
    "q(a['directory']=='attempts/'+a['id'],'Wrong assigned directory')\n"
    "q(a['state'] in ('running','accepted') and a['agent'],'Unbound assignment')\n"
    "q(a['verification'] in r.LEVELS and r.receipt_level(a)==a['verification'],'Bad level')\n"
    "f=r.host_binding if a['verification']=='isolated' else r.agent_binding\n"
    "q(f(p,d,a,a['agent'],a['launch']['record'])==a['launch'],'Invalid original binding')\n"
    "q(r.inputs_snapshot(p,a['inputs'])==a['input_hashes'],'Changed assigned inputs')\n"
    "if sys.argv[4]=='binding': print(json.dumps(a));sys.exit(0)\n"
    "i=r.read(p,'campaign.json');r.check_scope(p,i)\n"
    "q(r.changes_by_id(r.read(p,'scope.json')['changes'])==d['scope']['changes'],"
    "'Frozen scope mapping mismatch')\n"
    "q({'scope.json','campaign.json','progress.md'}<=a['input_hashes'].keys(),'Missing inputs')\n"
    "packs={};cat=a['input_hashes'].copy()\n"
    "todo=[n for n in a['inputs'] if r.local(p,n+'.seal.json').exists()]\n"
    "while todo:\n"
    " n=todo.pop()\n"
    " if n in packs: continue\n"
    " packs[n]=r.accepted(p,n);s=r.read(p,n+'.seal.json')\n"
    " cat.update(s['inputs']|s['artifacts']|{n:s['record']})\n"
    " cat.update({k+'.seal.json':v for k,v in s['dependencies'].items()})\n"
    " todo.extend(s['dependencies'])\n"
    "for ch in i['changes']:\n"
    " refs=[ch.get('prepare'),ch.get('hunt'),*[x.get('decision') for x in ch['candidates']]]\n"
    " q(all(n is None or n in packs for n in refs),'Unassigned indexed stage: '+ch['id'])\n"
    "print(json.dumps({'index':i,'packages':packs,'catalog':cat,'expected':t.collect(p)}))\n"
)


@c.output_type
class Review:
    reviews: dict[str, str]
    citations: dict[str, list[str]]
    blockers: list[str]


@c.output_type
class Reply:
    status: Status
    reports: list[str]
    result: str
    blocker: str


def require(ok: object, message: str) -> None:
    if not ok:
        raise ValueError(message)


def local(root: Path, name: str) -> Path:
    path = Path(name)
    require(path.parts and not path.is_absolute() and ".." not in path.parts, name)
    target = root / path
    require(not any(p.is_symlink() for p in (target, *target.parents)), f"Symlink: {name}")
    return target


def read(root: Path, name: str) -> dict:
    return json.loads(local(root, name).read_text(encoding="utf-8"))


def detail(error: Exception) -> str:
    if type(error).__name__ in ("BudgetExceeded", "UnmaterializedArtifactError"):
        raise error
    return f"{type(error).__name__}: {error}"


def execute(argv: list[str], writes: bool, logs: list[dict]) -> str:
    try:
        result = c.run_command(argv, timeout_seconds=600, mutating=writes)
    except Exception as error:
        logs.append(
            {
                "argv": argv,
                "exit_code": None,
                "error": str(error),
                "stdout": str(getattr(error, "stdout", "")),
                "stderr": str(getattr(error, "stderr", "")),
                "timeout_seconds": 600,
            }
        )
        raise
    logs.append(
        {
            "argv": result.argv,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timeout_seconds": 600,
        }
    )
    require(result.exit_code == 0, json.dumps(logs[-1], ensure_ascii=False))
    return result.stdout


def helper(script: str, args: list[str], writes: bool, logs: list[dict]) -> str:
    argv = ["uv", "run", "--no-project", "python", "-B"]
    argv += (
        ["-c", CHECK, str(c.resource("scripts/registry.py")), *args, script]
        if script in ("binding", "preflight")
        else [str(c.resource(f"scripts/{script}.py")), *args]
    )
    return execute(argv, writes, logs)


def finish(status: Status, paths: list[str], summary: str, blocker: str) -> Reply:
    return c.emit(
        Reply(status=status, reports=paths, result=summary, blocker=blocker), name="report"
    )


def target(root: Path, change: dict, state: dict, handoff: dict) -> dict:
    cid = change["id"]
    prep = state["packages"].get(change.get("prepare"), {})
    source = prep.get("source")
    require(not source or source in state["catalog"], f"{cid}: unsealed source")
    src = read(root, source) if source else {}
    require(not source or re.fullmatch(SHA, src.get("s1", "")), f"{cid}: invalid source S1")
    inp = change["input"] if isinstance(change["input"], dict) else {}
    h = handoff.get(cid, {})
    require(not h or re.fullmatch(SHA, h.get("s1", "")), f"{cid}: invalid handoff S1")
    require(set(h) <= {"s1", "absent"} and set(h.get("absent", [])) <= set(GUIDANCE), cid)
    raw = [src.get("s1"), h.get("s1"), *(inp.get(k) for k in ("s1", "commit", "sha"))]
    pins = [v for v in raw if isinstance(v, str) and re.fullmatch(SHA, v)]
    require(pins and len(set(pins)) == 1, f"{cid}: missing or conflicting immutable target S1")
    export = (Path(source).parent / "S1").as_posix() if source else ""
    tree = (
        bool(export)
        and local(root, export).is_dir()
        and any(
            (export == p or export.startswith(p + "/")) and local(root, p).is_dir()
            for p in prep.get("artifacts", [])
        )
    )
    one = {
        "id": cid,
        "s1": pins[0],
        "export": export,
        "tree": tree,
        "absent": h.get("absent", []),
        "repository": src.get("repository", inp.get("repository")),
    }
    return {"s1": pins[0], "documents": {n: document(root, n, one, state) for n in GUIDANCE}}


def document(root: Path, name: str, one: dict, state: dict) -> dict:
    copy = f"guidance/{one['id']}/{one['s1']}/{name}"
    exported = f"{one['export']}/{name}" if one["export"] else ""
    require(not local(root, copy).exists() or copy in state["job"]["input_hashes"], copy)
    paths = [p for p in (copy, exported) if p in state["catalog"]]
    texts = [local(root, p).read_text(encoding="utf-8") for p in paths]
    absent = name in one["absent"] or (one["tree"] and exported not in state["catalog"])
    require(len(set(texts)) <= 1 and not (absent and texts), f"Conflicting guidance: {copy}")
    proof = {"id": f"G:{one['id']}:{name}", "paths": paths, "absent": absent}
    if texts:
        return {**proof, "text": texts[0]}
    if absent:
        return {**proof, "text": "", "absence_handoff": True}
    repo = one["repository"]
    require(repo and Path(repo).is_dir(), f"{copy}: supply hashed guidance or explicit absence")
    argv = ["git", "-C", repo]
    listing = execute([*argv, "ls-tree", one["s1"], "--", name], False, state["logs"])
    require(
        not listing or re.fullmatch(r"100(?:644|755) blob [0-9a-f]+\t" + name + r"\n?", listing),
        f"Unsupported guidance object: {copy}",
    )
    text = execute([*argv, "show", f"{one['s1']}:{name}"], False, state["logs"]) if listing else ""
    return {**proof, "text": text, "absent": not listing, "immutable_git": one["s1"]}


def catalog_files(root: Path, catalog: dict) -> tuple[list[dict], list[Path]]:
    inventory, texts = [], []
    for i, name in enumerate(sorted(catalog)):
        path = local(root, name)
        require(path.is_file(), f"Not a regular evidence file: {name}")
        blob = path.read_bytes()
        require(hashlib.sha256(blob).hexdigest() == catalog[name], f"Changed evidence: {name}")
        try:
            blob.decode("utf-8")
            texts.append(path)
            binary = False
        except UnicodeDecodeError:
            binary = True
        inventory.append(
            {
                "id": f"E{i}",
                "path": name,
                "hash": catalog[name],
                "size": len(blob),
                "binary": binary,
            }
        )
    return inventory, texts


def produce(root: Path, state: dict, handoff_path: str, notes: dict) -> dict:
    require(not handoff_path or handoff_path in state["job"]["input_hashes"], "Unassigned handoff")
    handoff = read(root, handoff_path) if handoff_path else {}
    changes = state["index"]["changes"]
    require(set(handoff) <= {ch["id"] for ch in changes}, "Handoff outside frozen scope")
    notes["guidance"] = {ch["id"]: target(root, ch, state, handoff) for ch in changes}
    notes["inventory"], texts = catalog_files(root, state["catalog"])
    notes["binary_inventory"] = [e for e in notes["inventory"] if e["binary"]]
    refs = tuple(
        c.resource(p)
        for p in (
            "docs/regression-definition.md",
            "docs/report-definitions.md",
            "references/evidence.md",
        )
    )
    context = c.prepare_context(
        "Apply host-pinned guidance first; perform the original reporting review in one session. "
        "Return per-change guidance/security conclusions, E/G citations and actual blockers. "
        "Assess coverage and required linked content without adjudicating or repairing decisions. "
        "Targets, paths and absence facts are fixed. Binary inventory is not text review; "
        "inspect accessible evidence or state limitations. Do not select commands or paths.",
        prior_results=json.dumps(notes, ensure_ascii=False),
        files=(*texts, *refs),
        readable_roots=(root, *refs),
    )
    review = c.agent(
        "worker",
        "Use the complete assignment and original source workflow.",
        working_directory=local(root, state["job"]["directory"]),
        context=context,
        readable_paths=tuple(local(root, p) for p in state["catalog"]),
        output=Review,
    )
    notes["security_review"] = review.model_dump_json()
    ids = {e["id"] for e in notes["inventory"]} | {
        d["id"] for g in notes["guidance"].values() for d in g["documents"].values()
    }
    require(
        review.reviews.keys() == review.citations.keys() == notes["guidance"].keys(), "Review scope"
    )
    require(all(v.strip() for v in review.reviews.values()), "Empty guidance/security conclusions")
    require(
        all(v and set(v) <= ids for v in review.citations.values()), "Invalid evidence citations"
    )
    require(not review.blockers, "; ".join(review.blockers))
    helper(
        "report",
        [str(root), "--output", state["job"]["directory"] + "/reports"],
        True,
        state["logs"],
    )
    return inspect(root, state)


def links(root: Path, state: dict, data: dict) -> None:
    base = state["job"]["directory"] + "/reports"
    rows = data["findings"]
    for fname, pattern in (("index.html", r'href="([^"]+)"'), ("report.md", r"\]\(([^)\n]+)\)")):
        text = local(root, f"{base}/{fname}").read_text(encoding="utf-8")
        visible = unescape(text) if fname == "index.html" else text
        require("pending human review" in visible.lower(), "Missing human-review notice")
        require(
            all(
                str(r[k]) in visible
                for r in rows
                for k in ("reason", "unresolved_reason", "duplicate_of", *FIELDS)
                if r.get(k)
            ),
            "Missing rendered finding content",
        )
        targets = set()
        for url in re.findall(pattern, text):
            parsed = urlsplit(unescape(url))
            require(not parsed.scheme and not parsed.netloc, f"Unexpected link: {url}")
            name = posixpath.normpath(posixpath.join(base, unquote(parsed.path)))
            require(
                name in state["catalog"] and local(root, name).is_file(), f"Unsealed link: {name}"
            )
            targets.add(name)
        require({p for r in rows for p in r["evidence"]} <= targets, "Missing evidence links")


def inspect(root: Path, state: dict) -> dict:
    data = read(root, state["job"]["directory"] + "/reports/report.json")
    require(data == state["expected"] and data["changes"], "Report/scope/decision mismatch")
    require(
        data["counts"]
        == {
            k: sum(r["outcome"] == k and not r.get("duplicate_of") for r in data["findings"])
            for k in OUTCOMES
        },
        "Unique counts",
    )
    require(
        all(r.get("unresolved_reason") for r in data["findings"] if r["outcome"] == "UNRESOLVED"),
        "Missing unresolved reason",
    )
    require(
        all(
            r.get("verification") in ("isolated", "shared-host")
            for r in data["findings"]
            if r["outcome"] == OUTCOMES[0]
        ),
        "Missing verification",
    )
    links(root, state, data)
    return data


def save(root: Path, state: dict, notes: dict, audit: dict) -> Reply:
    job, directory = state["job"], state["job"]["directory"]
    record, diagnostic = directory + "/report-stage.json", directory + "/diagnostics.json"
    artifacts = [
        directory + "/reports/" + n
        for n in ("index.html", "report.md", "report.json")
        if local(root, directory + "/reports/" + n).is_file()
    ]
    status: Status = "blocked" if notes["errors"] else "complete"
    summary = (
        f"{len(audit['changes'])} scoped changes; {audit['counts']['UNRESOLVED']} unresolved; "
        f"{sum(x['status'] == 'INCOMPLETE' for x in audit['changes'])} coverage gaps."
        if audit
        else "Campaign coverage and unresolved work could not be validated."
    )
    notes.update(inspection=audit, outputs=artifacts)
    try:
        c.write_json(local(root, diagnostic), notes)
        c.write_json(
            local(root, record),
            {
                "stage": "report",
                "candidate": None,
                "change": "campaign",
                "attempt": job["id"],
                "agent": job["agent"],
                "inputs": job["inputs"],
                "status": status,
                "summary": summary,
                "security_review": notes["security_review"],
                "artifacts": [diagnostic, *artifacts],
            },
        )
        helper("evidence", ["seal", str(root), record], True, state["logs"])
        helper("evidence", ["verify", str(root), record], False, state["logs"])
        helper("registry", ["check", str(root), job["id"], record], False, state["logs"])
    except Exception as error:
        return finish(
            "blocked",
            [],
            summary,
            f"Incomplete {record}, {artifacts}: {detail(error)}; "
            + json.dumps(state["logs"])
            + "; require a new assignment.",
        )
    blocker = "; ".join(notes["errors"]) + (
        f"; incomplete/unvalidated outputs: {artifacts}" if status == "blocked" else ""
    )
    return finish(status, [record, record + ".seal.json", diagnostic, *artifacts], summary, blocker)


@c.recipe(agents=("worker",), capabilities=("Bash",), output_root=".", budget=c.Budget(2, 3600))
def report_regressions(campaign: str, attempt: str, guidance_handoff: str = "") -> Reply:
    """Optional guidance_handoff names an assigned JSON mapping: change -> {s1, absent}."""
    logs: list[dict] = []
    try:
        root = Path(campaign).absolute()
        require(root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)), campaign)
        job = json.loads(helper("binding", [str(root), attempt], False, logs))
        directory = job["directory"]
        record = directory + "/report-stage.json"
        reuse = local(root, record).exists() or local(root, record + ".seal.json").exists()
        if not reuse:
            own = local(root, directory)
            require(
                job["state"] == "running" and (not own.exists() or not any(own.iterdir())),
                "Partial/accepted attempt requires an intact seal or new assignment",
            )
            c.ensure_directory(
                own,
                output_files=(
                    "report-stage.json",
                    "report-stage.json.seal.json",
                    "diagnostics.json",
                    "reports/index.html",
                    "reports/report.md",
                    "reports/report.json",
                ),
            )
    except Exception as error:
        return finish("blocked", [], "Report production blocked.", detail(error) + json.dumps(logs))
    state: dict[str, Any] = {"job": job, "logs": logs}
    notes = {
        "commands": logs,
        "errors": [],
        "security_review": "Not reviewed: prerequisites missing.",
    }
    audit = {}
    try:
        state.update(json.loads(helper("preflight", [str(root), attempt], False, logs)))
        if reuse:
            saved = json.loads(
                helper("registry", ["check", str(root), attempt, record], False, logs)
            )
            if saved["status"] == "complete":
                inspect(root, state)
            return finish(
                saved["status"],
                [record, record + ".seal.json", *saved["artifacts"]],
                saved["summary"],
                "; ".join(read(root, directory + "/diagnostics.json")["errors"]),
            )
        audit = produce(root, state, guidance_handoff, notes)
    except Exception as error:
        notes["errors"].append(detail(error))
    if reuse:
        return finish(
            "blocked",
            [],
            "Reusable report failed validation.",
            "; ".join(notes["errors"]) + "; require a new assignment.",
        )
    return save(root, state, notes, audit)


if __name__ == "__main__":
    raise SystemExit(report_regressions.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("cf17208f4a444f6be10b8661a5a60c9f893c4cce750e9cf7b2b78dfe44725c13"),
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
        "deterministic report production and sealed report-stage.js"
        "on. Require a nonempty frozen scope, campaign index, progr"
        "ess ledger, actual assigned report-stage registry attempt "
        "(change='campaign') and accepted sealed stage packages for"
        " all scoped changes. Mechanically reconcile scope.json and"
        " registry's frozen ID/input mapping against campaign.json "
        "before rendering; preserve missing/unprepared changes as c"
        "overage gaps, never silently reduce the original request. "
        "Account for project guidance for every scoped S1, or recor"
        "d/block missing prerequisites. The component must not adju"
        "dicate, repair decisions, edit hashes, rewrite campaign/in"
        "dex/scope, fabricate acceptance, or drop invalid records t"
        "o make validation pass.\n\nExecute the actual pinned repor"
        "t.py with argv: uv run --no-project SCRIPT CAMPAIGN --outp"
        "ut ASSIGNED_DIRECTORY/reports. The --output value is CAMPA"
        "IGN-RELATIVE, derived from this bound assignment. Mark exe"
        "cution mutating=True because reports are written. The help"
        "er validates accepted records, exact index/discovery candi"
        "date sets, frozen scope, checks/seals, experiment identity"
        ", PoC/workload hashes, duplicate mappings and verification"
        " levels. Preserve real exit behavior: exit 1 means changed"
        " evidence/invalid index or rendering failure and MUST resu"
        "lt in blocked stage with retained stderr/diagnostics and c"
        "learly identified partial outputs; usage errors are failur"
        "es, not clean reports. Exit 0 may legitimately include UNR"
        "ESOLVED decisions. Never claim exit 0 means campaign compl"
        "ete or all findings valid.\n\nVerify actual outputs report"
        "s/index.html, reports/report.md, reports/report.json. Pars"
        "e report.json in native Python and inspect counts, coverag"
        "e, every finding, unresolved_reason, duplicate mapping and"
        " verification level. Counts must come from adjudicated out"
        "comes; only unique REPRODUCED_REGRESSION totals are confir"
        "med, incomplete fixes/latent/preexisting/rejected/unresolv"
        "ed remain separate. Surface every unresolved_reason and co"
        "nfirmed finding verification ('isolated' or 'shared-host')"
        " exactly; do not upgrade based on agent summaries. Preserv"
        "e links back to actual sealed files, setup/PoC/execution e"
        "vidence, severity/likelihood reasons, unknown novelty and "
        "pending human-review notice. Missing required report conte"
        "nt is blocked even if helper exited zero. Check linked loc"
        "al evidence exists without following symlinks outside the "
        "campaign.\n\nWrite report-stage.json at the assigned attem"
        "pt path with stage='report', candidate=null, change='campa"
        "ign', exact assigned inputs, security_review, complete/blo"
        "cked, summary and generated reports/diagnostics artifacts."
        " Seal/verify/registry check only after rendering/inspectio"
        "n ends. A blocked report still preserves diagnostic eviden"
        "ce; do not seal then mutate it. Return validated output pa"
        "ths, campaign coverage and unresolved work. A complete rep"
        "orting stage can describe an incomplete campaign; do not u"
        "se generic model prose instead of running the deterministi"
        "c renderer.\n\nTargeted compiler repair of the supplied pr"
        "ior candidate (preserve its native report/helper mechanics"
        "):\n1. Its prepare_context(files=all catalog paths) crashe"
        "s on ordinary binary artifacts. Published Calcifier 0.2.0 "
        "prepare_context decodes every selected file as UTF-8 and w"
        "raps decoding errors in RecipeError. Keep ALL evidence pat"
        "hs/hashes in the host catalog, original helper verificatio"
        "n and link checks; only pass strictly UTF-8-decodable regu"
        "lar files to the text context. Include an explicit binary "
        "evidence inventory (ID/path/hash/size) for the reviewer an"
        "d keep binary evidence accessible under the read-only cont"
        "ract when appropriate; do not drop it from evidence or cla"
        "im it was reviewed as text. Catch relevant context/provide"
        "r failures into honest blocked diagnostics and seal the bl"
        "ocked report stage when the valid assignment permits this."
        "\n2. Before reading/producing the report, validate this ow"
        "n assignment with the actual pinned registry/runtime host_"
        "binding or agent_binding and input-snapshot semantics, lik"
        "e the prepare component, rather than validating only recei"
        "pt hashes and handle strings. The end registry check remai"
        "ns required. Never fabricate replacement observations.\n3."
        " Preserve partial-campaign reporting where guidance is ful"
        "ly accounted for: report.py deliberately renders missing/b"
        "locked preparation/discovery as INCOMPLETE coverage. Do no"
        "t require an accepted prepare source for every change if t"
        "he frozen scope/assigned complete guidance handoff already"
        " pins the target S1 and supplies all three guidance conten"
        "ts or explicit absences. Resolve target SHA from immutable"
        " scope input when needed, or block with the exact missing "
        "guidance prerequisite; never silently omit the scoped chan"
        "ge or invent a SHA.\n\n\nFocused SOURCE-CONTRACT REPAIR of"
        " the supplied complete native report candidate. Preserve t"
        "he real deterministic report helper, actual scope/index/in"
        "put/accepted-seal checks, binary-safe text context plus fu"
        "ll binary evidence inventory, output inspection/counts/lin"
        "ks/verification/unresolved retention, blocked diagnostics,"
        " original binding semantics and sealed report-stage output"
        ". Do not replace the host renderer with a model report or "
        "a platform adapter. The prior XHIGH context is obsolete: i"
        "t let the worker select a target SHA from arbitrary SHA-lo"
        "oking strings in progress.md, which is not a valid host-de"
        "rived target selector and triggers native taint diagnostic"
        "s.\n\n1. Determine every target S1 and ALL guidance paths/"
        "absence facts in host control flow BEFORE model review. Pr"
        "efer the actual accepted sealed source.json.s1, else an im"
        "mutable full target SHA explicitly supplied by structured "
        "scope input. Do NOT collect arbitrary SHA-looking strings "
        "from progress.md and ask the worker to choose among them; "
        "those strings may include S0, unrelated commits or old tar"
        "gets. When an incomplete campaign needs a separate complet"
        "e guidance handoff, expose an explicit caller-supplied str"
        "uctured per-change mapping (for example guidance_handoff[c"
        "hange]={s1:full-SHA,absent:[known guidance names]}), check"
        "ed against frozen change IDs, any actual accepted source/s"
        "cope target and the already assigned/hashes-verified guida"
        "nce copies/complete handoff. The caller explicitly pins th"
        "e target and absence facts; the worker cannot invent/selec"
        "t them. Reject conflict with known S1, present sealed sour"
        "ce guidance or supplied copies. If a target or any filenam"
        "e is unaccounted, fetch by immutable Git objects when the "
        "actual repository is available, otherwise preserve the exa"
        "ct blocker; never fabricate absence. A complete handoff ma"
        "y avoid repository access per the original contract.\n\n2."
        " Preserve partial-campaign behavior: missing/blocked prepa"
        "ration or discovery remain INCOMPLETE in the real renderer"
        " when the explicit immutable target/guidance handoff is co"
        "mplete. A reporting stage may finish while campaign covera"
        "ge is incomplete. Missing target/handoff must block with r"
        "etained diagnostics rather than drop a change, require a f"
        "ake accepted preparation, or invent a SHA. The stage never"
        " rewrites scope, index, progress, receipts, source records"
        ", hashes or decisions.\n\n3. Worker output is interpretati"
        "on only: per-change guidance/security conclusions and cita"
        "tions to already enumerated evidence. It must not select S"
        "1s, file paths, absence facts, commands, tool requests or "
        "renderer/output paths. Precompute readonly paths/text file"
        " selections/host proof inventories before the call and kee"
        "p trusted selector structures separate from model result d"
        "ictionaries; do not call path-reading helpers using model-"
        "selected evidence after review. All renderer/seal/output p"
        "aths are host-derived from the bound report assignment. Us"
        "e actual original host_binding/agent_binding/input snapsho"
        "t validation before target work and the original final reg"
        "istry check.\n\n4. Strict plugin-local Ruff 0.14.13 is man"
        "datory: E,F,I,UP,B,SIM,C4,C90,PLR0913,RUF; py313, line100,"
        " max complexity8/default argument limit5. Current large re"
        "port function needs MODULE-LEVEL decomposition (nested hel"
        "per complexity still counts); replace unnecessary dict con"
        "structions with literals. No noqa, suppression, config cha"
        "nge or dropped gate.\n\n5. Launch every pinned original Py"
        "thon helper/fixed Python wrapper through uv no-project run"
        " using the Python interpreter and bytecode-suppression fla"
        "g -B; imports must not write caches outside owned attempts"
        ". Keep report/seal commands mutating and verification/read"
        " commands read-only. Preserve actual nonzero/launch/timeou"
        "t stdout/stderr and partial artifacts. Ordinary AgentError"
        "/TransientAgentError are RuntimeError subclasses; top-leve"
        "l AgentError is not exported. Catch ordinary provider/Reci"
        "peError failures into blocked diagnostic packages when bin"
        "ding/ownership permit. BudgetExceeded and compiler Unmater"
        "ializedArtifactError remain honest failures/unverified, no"
        "t fabricated executed/verified work.\n\nThe candidate alre"
        "ady has substantive native functionality; preserve it whil"
        "e correcting deterministic target/control flow and local d"
        "ecomposition. Return a complete valid Python module, not a"
        " truncated class-only draft.\n"
    ),
    "sha256": ("72e60c68958897f806363869a483e7a081b16709c9d818f76320d538f9fe6752"),
}
_CALCIFIER_SUBRECIPES = []
