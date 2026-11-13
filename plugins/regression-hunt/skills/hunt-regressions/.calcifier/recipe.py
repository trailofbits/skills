# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from pathlib import Path
from typing import Any

import calcifier as c


@c.output_type
class Lead:
    key: str
    title: str
    patch_intent: str
    prior_behavior: str
    changed_code: str
    reachable_trigger: str
    possible_defect: str
    false_positive_checks: str
    proof_needed: str
    evidence: list[str]


@c.output_type
class Coverage:
    inspected: bool
    notes: str
    evidence: list[str]


@c.output_type
class Analysis:
    leads: list[Lead]
    coverage: dict[str, Coverage]
    inspected_evidence: list[str]
    summary: str
    security_review: str
    limitations: list[str]
    blockers: list[str]


VALIDATE = """import json,re,runpy,sys;from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1]).parent));r=runpy.run_path(sys.argv[1])
p=Path(sys.argv[2]);d=r['show'](p);a=r['assigned'](d,sys.argv[3])
q=r['require'];rd=r['read'];l=r['local'];g=a['change'];k=a['prefix'];h=a['agent'];ins=a['inputs']
q(a['id']==sys.argv[3] and a['directory']=='attempts/'+a['id'],'Identity')
q(a['stage']=='hunt' and a['candidate'] is None and h,'Bound hunt required')
q(a['state'] in ('running','accepted'),'State');q(re.fullmatch(r'h[0-9]{3,}-',k),'Prefix')
q(d['prefixes'].get(k)==g and g in d['scope']['changes'],'Prefix/change/scope')
q(r['changes_by_id'](rd(p,d['scope']['file'])['changes'])==d['scope']['changes'],'Scope')
q(r['inputs_snapshot'](p,ins)==a['input_hashes'],'Changed inputs')
r['prerequisite_changes'](p,g,ins);l(p,a['directory'])
q(a['verification'] in ('isolated','shared-host'),'Verification')
f=r['host_binding'] if a['verification']=='isolated' else r['agent_binding']
q(f(p,d,a,h,a['launch']['record'])==a['launch'],'Launch mismatch')
q(r['receipt_level'](a)==a['verification'],'Verification mismatch')
own={i:e for i,e in d['candidates'].items() if e['prefix']==k}
q(all(e['change']==g for e in own.values()),'Prior ownership')
v={'a':a,'own':own,'files':{},'trees':[],'obs':{},'prior':{},'gaps':[]}\ntry:
 names=[n for n in ins if l(p,n+'.seal.json').is_file() and rd(p,n).get('stage')=='prepare']
 q(len(names)==1,'Need one assigned accepted preparation');n=names[0]
 prep=r['accepted'](p,n);q(prep['change']==g and prep['status']=='complete','Preparation')
 available={**a['input_hashes']};pending=list(ins);seen=set()\n while pending:\n  n=pending.pop()
  if n in seen or not l(p,n+'.seal.json').is_file():continue
  seen.add(n);r['verify'](p,n);s=rd(p,n+'.seal.json')
  available.update(s['inputs']|s['artifacts']);pending.extend(s['dependencies'])
 for n in available:\n  parts=Path(n).parts;l(p,n)
  q(parts[0] not in ('runtime','registry.json','scope.json','campaign.json','progress.md'),
    'Coordinator-only evidence')\n  if parts[0]=='attempts':\n   owner=d['attempts'][parts[1]]
   q(owner['change']==g and (owner['stage']=='prepare' or owner['prefix']==k),'Other hunter')
 source=prep['source'];q(source in rd(p,names[0]+'.seal.json')['artifacts'],'Unsealed source')
 src=rd(p,source);base=Path(source).parent.as_posix();trees=[base+'/S0',base+'/S1']
 q(all(re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}',src[x]) for x in ('s0','s1'))
   and src['s0']!=src['s1'] and src['repository'],'Frozen revisions')
 v.update(files=available,trees=trees)
 q(all(l(p,t).is_dir() and any(l(p,z).is_dir() and l(p,t).is_relative_to(l(p,z))
   for z in prep['artifacts']) for t in trees),'Need complete sealed trees')
 states=[{n[len(t)+1:]:h for n,h in available.items() if n.startswith(t+'/')} for t in trees]
 patch=base+'/change.patch';guidance={}
 q(patch in available and base+'/change-message.txt' in available,'Diff/context')
 lines=l(p,patch).read_text(encoding='utf-8').splitlines()
 heads={i+1:x for i,x in enumerate(lines) if x.startswith('diff --git ')}
 q(any(states) and heads and min(heads)==1,'Empty source/diff inspection scope')
 segments={f'd{i//120:05d}':[i+1,min(i+120,len(lines))] for i in range(0,len(lines),120)}
 for name in ('AGENTS.md','PATCHING_GUIDELINES.md','THREAT_MODEL.md'):
  frozen=trees[1]+'/'+name;saved=f'guidance/{g}/{src["s1"]}/{name}'
  q((saved in ins)==(frozen in available) and (frozen not in available
    or available.get(saved)==available[frozen]),'Pinned guidance missing/mismatched')
  guidance[name]=l(p,saved).read_text(encoding='utf-8') if frozen in available else 'Absent in S1'
 prior={e['key']:rd(p,e['file']) if e['file'] in available else None for e in own.values()}
 inventory={f'e{i:06d}':{'path':n,'sha256':h,'source':any(n.startswith(t+'/') for t in trees)}
   for i,(n,h) in enumerate(sorted(available.items()))}
 v.update(prior=prior)
 v['obs']={'evidence':inventory,'changed_files':heads,'segments':segments,'guidance':guidance,
  'content_changes':[n for n in sorted(states[0].keys()|states[1].keys())
   if states[0].get(n)!=states[1].get(n)],'prior':prior,
  'prior_ids':{e['key']:i for i,e in own.items()}}
except (OSError,ValueError,KeyError,TypeError) as e:v['gaps'].append(repr(e))
print(json.dumps(v))"""
RESERVE = """import json,subprocess,sys;from pathlib import Path
data=json.loads(Path(sys.argv[4]).read_text(encoding='utf-8'))\nfor lead in data['leads']:
 argv=['uv','run','--no-project','python','-B',sys.argv[1],'candidate',
       sys.argv[2],sys.argv[3],'--agent',sys.argv[5],'--key',lead['key']]\n try:
  r=subprocess.run(argv,capture_output=True,text=True,timeout=120)
 except (OSError,subprocess.TimeoutExpired) as e:
  row={'argv':argv,'exit_code':None,'error':repr(e),
       'stdout':repr(getattr(e,'stdout',None)),'stderr':repr(getattr(e,'stderr',None))}
 else:row={'argv':argv,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
 print(json.dumps(row),flush=True)\n if row['exit_code']!=0:break
print(json.dumps({'finished':True}),flush=True)"""
MISSING = {"title": "Prior content missing", "status": "blocked"}
GAP = {"inspected": False, "notes": "Uninspected; see blockers", "evidence": []}
ARTIFACTS = ("analysis.json", "inspection.json", "reservation.json")


def require(value: object, message: str) -> None:
    if not value:
        raise ValueError(message)


def diagnostic(error: Exception) -> str:
    if type(error).__name__ == "BudgetExceeded":
        raise error
    logs = (getattr(error, "stdout", None), getattr(error, "stderr", None))
    return f"{error!r}; stdout/stderr={logs!r}"


@c.step
def command(root: Path, argv: list[str], writes: bool = False) -> str:
    result = c.run_command(argv, timeout_seconds=900, working_directory=root, mutating=writes)
    c.emit(result, name="command")
    require(result.exit_code == 0, f"Exit {result.exit_code}: {result.stderr}\n{result.stdout}")
    return result.stdout


def helper(root: Path, script: str, action: str, *args: str) -> str:
    path = {"registry": "scripts/registry.py", "evidence": "scripts/evidence.py"}[script]
    argv = ["uv", "run", "--no-project", "python", "-B", str(c.resource(path)), action]
    return command(root, [*argv, str(root), *args], action == "seal")


def brief(data: dict[str, Any], record: str) -> str:
    gaps = "; ".join(data["limitations"]) or "none"
    return (
        f"Status: {data['status']}\nRecord: {record}\n"
        f"Result: {len(data['candidates'])} candidates; coverage gaps: {gaps}\n"
        f"Blocker: {gaps if data['status'] == 'blocked' else 'none'}"
    )


def validate_analysis(answer: Analysis, plan: dict[str, Any]) -> None:
    seen = set(answer.inspected_evidence)
    inventory = plan["obs"]["evidence"]
    sources = {i for i, entry in inventory.items() if entry["source"]}
    require(seen <= inventory.keys() and answer.summary.strip(), "Unknown evidence/missing summary")
    require(answer.security_review.strip(), "Missing security review")
    require(set(answer.coverage) == set(plan["obs"]["segments"]), "Segment accounting")
    for item in answer.coverage.values():
        require(item.notes.strip() and set(item.evidence) <= seen, "Invalid coverage")
        require(not item.inspected or bool(set(item.evidence) & sources), "Uncited coverage")
    require(len({lead.key for lead in answer.leads}) == len(answer.leads), "Duplicate keys")
    for lead in answer.leads:
        raw = lead.model_dump()
        require(all(v.strip() for k, v in raw.items() if k != "evidence"), "Empty lead")
        require(set(lead.evidence) <= seen and bool(set(lead.evidence) & sources), "Uncited lead")


def analyze(root: Path, plan: dict[str, Any], prior_ids: dict[str, str]) -> dict[str, Any]:
    work: dict[str, Any] = {"values": {}, "analysis": {}, "gaps": list(plan["gaps"])}
    try:
        require(prior_ids == {e["key"]: i for i, e in plan["own"].items()}, "Prior ID mapping")
        require(not work["gaps"], "; ".join(work["gaps"]))
        ctx = c.prepare_context("Hunt the bound change.", prior_results=json.dumps(plan["obs"]))
        answer = c.agent(
            "worker",
            "Perform discovery under the original hunt workflow and references in order. Read "
            "complete frozen evidence and guidance; inspect all numbered diff segments in bounded "
            "chunks, intent/discussion, unchanged callers/interfaces and other security documents. "
            "Cite inspected evidence IDs; explain attacker control/security scope; preserve all "
            "supplied/prior leads, including possible old bugs/incomplete fixes. Account for every "
            "segment/gap. Read task.txt when not embedded. No commands, later research, PoCs or "
            "confirmation. Return typed analysis; host persists files.",
            working_directory=root / plan["trees"][1],
            readable_paths=tuple(root / n for n in plan["files"]),
            context=ctx,
            output=Analysis,
            timeout=3600,
        )
        work["analysis"] = answer.model_dump()
        validate_analysis(answer, plan)
        work["values"] = {lead.key: lead.model_dump() for lead in answer.leads}
        work["gaps"] += answer.blockers + [
            f"{k}: {x.notes}" for k, x in answer.coverage.items() if not x.inspected
        ]
    except Exception as error:
        work["gaps"].append(diagnostic(error))
    return work


def publish(root: Path, plan: dict[str, Any], work: dict[str, Any]) -> str:
    a = plan["a"]
    directory = root / a["directory"]
    for entry in plan["own"].values():
        key = entry["key"]
        if key not in work["values"]:
            work["values"][key] = plan["prior"].get(key) or {"key": key, **MISSING}
            work["gaps"].append(f"Prior lead {key} requires recovery/reassessment")
    payload = {"leads": list(work["values"].values()), "analysis": work["analysis"]}
    c.write_json(directory / "analysis.json", payload)
    c.write_json(directory / "inspection.json", plan)
    reservation = ""
    try:
        reservation = command(
            root,
            [
                "uv",
                "run",
                "--no-project",
                "python",
                "-B",
                "-c",
                RESERVE,
                str(c.resource("scripts/registry.py")),
                str(root),
                a["id"],
                str(directory / "analysis.json"),
                a["agent"],
            ],
            True,
        )
    except Exception as error:
        work["gaps"].append(diagnostic(error))
    c.write_json(directory / "reservation.json", reservation)
    current = json.loads(helper(root, "registry", "show"))
    own = {i: e for i, e in current["candidates"].items() if e["prefix"] == a["prefix"]}
    require(
        all(
            e["change"] == a["change"] and re.fullmatch(re.escape(a["prefix"]) + r"[0-9]{3,}", i)
            for i, e in own.items()
        ),
        "Candidate ownership",
    )
    try:
        rows = [json.loads(x) for x in reservation.splitlines() if x]
        require(rows and rows[-1] == {"finished": True}, "Incomplete reservation command")
        for row in rows[:-1]:
            require(row["exit_code"] == 0, json.dumps(row))
            cid = json.loads(row["stdout"])["candidate"]
            require(cid in own and own[cid]["key"] == row["argv"][-1], "Reservation mismatch")
    except Exception as error:
        work["gaps"].append(diagnostic(error))
    missing = {e["key"] for e in own.values()}.symmetric_difference(work["values"])
    work["gaps"] += [f"Registry/lead mismatch: {sorted(missing)}"] if missing else []
    mapping = {i: f"{a['directory']}/{i}.json" for i in own}
    c.ensure_directory(directory, output_files=tuple(f"{i}.json" for i in own))
    for cid, entry in own.items():
        raw = work["values"].get(entry["key"], MISSING)
        c.write_json(root / mapping[cid], {**raw, "id": cid, "key": entry["key"]})
    analysis = work["analysis"]
    data = {
        **{k: a[k] for k in ("stage", "agent", "change", "inputs")},
        "attempt": a["id"],
        "candidate": None,
        "status": "blocked" if work["gaps"] else "complete",
        "summary": analysis.get("summary") or "Discovery blocked",
        "security_review": analysis.get("security_review") or "Target review incomplete",
        "candidates": sorted(own),
        "candidate_files": mapping,
        "coverage": {
            k: analysis.get("coverage", {}).get(k, GAP) for k in plan["obs"].get("segments", {})
        },
        "limitations": analysis.get("limitations", []) + work["gaps"],
        "artifacts": [f"{a['directory']}/{n}" for n in ARTIFACTS] + list(mapping.values()),
    }
    record = f"{a['directory']}/hunt.json"
    c.write_json(root / record, data)
    helper(root, "evidence", "seal", record)
    helper(root, "evidence", "verify", record)
    helper(root, "registry", "check", a["id"], record)
    return brief(data, record)


@c.recipe(
    name="hunt-regressions",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root=".",
)
def hunt(campaign: str, attempt: str, prior_ids: dict[str, str] | None = None) -> str:
    try:
        root = Path(campaign).absolute()
        require(root.is_dir() and re.fullmatch(r"a[0-9]{3,}", attempt), "Invalid campaign/attempt")
        require(
            ".." not in root.parts and not any(p.is_symlink() for p in (root, *root.parents)),
            "Unsafe campaign",
        )
        plan = json.loads(
            command(
                root,
                [
                    "uv",
                    "run",
                    "--no-project",
                    "python",
                    "-B",
                    "-c",
                    VALIDATE,
                    str(c.resource("scripts/registry.py")),
                    str(root),
                    attempt,
                ],
            )
        )
        a = plan["a"]
        directory, record = root / a["directory"], f"{a['directory']}/hunt.json"
        if (root / record).exists() or (root / (record + ".seal.json")).exists():
            helper(root, "evidence", "verify", record)
            data = json.loads(helper(root, "registry", "check", attempt, record))
            require(data["status"] == "blocked" or not plan["gaps"], "Preparation invalid")
            return c.emit(brief(data, record), name="hunt")
        require(
            a["state"] == "running" and (not directory.exists() or not any(directory.iterdir())),
            "Obtain a new assignment",
        )
        c.ensure_directory(directory, output_files=(*ARTIFACTS, "hunt.json", "hunt.json.seal.json"))
        work = analyze(root, plan, prior_ids or {})
        return c.emit(publish(root, plan, work), name="hunt")
    except Exception as error:
        message = (
            "Status: blocked\nRecord: none; no verified package\n"
            "Result: count unknown; coverage incomplete\n"
        )
        return c.emit(message + f"Blocker: {diagnostic(error)}", name="hunt")


if __name__ == "__main__":
    raise SystemExit(hunt.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("9318487e0acea33c0ebb7d7cfea1dbcf6a041b324c27b8b1a459f0274ed910bf"),
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
        "its generated PEP 723 header. This skill is distributed in"
        "dependently: do not require another unmerged skill recipe."
        " Referenced prose and explicitly provided resources may be"
        " packaged, while the generated recipe belongs only to the "
        "requested skill. Repository contribution rule: a checker t"
        "hat inspects zero items must fail with an explanation rath"
        "er than return a successful clean report. This applies to "
        "an empty inspection scope, not to a completed inspection t"
        "hat finds zero issues.\n\nImplement this one assigned stag"
        "e as native host Python control flow using the actual pinn"
        "ed helpers. Do not emit a single model call asking it to r"
        "un the whole workflow. Producing agent calls have a read-o"
        "nly filesystem: return analysis/code as typed data, then h"
        "ost Python persists it only to host-derived designated pat"
        "hs. Runtime build, deployment, PoC, cleanup and metadata-c"
        "ollection commands may be explicit user-supplied argv/plan"
        " inputs; do not execute tainted model-produced argv or use"
        " fictional platform adapters. Host run_command invocations"
        " use accurate mutating flags: Git reads/verify/check are r"
        "ead-only, snapshot/seal/report/candidate reservation/build"
        "/run/cleanup write. Preserve real exit codes, stderr, time"
        "outs and partial logs; command errors are not empty succes"
        "s. No source execution during generation/dry runs.\n\nRequ"
        "ire a campaign path and exact caller-supplied registry ass"
        "ignment/attempt identifier. Read and validate the actual r"
        "egistry.json, frozen scope/hash, stage/change/candidate/ag"
        "ent/directory/inputs/input_hashes/state and retained launc"
        "h evidence; derive allowed source/record selectors and all"
        " output names from trusted assignment/package records. A w"
        "orker may cite host-enumerated evidence IDs, not choose ar"
        "bitrary read/write/command paths. Validate campaign-relati"
        "ve confinement and reject symlink evidence. Never invent a"
        " launch handle, fresh-context/isolation receipt or verific"
        "ation level. Caller supplies genuinely bound assignments; "
        "absent/invalid binding blocks the stage. Use the original "
        "registry/evidence/runtime helper semantics, not hand-writt"
        "en lookalike receipts. The registry helper is version 3 ev"
        "en though part of the prose still says version 2.\n\nBefor"
        "e target work verify sealed prerequisite packages, assigne"
        "d hashes and full artifact trees, then read/apply pinned t"
        "arget-S1 AGENTS.md, PATCHING_GUIDELINES.md and THREAT_MODE"
        "L.md, accounting for each as copied-and-hash-checked or ex"
        "plicitly absent; fetch unaccounted files from immutable Gi"
        "t objects or block. Provide the full guidance contents to "
        "producing workers. Do not claim security review from filen"
        "ames alone. Use frozen sources/context; later fixes/adviso"
        "ries/reviews are excluded from investigation.\n\nEach stag"
        "e owns only its assigned attempt directory. Never overwrit"
        "e sealed attempts; on intact reusable records verify and r"
        "eturn them, otherwise require a new assignment. Produce th"
        "e exact stage JSON with assigned identity, exact inputs, s"
        "tatus complete/blocked, summary, security_review and compl"
        "ete artifacts. Seal with evidence.py seal CAMPAIGN RECORD,"
        " verify with evidence.py verify, and registry.py check CAM"
        "PAIGN ATTEMPT RECORD before reporting. Only the coordinato"
        "r accepts assignments and changes campaign.json/progress/r"
        "eceipts: this component must not accept records, bind/retr"
        "y agents, rewrite scope/index or fabricate host observatio"
        "ns. Blockers preserve actual collected evidence and exact "
        "missing prerequisites; completion never means regression c"
        "onfirmation. Helpers use uv run --no-project <resource('sc"
        "ripts/NAME.py')> with their actual CLI argument order; pin"
        "ned sibling helper files must remain available. A nonempty"
        " investigation scope is required, while an inspected scope"
        " with zero candidates is valid.\n\nOwn discovery, not repr"
        "oduction or confirmation. Require the sealed accepted prep"
        "aration/source.json, pristine S0/S1, frozen context, exact"
        " hunt assignment and ONLY this assignment's prior hypothes"
        "is-key/ID mapping on retry. Host validates preparation, ac"
        "cepted paths and source hashes before providing the worker"
        " the complete frozen diff, change intent/discussion and ta"
        "rget security guidance. Mechanically enumerate all changed"
        " files and diff segments, require nonempty source/diff ins"
        "pection scope, and account for every segment in coverage; "
        "process bounded chunks when necessary rather than truncate"
        " or choose the first N. Have native read-only workers trac"
        "e changed behavior through actual callers and supported us"
        "er/attacker interfaces, with relevant unchanged context. N"
        "o later-fix research and no PoC execution/construction in "
        "discovery.\n\nEach typed lead must retain stable hypothesi"
        "s key, title, patch intent, previously correct supported b"
        "ehavior, changed code, reachable trigger, possible new def"
        "ect, false-positive checks and proof needed, using host-en"
        "umerated source/evidence selectors. Preserve supplied lead"
        "s that may instead be incomplete fixes or old bugs for lat"
        "er adjudication. Agent claims require cited inspected sour"
        "ce; make limitations and blocked/uninspected regions expli"
        "cit. Discovery can produce zero leads after real coverage;"
        " it must not confirm REPRODUCED_REGRESSION.\n\nThe host re"
        "serves every lead ID by the actual command registry.py can"
        "didate CAMPAIGN ATTEMPT --agent BOUND_HANDLE --key STABLE_"
        "KEY, parses the JSON {candidate: ID}, and checks the retur"
        "ned ID/key against this assignment's prefix. Do not constr"
        "uct IDs yourself, read other hunters' hypotheses into the "
        "producing prompt, or manually edit registry.json. Reuse ke"
        "ys on retry and include ALL IDs already reserved under thi"
        "s assignment's prefix, even when recovering partial work; "
        "dropping old mappings would fail the helper's exact set ch"
        "eck. Preserve missing prior lead content as a blocked lead"
        "/limitation, not silent deletion.\n\nHost writes candidate"
        " JSON files at deterministic paths based on reserved IDs, "
        "then hunt.json with stage='hunt', candidate=null, candidat"
        "es as the complete ID list and candidate_files mapping eve"
        "ry ID to its actual sealed file; include coverage/limitati"
        "ons, every candidate file and analysis evidence as artifac"
        "ts. Call seal, verify and registry check. Do not update ca"
        "mpaign index or accept your own result. Return candidate c"
        "ount and material coverage gaps with complete/blocked inde"
        "pendently from whether leads exist.\n\nNarrow repair of th"
        "e substantive candidate: retain its original-helper assign"
        "ment validation, complete frozen diff/caller/security revi"
        "ew, native ID allocation from persisted lead DATA, no cros"
        "s-hunter exposure, source evidence selectors, all candidat"
        "e mappings and record/seal/check behavior. The actual loca"
        "l Ruff rules are E,F,I,UP,B,SIM,C4,C90,PLR0913,RUF, py313,"
        " line length 100, max-complexity=8. Current hunt complexit"
        "y is 12 and C408 flags dict() at lines 244 and 311. Decomp"
        "ose into MODULE-LEVEL helpers/steps, since nested helper c"
        "omplexity is counted in its enclosing function; use dict l"
        "iterals, keep allowed argument counts, and never suppress "
        "lint or alter configuration.\nAll Python helper invocation"
        "s that are marked read-only must suppress Python bytecode "
        "side effects, including nested helper invocations in the R"
        "ESERVE script. Prefer uv run --no-project python -B <pinne"
        "d SCRIPT> and python -B -c <fixed host code>, preserving a"
        "ctual CLI argument order. Imported sibling helper modules "
        "must not create __pycache__ under the plugin/resource sour"
        "ce tree. Writes, candidate reservation and sealing remain "
        "honestly mutating=True.\nPreserve command launch/timeout f"
        "ailures with stdout/stderr/exit diagnostics. After a valid"
        " bound assignment, retain partial analysis, coverage and a"
        "ny successfully reserved IDs on failure; where valid stage"
        " records can still be constructed, seal a blocked hunt pac"
        "kage instead of dropping the evidence. Never report a comp"
        "leted empty hunt merely because a command/model failed, an"
        "d never omit prior/reserved IDs.\n"
    ),
    "sha256": ("65cd9b0794ac0bc32ffcddc9cb515dec80cbb11060b3e96fbc8fa73dc7706207"),
}
_CALCIFIER_SUBRECIPES = []
