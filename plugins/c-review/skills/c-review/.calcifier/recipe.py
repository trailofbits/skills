# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from pathlib import Path
from shutil import which
from typing import Any, Literal

import calcifier as c


@c.output_type
class Detect:
    is_cpp: bool
    is_posix: bool
    is_windows: bool
    platform_evidence: str
    purpose: str
    entry_points: list[str]
    trust_boundaries: list[str]
    existing_hardening: list[str]
    state_structs: list[str]
    class_evidence: dict[str, tuple[bool, str]]


@c.output_type
class Finding:
    bug_class: str
    title: str
    file: str
    line: int
    function: str
    unit_id: str
    confidence: Literal["High", "Medium", "Low"]
    description: str
    code: str
    data_flow: str
    reachability: str
    impact: str
    mitigations_checked: str
    recommendation: str
    outside_assigned_classes: bool
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    attack_vector: Literal["Remote", "Local", "Both"]
    exploitability: Literal["Reliable", "Difficult", "Theoretical"]
    severity_rationale: str


@c.output_type
class Ledger:
    unit_id: str
    question: str
    verdict: Literal["clean", "finding", "needs-human", "not-applicable"]
    sites_accounted: list[int]
    evidence: str


@c.output_type
class Part:
    findings: list[Finding]
    ledger: list[Ledger]
    pointers: list[tuple[str, int, str]]
    notes: str


HOST = (
    "import json,re,runpy,sys\nfrom pathlib import Path\nmode,directory,assembler,enumerator,workfl"
    'ow=sys.argv[1:]; o=Path(directory)\ndef read(n): return json.loads((o/n).read_text(encoding="u'
    'tf-8"))\ncfg=read("config.json")\nif mode=="detect":\n e=runpy.run_path(enumerator)\n u=e["bui'
    'ld"](Path(cfg["findingScopeRootAbs"]),cfg["exclude"],"auto",cfg["maxUnitLines"],cfg["reviewAge'
    'nts"],cfg["linesPerAgent"],4,max(14,cfg["reviewAgents"] or 0))\n assert u["units"] and u["assi'
    'gnments"] and u["totals"]["checks_required"]>0,"Zero units or checks: nothing was inspected"\n'
    ' e["write_outputs"](u,o)\n print(json.dumps(dict(jobs=[dict(stem="detect",prompt="detectPrompt'
    '",totals=u["totals"])]))); sys.exit()\nu=read("units.json"); d=read("detect.json")\nif mode=="'
    'report":\n r=read("recovery.json"); z=read("assembly.json"); ns=("findings.json","REPORT.md","'
    'REPORT.sarif","ledger-gate.json")\n written=all((o/n).is_file() for n in ns); s=json.loads(z["'
    'stdout"]) if z["exit_code"] in (0,1) else {}\n partial=bool(r["partial"] or z["exit_code"] or '
    'not written or s.get("ignored_fields") or s.get("unrecognised_parts") or not s.get("checks_req'
    'uired") or s.get("checks_satisfied")!=s.get("checks_required"))\n g=read("ledger-gate.json") i'
    'f written else None\n report=(o/"REPORT.md").read_text(encoding="utf-8") if written else "No r'
    "eport was written. Parts remain intact; fix assembly and use recovery.json. No false-positive "
    'review ran."\n v=dict(partial=partial,artifactsWritten=written,coverage=g,counts={k:s.get("che'
    'cks_"+k) for k in ("satisfied","required","completed")},recovery=r,assembly=z,entries=sorted(p'
    '.name for p in o.iterdir()),artifacts=[str(o/n) for n in (*ns,"units.json","detect.json","part'
    's/","assignments/")])\n text=("PARTIAL AUDIT.\\n\\n" if partial else "")+"Findings may be wron'
    'g or out of scope; severities are unreviewed.\\n\\n"+report+"\\nCoverage (completed means answ'
    'ered), exact gaps and routing:\\n"+json.dumps(v,indent=2)\n print(json.dumps(dict(text=text,pa'
    'rtial=partial))); sys.exit()\nstate=read(mode+"-state.json"); a=runpy.run_path(assembler)\njs='
    'Path(workflow).read_text(encoding="utf-8")\nbody=js.split("const CLASSES = {",1)[1].split("\\n'
    '}\\n",1)[0]\ncs={(x or y):{k:bool(re.search("^    "+k+":",b,re.M)) for k in ("evidence","posix'
    '","skipRemote")} for x,y,b in re.findall(r"^  (?:\'([^\']+)\'|(\\w+)): \\{\\n(.*?)^  },?$",bod'
    'y,re.M|re.S)}\ngs=[re.findall(r"\'([^\']+)\'",s) for s in js.split("const GROUPS = [",1)[1].sp'
    'lit("\\n]",1)[0].splitlines() if "classes: [" in s]\nassert len(cs)==56 and len(gs)==18\nev={r'
    'e.sub(r"[-_\\s]+","-",e["bug_class"].strip().lower()):e for e in d["class_evidence"]}\nassert '
    'set(ev)=={k for k,v in cs.items() if v["evidence"]} and len(ev)==len(d["class_evidence"]),"Det'
    'ect must answer every gateable class once"\nassert all(e["citation"].strip() for e in ev.value'
    's()),"Detect omitted a citation or reason"\nstems=["review-"+v["id"] for v in u["assignments"]'
    ']\nif mode=="review":\n print(json.dumps(dict(jobs=[dict(stem=s,prompt="reviewPrompt",assignme'
    'nt=dict(id=v["id"],path=str(o/"assignments"/(v["id"]+".json"))),detect=d) for s,v in zip(stems'
    ',u["assignments"],strict=True)]))); sys.exit()\nif mode!="sweep": stems += [j["stem"] for j in'
    ' read("sweep.json")["jobs"]]\nparts=[(s,read("parts/"+s+".json")) for s in stems if (o/"parts"'
    '/(s+".json")).is_file()]\ngot=a["collect"](parts,scope_root=(cfg["findingScopeRootAbs"],cfg["f'
    'indingScopeRoot"]))\npresent={f["bug_class"] for f in got.findings.values()}; selected=[]; dro'
    'pped=[]; ruled=[]; sweep=[]\nfor g in gs:\n gid,title,*ids=g; gate=ids.pop(0) if ids[0] in ("i'
    's_cpp","is_windows") else ""; live=[]\n for k in ids:\n  why=gate if gate and not d[gate] else'
    ' "not POSIX" if cs[k]["posix"] and not d["is_posix"] else "REMOTE" if cs[k]["skipRemote"] and '
    'cfg["threatModel"]=="REMOTE" else ""\n  if why: dropped.append(k+" ("+why+")")\n  else: live.a'
    "ppend(k)\n if live: selected.append(gid)\n wanted=[k for k in live if k not in present and (no"
    't cs[k]["evidence"] or ev[k]["has_candidates"])]\n ruled += [k for k in live if k not in prese'
    "nt and k not in wanted]\n if wanted: sweep.append(dict(group=dict(id=gid,title=title),classIds"
    '=wanted))\nif mode=="sweep":\n jobs=[dict(stem="sweep-classes",prompt="classSweepPrompt",group'
    's=sweep,detect=d,evidenceById={k:e["citation"] for k,e in ev.items()})] if sweep else []\n if '
    'cfg["invariantAudit"]: jobs.append(dict(stem="sweep-invariants",prompt="invariantSweepPrompt",'
    'structs=d["state_structs"],detect=d))\n print(json.dumps(dict(jobs=jobs,selected=selected,drop'
    'ped=dropped,ruled=ruled,groups=sweep))); sys.exit()\np=read("sweep.json"); planned={k for g in'
    ' p["groups"] for k in g["classIds"]}\nrows=(state.get("sweep-classes",{}).get("result") or {})'
    '.get("ledger",[])\nanswered={r["question"] for r in rows if r["unit_id"]=="(sweep)" and r["evi'
    'dence"].strip() and r["verdict"]!="needs-human"}\nmissing=sorted(planned-answered); failures=['
    's+": worker failed" for s,r in sorted(state.items()) if r["result"] is None]\nm=a["tier1"](got'
    '.findings); a["tier1_5"](got.findings,m); buckets={}\nfor k,b in a["collision_buckets"](got.fi'
    "ndings,m).items(): buckets.setdefault(b,[]).append(got.findings[k])\nsent=[]; used=0\nfor b in"
    ' buckets.values():\n if used+len(b)<=40: sent.append(b); used+=len(b)\nif mode=="dedup":\n pri'
    'nt(json.dumps(dict(jobs=[dict(stem="dedup-agent",prompt="dedupPrompt",buckets=sent)] if sent e'
    'lse [],buckets=sent))); sys.exit()\nargv=["--run-dir",directory,"--no-judge"]\nfor flag,key in'
    ' (("threat-model","threatModel"),("severity-filter","severityFilter"),("scope","findingScopeRo'
    'ot"),("scope-abs","findingScopeRootAbs"),("context-roots","contextRoots"),("worker-model","wor'
    'kerModel")): argv+=["--"+flag,cfg[key]]\nfailed=[g["group"]["id"] for g in p["groups"] if set('
    'g["classIds"]) & set(missing)]\nargv+=["--groups-attempted",",".join(p["selected"]),"--groups-'
    'failed",",".join(failed)]\nif cfg["benchmarkMode"]: argv.append("--benchmark-mode")\nfor s in '
    'stems:\n r=state[s]["result"]; argv+=["--expect",s if r is None else s+"="+str(len(r["findings'
    '"]))]\n if r and r["findings"] and all(all(f[k] for k in a["REQUIRED_FINDING_FIELDS"]) for f i'
    'n r["findings"]): argv+=["--expect-complete",s]\n if r is not None and cfg["benchmarkMode"]: a'
    'rgv+=["--external-source",s+"="+str(int(r["external_sources_consulted"]))]\nargv += [v for f i'
    'n failures for v in ("--agent-failure",f)]\nprint(json.dumps(dict(argv=argv,agentFailures=fail'
    "ures,groupsFailed=failed,unsearchedClasses=missing,silentClasses=sorted(planned-present-set(mi"
    'ssing)),ruledOutClasses=p["ruled"],platformDroppedClasses=p["dropped"],unauditedStateStructs=['
    '] if cfg["invariantAudit"] else d["state_structs"],reachabilityConfidenceReduced=cfg["narrowCo'
    'ntext"],dedupLeftUnmerged=sum(len(b) for b in buckets.values())-used,enumeration=u["totals"],e'
    'xcluded=u["excluded"],parseDegraded=u["parse_degraded"],partial=bool(failures or missing or go'
    "t.notes or got.incomplete))))\n"
)
PROMPT = (
    "Read all complete references. Follow the named JS prompt's reasoning, order and checks. "
    "Bind config to its JS constants. Host owns commands, enumeration and persistence; return "
    "full typed data instead. Detect performs jobs 2-4 and context; class_evidence maps ids "
    "to [has_candidates,citation]. Part pointers are [file,line,note]. Benchmark output is "
    "[Part,external_sources_consulted,external_sources_detail]. Dedup output is a list of "
    "[primary,duplicates,rationale]. Read whole assigned targets; searches guide reading. "
    "File every issue regardless of severity. Do not edit files. References and task data:\n"
)


@c.recipe(
    name="c-review",
    agents=("worker",),
    capabilities=("Bash",),
    output_root="c-review-results",
    budget=c.Budget(max_agent_calls=136, max_wall_seconds=3600),
)
def c_review(
    project: str,
    threat_model: Literal["REMOTE", "LOCAL_UNPRIVILEGED", "BOTH"],
    worker_model: Literal["haiku", "sonnet", "opus", "inherit"],
    severity_filter: Literal["all", "medium", "high"],
    scope_subpath: str = ".",
    narrow_context: bool = False,
    max_unit_lines: int = 150,
    lines_per_agent: int = 1500,
    review_agents: int | None = None,
    invariant_audit: bool = False,
    exclude: tuple[str, ...] = (),
    benchmark_mode: bool = False,
) -> str:
    if not 40 <= max_unit_lines <= 100000 or not 200 <= lines_per_agent <= 1000000:
        c.fail("Use max_unit_lines=40..100000 and lines_per_agent=200..1000000.")
    if (review_agents is not None and not 1 <= review_agents <= 64) or "" in exclude:
        c.fail("Use review_agents=1..64 and nonempty exclude patterns.")
    repo, scope = Path(project).resolve(), (Path(project) / scope_subpath).resolve()
    if Path(scope_subpath).is_absolute() or not scope.is_relative_to(repo) or not scope.is_dir():
        c.fail("Supply an existing repo-relative scope_subpath inside project.")
    if worker_model != "inherit" or which("uv") is None:
        c.fail("Install uv; configure the desired worker provider model and pass inherit.")
    context, cap = (scope if narrow_context else repo), max(14, review_agents or 0)
    ids = [f"unit-{i:02d}" for i in range(1, cap + 1)]
    phases = ("detect", "review", "sweep", "dedup", "assemble")
    artifacts = ("findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json")
    names = [
        *artifacts,
        "units.json",
        "config.json",
        "recovery.json",
        "assembly.json",
        *[p + ".json" for p in phases[:4]],
        *[p + "-state.json" for p in phases],
        *[f"assignments/{i}.json" for i in ids],
        *[f"parts/review-{i}.json" for i in ids],
        "parts/sweep-classes.json",
        "parts/sweep-invariants.json",
        "parts/dedup-agent.json",
        *[f"{n}.{suffix}" for n in artifacts for suffix in ("partial", "prev")],
    ]
    out = c.ensure_directory(".", output_files=tuple(names), exclude_roots=(repo,)).resolve()
    if any(out.iterdir()):
        c.fail("Use a fresh --output-dir outside the audited project.")
    cfg = dict(
        threatModel=threat_model,
        severityFilter=severity_filter,
        workerModel=worker_model,
        findingScopeRoot=scope_subpath,
        findingScopeRootAbs=str(scope),
        contextRoots=str(context),
        benchmarkMode=benchmark_mode,
        invariantAudit=invariant_audit,
        narrowContext=narrow_context,
        maxUnitLines=max_unit_lines,
        linesPerAgent=lines_per_agent,
        reviewAgents=review_agents,
        exclude=exclude,
        outputDir=str(out),
    )
    c.write_json("config.json", cfg)
    enum, assembler, workflow = (
        c.resource(p)
        for p in (
            "scripts/enumerate_units.py",
            "scripts/assemble_findings.py",
            "workflows/c-review.js",
        )
    )
    refs = (workflow, c.resource("plugin/AGENTS.md"), c.resource("agents/c-review-worker.md"))
    pins = json.loads(
        enum.read_text(encoding="utf-8").split("# dependencies = ", 1)[1].splitlines()[0]
    )
    launch = [
        "uv",
        "run",
        "--no-project",
        *[x for p in pins for x in ("--with", p)],
        "python",
        "-B",
    ]
    records: dict[str, Any] = {}

    def host(phase: str) -> Any:
        r = c.run_command(
            launch + ["-c", HOST, phase, str(out), str(assembler), str(enum), str(workflow)],
            timeout_seconds=3600,
            working_directory=out,
            mutating=phase == "detect",
        )
        if r.exit_code:
            c.fail("Host phase failed; completed parts remain intact: " + r.stderr)
        return json.loads(r.stdout)

    def produce(job: dict[str, Any]) -> dict[str, Any]:
        try:
            schema = (
                Detect
                if job["stem"] == "detect"
                else list[tuple[str, list[str], str]]
                if job["stem"] == "dedup-agent"
                else tuple[Part, bool, str]
                if benchmark_mode
                else Part
            )
            value = c.agent(
                "worker",
                PROMPT + json.dumps(dict(references=[str(p) for p in refs], config=cfg, job=job)),
                working_directory=context,
                readable_paths=(context, out, *refs),
                output=schema,
                timeout=3600,
            )
            part = value[0] if isinstance(value, tuple) else value
            data = (
                dict(merges=[dict(primary=m[0], duplicates=m[1], rationale=m[2]) for m in part])
                if isinstance(part, list)
                else part.model_dump()
            )
            if isinstance(part, Part):
                if any(f.line < 1 for f in part.findings) or any(p[1] < 1 for p in part.pointers):
                    c.fail("Finding and pointer lines must be positive.")
                data["pointers"] = [dict(file=p[0], line=p[1], note=p[2]) for p in part.pointers]
            if isinstance(value, tuple):
                data.update(external_sources_consulted=value[1], external_sources_detail=value[2])
            return dict(result=data, error="")
        except Exception as exc:
            if type(exc).__name__ == "BudgetExceeded":
                raise
            return dict(result=None, error=str(exc))

    for phase in phases[:4]:
        c.write_json(phase + "-state.json", records)
        plan = host(phase)
        if phase != "detect":
            c.write_json(phase + ".json", plan)
        for job, record in zip(
            plan["jobs"], c.parallel(produce, plan["jobs"], max_workers=cap), strict=True
        ):
            records[job["stem"]] = record
            if (data := record["result"]) is not None:
                if phase == "detect":
                    data["class_evidence"] = [
                        dict(bug_class=k, has_candidates=v[0], citation=v[1])
                        for k, v in data["class_evidence"].items()
                    ]
                if phase == "dedup":
                    buckets = {f["key"]: i for i, b in enumerate(plan["buckets"]) for f in b}
                    data["merges"] = [
                        dict(
                            primary=m["primary"],
                            rationale=m["rationale"],
                            duplicates=[
                                k
                                for k in m["duplicates"]
                                if buckets.get(k) == buckets[m["primary"]]
                            ],
                        )
                        for m in data["merges"]
                        if m["primary"] in buckets
                    ]
                path = "detect.json" if phase == "detect" else "parts/" + job["stem"] + ".json"
                c.write_json(path, data)
    c.write_json("assemble-state.json", records)
    recovery = host("assemble")
    recovery["command"] = launch + [str(assembler), *recovery["argv"]]
    c.write_json("recovery.json", recovery)
    r = c.run_command(recovery["command"], timeout_seconds=3600, working_directory=out)
    c.write_json("assembly.json", dict(exit_code=r.exit_code, stdout=r.stdout, stderr=r.stderr))
    result = host("report")
    c.emit(result["text"], name="report")
    if result["partial"]:
        c.fail("Partial audit; see report, ledger-gate.json, assembly.json and recovery.json.")
    return result["text"]


if __name__ == "__main__":
    raise SystemExit(c_review.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("3fc2fc7f3dba9decd2dd9e449150395cf62ee156c8dd1c48d09a233318f4dc69"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/c-review-worker.md",
        "sha256": ("b8ec27017b4ca2d58b295fde42172ed073460d698b6cbe1b95cd0e258ea53a20"),
        "size": 1925,
        "source": "../../agents/c-review-worker.md",
    },
    {
        "path": "plugin/AGENTS.md",
        "sha256": ("92e9e1d8765494b65efebccbb4b5c8468ba2790eef14fd6e85e855502bf301c6"),
        "size": 20950,
        "source": "../../AGENTS.md",
    },
    {
        "path": "scripts/assemble_findings.py",
        "sha256": ("bd34c140891db01b8009c20e61c204ddd6dcc5062634c1ee2db5c35bf5d4e21c"),
        "size": 94893,
        "source": "../../scripts/assemble_findings.py",
    },
    {
        "path": "scripts/check_ledger.py",
        "sha256": ("a24898bd9cac8e0c74b0934a676a1332275a676bd5e26b3ffec0d74c0e31ca86"),
        "size": 44399,
        "source": "../../scripts/check_ledger.py",
    },
    {
        "path": "scripts/enumerate_units.py",
        "sha256": ("13bbfbfcce11d07b44534754b430580de329c5964e1795d80405749ab975723b"),
        "size": 79164,
        "source": "../../scripts/enumerate_units.py",
    },
    {
        "path": "scripts/findings_model.py",
        "sha256": ("64c25a8535eb0abca19b1dfc93ab73f56616efd5892ce2dc9018306f99a60b62"),
        "size": 20460,
        "source": "../../scripts/findings_model.py",
    },
    {
        "path": "scripts/generate_sarif.py",
        "sha256": ("c68085761b699c15a6ae80bb95f18867b2181374b8f5033fe38278a1f5ec9d9e"),
        "size": 20949,
        "source": "../../scripts/generate_sarif.py",
    },
    {
        "path": "scripts/render_report.py",
        "sha256": ("f219ac95feccf36cc30dec5059f700686d0da3e1cf561fccbb0765a882907d00"),
        "size": 22526,
        "source": "../../scripts/render_report.py",
    },
    {
        "path": "workflows/c-review.js",
        "sha256": ("b943d67343730854d43b495016c2e6ac03e0d5ef384591a02e6a2ed3a2cd889f"),
        "size": 131395,
        "source": "../../workflows/c-review.js",
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
        "ed inspection that finds zero issues.\n\nThe previous acce"
        'pted candidate delegates its entire audit to tool("Workflo'
        'w")\nand asks parameters with tool("AskUserQuestion"). Cal'
        "cifier does not ship adapters\nfor either capability; that"
        " candidate cannot run using its documented builtin\nprovid"
        "ers and adds no Python control over the actual review pipe"
        "line.\n\nGenerate an independently runnable Python orchest"
        "ration using Calcifier native\nprimitives and the existing"
        " c-review Python helpers. The complete original JS\nworkfl"
        "ow, plugin AGENTS.md, helper scripts, and agent references"
        " are now explicit\npackaged resources for fidelity. Use re"
        "source() paths to these exact pinned helpers;\ndo not sear"
        "ch ~/.claude caches or depend on an arbitrary installed pl"
        "ugin version.\nTranslate the workflow mechanics and keep i"
        "ts domain reasoning with the workers.\nUse explicit typed "
        "recipe inputs for required user choices; fail with actiona"
        "ble\nmissing-input guidance rather than requiring an inter"
        "active tool adapter.\n\nThe configured worker is builtin C"
        "laude with read/write tools and NO shell. All\nproducing r"
        "eview/sweep/dedup workers must retain that enforced tool r"
        "estriction.\nThe Python host runs enumeration, assignment "
        "preparation, persistence, ledger\ncoverage checks, and ass"
        "embly with the original helpers. Preserve the original\nsi"
        "te-count binding, stable expected-part counts, incomplete-"
        "agent accounting,\ncoverage failures and recovery evidence"
        ". Do not add a false-positive judge or\npre-filter investi"
        "gations by severity; severity filtering belongs after revi"
        "ew.\nFail on zero inspected units/checks. Do not claim inc"
        "omplete audits are clean.\nReturned model content must nev"
        "er select filesystem contract paths, command\narguments or"
        " artifact paths; derive those from trusted inputs, fixed p"
        "ass plans\nand deterministic enumeration outputs. Keep pat"
        "hs for worker outputs fixed by\nthe host. Avoid nonstandar"
        "d tool providers; native agent(), run_command(),\nresource"
        "(), typed outputs, and fixed host artifact primitives are "
        "sufficient.\n\nThe last candidate only called fail() and p"
        "erformed no review. It is rejected.\nThe compiler now rece"
        "ives the complete exact staged resource contents as refere"
        "nce\ndata in its input; translate the actual helper contra"
        "cts from that text. The no-shell\nrestriction applies only"
        " to producing audit workers. It does not forbid the Python"
        "\nhost from running the pinned helpers. Preserve a real ex"
        "ecutable review pipeline.\n"
    ),
    "sha256": ("889a949ddec13fc607fda36945fbb10fa4d247a06c3218d018660f267bccf9cd"),
}
_CALCIFIER_SUBRECIPES = []
