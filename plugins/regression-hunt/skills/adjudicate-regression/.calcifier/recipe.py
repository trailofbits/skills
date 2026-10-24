# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from pathlib import Path
from typing import Any, Literal

import calcifier as cf

PREFLIGHT = (
    "import json, re, sys\nfrom pathlib import Path\n"
    "sys.path.insert(0, str(Path(sys.argv[1]).parent))\n"
    "import registry as r\nimport evidence as e\nimport report as p\n"
    "def require(ok, message):\n    if not ok: raise ValueError(message)\n"
    "def binding(root, data, a):\n"
    "    r.require(a['agent'] and a['launch'], 'Missing bound launch')\n"
    "    e.require = require\n    r.verify_receipt(root, a['launch'])\n"
    "    level = r.receipt_level(a)\n"
    "    require(level == a['verification'], 'Wrong receipt level')\n"
    "    fn = r.host_binding if level == 'isolated' else r.agent_binding\n"
    "    require(level in r.LEVELS, 'Unknown verification level')\n"
    "    receipt = fn(root, data, a, a['agent'], a['launch']['record'])\n"
    "    require(receipt == a['launch'], 'Original binding changed')\n"
    "    r.distinct_candidate_agent(data, a, a['agent'])\n"
    "    require(r.inputs_snapshot(root, a['inputs']) == a['input_hashes'],\n"
    "            'Assignment inputs changed; require a new assignment')\n"
    "def packages(root, data, a):\n"
    "    records, seals, queue = {}, {}, list(a['inputs'])\n"
    "    while queue:\n        name = queue.pop()\n"
    "        if name in seals or not e.local(root, name+'.seal.json').is_file(): continue\n"
    "        e.verify(root, name)\n        seal = e.read(root, name+'.seal.json')\n"
    "        seals[name] = seal\n        queue.extend(seal['dependencies'])\n"
    "    for b in data['attempts'].values():\n"
    "        if b.get('record') not in seals: continue\n"
    "        if b['state'] != 'accepted': continue\n"
    "        binding(root, data, b)\n"
    "        records[b['record']] = r.checked(root, data, b['id'], b['record'])\n"
    "    return records, seals\n"
    "def experiment(root, name, records, source, base):\n"
    "    v = records[name]\n    require(v['status'] == 'complete', name+': blocked')\n"
    "    require(v.get('source') == source, name+': wrong source')\n"
    "    require(set(base) <= set(v['inputs']), name+': missing prerequisites')\n"
    "    runs = v.get('runs', [])\n"
    "    require([x.get('state') for x in runs] == ['S0','S1'], 'Need ordered S0/S1')\n"
    "    pinned = e.read(root, source)\n"
    "    paths = [source, v['setup'], v['poc'], v['workload']]\n"
    "    for x, state, behavior in zip(runs, ('s0','s1'), ('correct','failure'), strict=True):\n"
    "        require(x.get('revision') == pinned[state], name+': wrong revision')\n"
    "        require(x.get('behavior') == behavior, name+': missing differential result')\n"
    "        require(x.get('deployment') and x.get('command'), name+': missing live command')\n"
    "        paths.append(x['log'])\n"
    "    p.bound(root, name, paths)\n"
    "    require(all(e.local(root, x).stat().st_size for x in paths), 'Empty proof file')\n"
    "    return v\n"
    "def proof(root, records, selected, source, base):\n"
    "    x, y = [experiment(root, n, records, source, base) for n in selected]\n"
    "    require(selected[0] in y['inputs'], 'Replay omits reproduction')\n"
    "    logs = [z['log'] for v in (x,y) for z in v['runs']]\n"
    "    require(len(set(logs)) == 4, 'Independent logs required')\n"
    "    require(len({e.local(root,z).resolve() for z in logs}) == 4, 'Aliased logs')\n"
    "    for field in ('poc','workload'):\n"
    "        require(e.digest(e.local(root,x[field])) == e.digest(e.local(root,y[field])),\n"
    "                field+': replay bytes differ')\n"
    "    return {'logs': logs, 'hashes': e.files(root, [x['poc'], x['workload']])}\n"
    "def guidance(root, a, source, files, absent):\n"
    "    result = {}\n"
    "    for g in ('AGENTS.md','PATCHING_GUIDELINES.md','THREAT_MODEL.md'):\n"
    "        copy = f\"guidance/{a['change']}/{source['s1']}/{g}\"\n"
    "        original = str(Path(source_name).parent/'S1'/g)\n"
    "        present = [n for n in (copy,original) if n in files]\n"
    "        require(not (present and g in absent), 'Contradictory guidance absence')\n"
    "        if len(present) == 2:\n"
    "            require(files[copy] == files[original], 'Original/copy guidance mismatch')\n"
    "        require(present or g in absent, 'Unaccounted pinned guidance: '+g)\n"
    "        result[g] = e.local(root,present[0]).read_text() if present else None\n"
    "    return result\n"
    "root = Path(sys.argv[2]).resolve(strict=True)\nplan = json.loads(sys.argv[3])\n"
    "data = r.load(root)\na = r.assigned(data, plan['attempt'])\n"
    "require(r.changes_by_id(e.read(root,data['scope']['file'])['changes'])\n"
    "        == data['scope']['changes'], 'Frozen scope mapping changed')\n"
    "require(a['stage'] == 'adjudicate' and a['agent'] == plan['owner'], 'Wrong owner/stage')\n"
    "require(a['id'] == plan['attempt'] and a['directory'] == 'attempts/'+a['id'],\n"
    "        'Invalid assignment directory')\n"
    "require(a['change'] in data['scope']['changes'], 'Outside frozen scope')\n"
    "require(a['state'] in ('running','accepted'), 'Inactive assignment')\n"
    "r.candidate_input(data,a)\nbinding(root,data,a)\n"
    "name = a['directory']+'/decision.json'\nresult = {'assignment': a, 'name': name}\n"
    "if sys.argv[4] == 'prepare':\n"
    "    if e.local(root,name).exists():\n"
    "        result['reuse'] = r.checked(root,data,a['id'],name)\n"
    "    else:\n"
    "        require(a['state'] == 'running', 'Accepted attempt has no reusable record')\n"
    "        records,seals = packages(root,data,a)\n"
    "        selected = {}\n        gaps = []\n"
    "        for stage in ('prepare','hunt','reproduce','replay'):\n"
    "            choices = [n for n,v in records.items() if v['stage'] == stage\n"
    "                       and v['change'] == a['change'] and\n"
    "                       (stage in ('prepare','hunt') or v['candidate'] == a['candidate'])]\n"
    "            selected[stage] = choices[0] if len(choices) == 1 else None\n"
    "        require(selected['prepare'] and selected['hunt'], 'Need unique prepare/hunt')\n"
    "        prep,hunt = selected['prepare'],selected['hunt']\n"
    "        candidate = data['candidates'][a['candidate']]['file']\n"
    "        require({prep,hunt,candidate} <= set(a['inputs']), 'Missing direct inputs')\n"
    "        require(records[hunt]['candidate_files'][a['candidate']] == candidate,\n"
    "                'Candidate does not match accepted discovery')\n"
    "        for b in data['attempts'].values():\n"
    "            if b['candidate'] != a['candidate'] or b['stage'] not in r.BUILD_STAGES: conti"
    "nue\n"
    "            if b.get('record'):\n"
    "                require(b['record'] in a['inputs'], 'Unassigned available experiment')\n"
    "        source_name = records[prep]['source']\n        p.bound(root,prep,[source_name])\n"
    "        source = e.read(root,source_name)\n"
    "        require(all(re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}',source[k])\n"
    "                    for k in ('s0','s1')) and source['s0'] != source['s1'], 'Bad boundary')\n"
    "        files = e.files(root,a['inputs'])\n"
    "        for n,s in seals.items(): files.update(e.files(root,[n,*s['inputs'],*s['artifacts'"
    "]]))\n"
    "        require(files, 'Empty inspection scope')\n"
    "        guide = guidance(root,a,source,files,plan['absent'])\n"
    "        require(set(plan['known']) <= set(a['inputs']), 'Unassigned novelty evidence')\n"
    "        canonical = None\n"
    "        if plan['comparison']:\n"
    "            require(plan['comparison'] in a['inputs'], 'Unassigned comparison')\n"
    "            canonical = records.get(plan['comparison'])\n"
    "            require(canonical and canonical['stage'] == 'adjudicate', 'Invalid canonical')\n"
    "            require(canonical['candidate'] in data['candidates'], 'Unknown canonical candi"
    "date')\n"
    "        structural = {}\n"
    "        try:\n"
    "            pair = [selected['reproduce'],selected['replay']]\n"
    "            require(all(pair), 'Missing or ambiguous accepted reproduction/replay')\n"
    "            structural = proof(root,records,pair,source_name,[prep,hunt,candidate])\n"
    "            require(records[prep]['status'] == 'complete', 'Preparation blocked')\n"
    "            require(len({a['agent'],*(records[n]['agent'] for n in pair)}) == 3,\n"
    "                    'Need three distinct agents')\n"
    "        except (ValueError,KeyError,TypeError,OSError) as error: gaps.append(str(error))\n"
    "        result.update(records=records, files=files, guidance=guide, source=source,\n"
    "                      selected=selected, gaps=gaps, proof=structural, canonical=canonical)\n"
    "print(json.dumps(result))\n"
)


@cf.output_type
class Plan:
    campaign: str
    attempt: str
    owner: str
    known: list[str]
    comparison: str | None
    deduplicate: bool
    absent: list[Literal["AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md"]]


@cf.output_type
class Check:
    conclusion: Literal["SUPPORTED", "REFUTED", "UNKNOWN", "NOT_APPLICABLE"]
    reason: str
    evidence: list[int]


@cf.output_type
class Judgment:
    status: Literal["complete", "blocked"]
    outcome: Literal[
        "REPRODUCED_REGRESSION",
        "INCOMPLETE_FIX",
        "LATENT_BUG",
        "PREEXISTING_BUG",
        "REJECTED",
        "UNRESOLVED",
    ]
    summary: str
    reason: str
    gap: str
    analysis: str
    security_review: str
    evidence: list[int]
    checks: dict[str, Check]
    category: Literal["VULNERABILITY", "FUNCTIONAL_BUG", "PERFORMANCE", "BUILD_TEST"] | None
    severity: Literal["Low", "Medium", "High", "Critical"] | None
    likelihood: Literal["Low", "Medium", "High"] | None
    severity_reason: str
    likelihood_reason: str
    novelty: Literal["known", "not_found", "unknown"]
    duplicate: bool
    common_root_cause: str


def execute(argv: list[str], mutate: bool = False) -> str:
    result = cf.run_command(argv, timeout_seconds=120, mutating=mutate)
    cf.emit(result, name="command")
    if result.exit_code:
        raise ValueError(f"Exit {result.exit_code}: {result.stdout}\n{result.stderr}")
    return result.stdout


def preflight(plan: Plan, mode: str) -> dict[str, Any]:
    return json.loads(
        execute(
            [
                "uv",
                "run",
                "--no-project",
                "python",
                "-B",
                "-c",
                PREFLIGHT,
                str(cf.resource("scripts/registry.py")),
                plan.campaign,
                plan.model_dump_json(),
                mode,
            ]
        )
    )


def unresolved(error: str) -> dict[str, Any]:
    reason = (
        f"Observed gap: {error}. A missing or contradictory evidence handoff or unavailable "
        "adjudication may explain this gap; the caller must supply intact assigned packages "
        "and restore review before supported behavior, reachability and causality can be decided."
    )
    return {
        "status": "blocked",
        "outcome": "UNRESOLVED",
        "summary": error,
        "reason": reason,
        "gap": error,
        "analysis": reason,
        "security_review": "Review unavailable: " + error,
        "novelty": "unknown",
        "evidence": [],
        "checks": {},
    }


def conclusions(value: dict[str, Any], inventory: dict[str, Any], plan: Plan) -> None:
    keys = (
        "supported_behavior",
        "reachability",
        "introduced_defect",
        "incomplete_fix",
        "latent_bug",
        "preexisting_bug",
        "intentional_change",
        "unsupported_expectation",
        "security_scope",
    )
    assert set(value["checks"]) == set(keys), "Require exactly nine checks"
    assert all(value[k].strip() for k in ("reason", "summary", "analysis", "security_review"))
    assert value["evidence"], "Missing cited decision evidence"
    assert plan.known or value["novelty"] == "unknown", "Novelty unavailable"
    for item in [value, *value["checks"].values()]:
        assert all(
            isinstance(i, int) and 0 <= i < len(inventory["files"]) for i in item["evidence"]
        )
        assert item["reason"].strip(), "Missing reasoning"
        item["evidence"] = [sorted(inventory["files"])[i] for i in item["evidence"]]
    if value["outcome"] == "REPRODUCED_REGRESSION":
        assert not inventory["gaps"] and inventory["proof"], inventory["gaps"]
        assert value["status"] == "complete" and value["severity"] and value["likelihood"]
        assert value["category"] and value["severity_reason"] and value["likelihood_reason"]
        for key in keys:
            expected = "SUPPORTED" if key in keys[:3] else "REFUTED"
            if key == "security_scope":
                expected = "SUPPORTED" if value["category"] == "VULNERABILITY" else "NOT_APPLICABLE"
            check = value["checks"][key]
            assert check["conclusion"] == expected
            assert expected == "NOT_APPLICABLE" or check["evidence"]


def duplicate(value: dict[str, Any], inventory: dict[str, Any], plan: Plan) -> None:
    if not value.pop("duplicate"):
        return
    canonical = inventory["canonical"]
    assert plan.deduplicate and canonical and value["common_root_cause"].strip()
    assert not canonical.get("duplicate_of") and canonical["outcome"] == value["outcome"]
    assert canonical["candidate"] != inventory["assignment"]["candidate"]
    value.update(
        duplicate_of=canonical["candidate"],
        duplicate_changes=[inventory["assignment"]["change"], canonical["change"]],
    )


def review(plan: Plan, inventory: dict[str, Any]) -> dict[str, Any]:
    refs = tuple(
        cf.resource(n)
        for n in (
            "docs/regression-definition.md",
            "docs/report-definitions.md",
            "references/evidence.md",
        )
    )
    context = cf.prepare_context(
        "Adjudicate the complete assigned evidence under the original workflow. Inspect actual "
        "source, setup, PoC, logs and guidance using the complete inventory and read-only files. "
        "Host proof checks establish structure only. Cite zero-based sorted file IDs. Return ex"
        "actly "
        "nine checks with reasons and citations; independently assess all exclusions, security "
        "access/protections, causality, live interfaces, ratings and requested deduplication. "
        "Use assigned known data only for novelty; otherwise unknown. Later fixes/reviews cannot "
        "prove causality. Missing proof is UNRESOLVED with the standard's concise gap/cause/check "
        "paragraph. An evidenced exclusion may lack experiments. Do not execute or repair proof. "
        "Summary is one sentence. Keep detailed reasoning in analysis; no human-verification cl"
        "aim.",
        prior_results=json.dumps({"plan": plan.model_dump(), "inventory": inventory}),
        files=refs,
        readable_roots=refs,
    )
    value = cf.agent(
        "worker",
        context.prompt,
        context=context,
        working_directory=plan.campaign,
        readable_paths=tuple(Path(plan.campaign) / n for n in inventory["files"]),
        output=Judgment,
    ).model_dump()
    conclusions(value, inventory, plan)
    duplicate(value, inventory, plan)
    return value


def report_back(value: dict[str, Any], name: str) -> dict[str, Any]:
    return cf.emit(
        {
            "status": value["status"],
            "record": name,
            "result": {"outcome": value["outcome"], "reason": value["summary"]},
            "gap": value.get("gap", ""),
        },
        name="adjudication",
    )


@cf.recipe(
    agents=("worker",),
    capabilities=("Bash",),
    output_root=".",
    budget=cf.Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def adjudicate(plan: Plan) -> dict[str, Any]:
    bound = preflight(plan, "binding")
    root = Path(plan.campaign).resolve(strict=True)
    assignment, name = bound["assignment"], bound["name"]
    inventory: dict[str, Any] = {}
    try:
        inventory = preflight(plan, "prepare")
        if "reuse" in inventory:
            return report_back(inventory["reuse"], name)
        value = review(plan, inventory)
    except Exception as error:
        if type(error).__name__ in ("BudgetExceeded", "UnmaterializedArtifactError"):
            raise
        value = unresolved(f"{type(error).__name__}: {error}")
    out = root / assignment["directory"]
    assert not out.exists() or not any(out.iterdir()), "Unsealed work requires a new assignment"
    cf.ensure_directory(out, output_files=("decision.json", "decision.json.seal.json"))
    value.update(
        stage="adjudicate",
        agent=plan.owner,
        attempt=plan.attempt,
        change=assignment["change"],
        candidate=assignment["candidate"],
        inputs=assignment["inputs"],
        artifacts=[],
    )
    selected = inventory.get("selected", {})
    value.update(reproduction=selected.get("reproduce"), replay=selected.get("replay"))
    cf.write_json(root / name, value)
    for action in ("seal", "verify"):
        execute(
            [
                "uv",
                "run",
                "--no-project",
                "python",
                "-B",
                str(cf.resource("scripts/evidence.py")),
                action,
                str(root),
                name,
            ],
            action == "seal",
        )
    execute(
        [
            "uv",
            "run",
            "--no-project",
            "python",
            "-B",
            str(cf.resource("scripts/registry.py")),
            "check",
            str(root),
            plan.attempt,
            name,
        ]
    )
    return report_back(value, name)


if __name__ == "__main__":
    raise SystemExit(adjudicate.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("b6e17a31335c210cd1ba0d3e9969d813aeb0b1680bf7ab70de9642a079f70d34"),
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
        "adjudication from real sealed evidence. Require the accept"
        "ed preparation/discovery/candidate and all available exper"
        "iment packages; early evidenced exclusions can lack experi"
        "ments. Verify registry/seals/source identity/receipt integ"
        "rity and use a genuinely fresh bound context distinct from"
        " both reproducer and replayer; never invent identity/isola"
        "tion. Host enumerates the actual available source/setup/Po"
        "C/log/security evidence and supplies contents or pinned re"
        "ad-only roots to a native typed adjudicator; do not ask it"
        " to judge summary strings instead of real files. Do not ex"
        "ecute new proof, modify evidence, or repair missing record"
        "s: return the gap.\n\nAssess the precise new defect and su"
        "pported behavior, real user/attacker reachability and patc"
        "h-introduced causality. Explicitly exclude incomplete_fix,"
        " latent_bug, preexisting_bug, intentional_change, unsuppor"
        "ted_expectation and out-of-scope security. S0-correct/S1-f"
        "ailure alone does not refute a latent defect. For security"
        " identify existing attacker access and the project's actua"
        "l promised protections from supplied threat-model guidance"
        ". Use categories/rating labels and reasons from the pinned"
        " definitions. Check caller-authorized known findings/issue"
        "s/PR data before claiming novelty; if unavailable novelty "
        "must be unknown, without consulting later fixes as causal "
        "proof.\n\nNative host gates must prevent REPRODUCED_REGRES"
        "SION unless accepted complete reproduction AND independent"
        " replay exist for this same candidate/change/source; three"
        " agent handles are distinct; both experiments have ordered"
        " S0/S1 with full expected revisions, real deployment/comma"
        "nds, correct/failure observations and distinct nonempty ac"
        "tual logs; PoC/workload bytes match between experiments; r"
        "eplay explicitly inputs the reproduction; all references a"
        "re seal-bound. Do not rely only on the model promising the"
        "se gates. Produce the exact nine checks, each with conclus"
        "ion/reason/evidence: supported_behavior, reachability, int"
        "roduced_defect SUPPORTED; incomplete_fix, latent_bug, pree"
        "xisting_bug, intentional_change, unsupported_expectation R"
        "EFUTED; security_scope SUPPORTED for VULNERABILITY, otherw"
        "ise NOT_APPLICABLE. UNKNOWN or missing checks prevents con"
        "firmation. The pinned report.py confirmation/check_conclus"
        "ions semantics define structural requirements, though inte"
        "grity alone does not prove reasoning.\n\nOtherwise retain "
        "an evidenced exclusion (INCOMPLETE_FIX/LATENT_BUG/PREEXIST"
        "ING_BUG/REJECTED) or UNRESOLVED for missing/contradictory "
        "proof. UNRESOLVED reason must be the concise observed-gaps"
        "/plausible-causes/resolving-checks paragraph from the stan"
        "dard, not merely 'insufficient evidence'. For requested de"
        "dup preserve change mappings and cite common root cause; n"
        "o unresolved-to-confirmed laundering. Host writes decision"
        ".json stage='adjudicate', assigned candidate, outcome, cit"
        "ed reason/evidence, available reproduction/replay paths an"
        "d, for confirmation, category/severity/likelihood plus rea"
        "sons and nine checks. All evidence paths must be actually "
        "sealed input/artifact files. Seal/verify/registry check. T"
        "ask complete can mean UNRESOLVED; separate stage blockers "
        "from finding outcome. Return outcome and reason without cl"
        "aiming human verification.\n\n\nRepair the supplied SUBSTA"
        "NTIVE NATIVE adjudication candidate (a complete draft from"
        " this request); the retained single-agent baseline is unac"
        "ceptable and is NOT the candidate. The prior XHIGH run exh"
        "austed its global budget after malformed indentation respo"
        "nses; do not reproduce truncated class-only drafts. Preser"
        "ve all native preparation/scope/receipt/input/seal/source "
        "checks, reasoning workflow, nine explicit confirmation che"
        "cks, true experiment identity/log/PoC/workload gates, excl"
        "usions/UNRESOLVED semantics, novelty and requested dedupli"
        "cation, ratings/reasons and sealed decision record.\n\n1. "
        "Solve the actual model-derived selector problem by moving "
        "ALL file reads, helper commands, original/copy hash checks"
        ", source/guidance enumeration and experiment structural va"
        "lidation to deterministic host work over the bound assignm"
        "ent BEFORE calling the worker. Host-select the assigned ac"
        "cepted reproduction/replay for this candidate/change by th"
        "eir actual trusted stage/identity (or explicit caller sele"
        "ctors checked against that assignment); ambiguity is a pro"
        "of gap. Host-compute full structural proof results, nonemp"
        "ty distinct log evidence, actual same PoC/workload hashes "
        "and source/revision identity before model judgment. Give t"
        "he read-only worker this complete evidence and host proof "
        "inventory. After the worker, validate its typed conclusion"
        "s/citations against already-enumerated data; do not use wo"
        "rker-selected proof records/evidence IDs to trigger file r"
        "eads, commands or filesystem contracts. Only host-derived "
        "owned output paths may reach writes/seal commands. Avoid a"
        " shared mutable object that mixes worker results with trus"
        "ted path selectors. Keep required all-available-experiment"
        " inspection and do not drop native proof checks to satisfy"
        " taint lint.\n\n2. Validate the actual original launch usi"
        "ng the shipped registry host_binding/agent_binding and rec"
        "eipt_level helpers (and exact input snapshot/scope/stage/c"
        "hange/candidate/owner), as the other native components do."
        " Hand-written partial launch-field comparisons do not repl"
        "ace the actual helper contract. Never bind/reserve/accept/"
        "forge outer host receipts. Invalid binding blocks before w"
        "rites. Fresh independent adjudicator context is mandatory."
        "\n\n3. Follow the plugin-local Ruff configuration, beyond "
        "portable lint: pinned Ruff 0.14.13, py313, line100; select"
        " E,F,I,UP,B,SIM,C4,C90,PLR0913,RUF; max complexity8 and de"
        "fault argument limit5. Decompose the large native stage in"
        "to MODULE-LEVEL helpers/steps. Nested functions contribute"
        " to outer complexity. No noqa, suppressions or config edit"
        "s. Use dict literals/list unpacking where required.\n\n4. "
        "Every original Python helper and fixed Python preflight wr"
        "apper must launch the Python interpreter through uv's no-p"
        "roject run with bytecode-suppression flag -B, including si"
        "bling-import wrappers, so read-only validation does not cr"
        "eate caches outside the owned attempt. Keep command mutati"
        "on flags accurate.\n\n5. Retain ordinary provider/command "
        "diagnostic failures in an honest sealed blocked UNRESOLVED"
        " decision when binding/ownership allow it. AgentError and "
        "TransientAgentError are RuntimeError subclasses, not top-l"
        "evel exported AgentError symbols. The public RecipeError c"
        "lass is separate; launch/local timeout details have comman"
        "d_failure/stdout/stderr. BudgetExceeded and Unmaterialized"
        "ArtifactError must propagate as honest budget/compiler sup"
        "pression failures rather than fabricated completed judgmen"
        "t. Missing proof means UNRESOLVED with the required concis"
        "e observed-gap/plausible-explanation/resolving-check parag"
        "raph; never classify missing proof as REJECTED. Keep detai"
        "led reasoning and actual evidence references, and no human"
        "-verification claim.\n\n6. Requested deduplication still n"
        "eeds supplied assignment-bound comparison evidence, common"
        "-root-cause reasons, a real canonical candidate and preser"
        "ved change mapping. Pre-read/validate any comparison recor"
        "ds before model judgment; unknown/missing canonical eviden"
        "ce must remain an explicit gap, and unresolved claims cann"
        "ot be promoted by deduplication. Known findings/issues/PR "
        "evidence is only the assigned caller data; novelty must re"
        "main unknown when unavailable, and later fixes/reviews can"
        "not prove causality.\n\n\nONE FORMATTER-ONLY REPAIR of the"
        " now source-reviewed compiled native candidate. It passes "
        "strict local Ruff and preserves the original helper/receip"
        "t/scope/seal contracts, host-owned proof preflight and tar"
        "get selectors, typed Plan/Judgment, nine checks, different"
        "ial log/hash gates, exclusions, novelty/dedup and blocked "
        "evidence behavior. Do not change any of those controls or "
        "interfaces.\n\nThe intact-record reuse branch currently re"
        "turns emit(inventory['reuse']), dumping the complete detai"
        "led decision. The skill's Report Back contract requires on"
        "ly compact status, record, result (outcome plus one-senten"
        "ce reason) and gap, just like the final new-record return."
        " Use the same small module-level formatter/emitter for BOT"
        "H the verified reusable decision and the newly sealed deci"
        "sion, supplying the host-derived decision.json record path"
        ". Keep detailed reasoning only in the existing sealed deci"
        "sion. Do not rewrite/reseal intact reuse or alter artifact"
        "s/metadata/agent behavior. No other change requested; keep"
        " all local lint rules satisfied and no suppressions/config"
        " changes.\n"
    ),
    "sha256": ("bed968e0fe002c80b0763b8a937e3dc5069be938168d049ff275b3da15ea433d"),
}
_CALCIFIER_SUBRECIPES = []
