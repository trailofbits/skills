# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import hashlib
import json
import re
import time
from pathlib import Path as P
from typing import Any, Literal

import calcifier as c

Data = dict[str, Any]
NAMES = ("AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md")
R = "reproduce/receipts"
KINDS = ("finding", "run", "reproduce", "validate", "patch", "prove", "regression", "report-input")
BUNDLE = (
    "references/records.md",
    "scripts/records.py",
    *(f"schemas/{n}.schema.json" for n in KINDS),
)


@c.output_type
class Request:
    repo: str
    run: str
    identity: str
    build: list[str]
    cases: list[Data]
    kind: Literal["runtime", "compile"]
    artifact: str = ""
    diagnostic: str = ""
    timeout: float = 600.0


@c.output_type
class Decision:
    outcome: Literal["reproduced", "not_reproduced", "blocked"]
    observed: str


@c.output_type
class Result:
    record: Data
    record_path: str
    manifest_path: str
    receipts: list[str]


def need(value: object, reason: str) -> None:
    return None if value else c.fail(reason)


def safe(value: str | P) -> P:
    path = P(value).absolute()
    need(not {"..", ".git"}.intersection(path.parts), f"Unsafe path: {path}")
    need(not any(p.is_symlink() for p in (path, *path.parents)), f"Linked path: {path}")
    return path.resolve()


def regular(path: P) -> bool:
    return path.is_file() and not any(x.is_symlink() for x in (path, *path.parents))


def sha(path: str | P) -> str:
    return hashlib.sha256(P(path).read_bytes()).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, allow_nan=False)


def helper(operation: str, path: P) -> list[str]:
    return [
        "uv",
        "run",
        "--no-project",
        "python",
        "-B",
        str(c.resource("scripts/records.py")),
        operation,
        str(path),
    ]


def read(args: list[str], cwd: P) -> str:
    result = c.run_command(args, working_directory=cwd, timeout_seconds=60, mutating=False)
    need(result.exit_code == 0, f"Preflight failed: {args!r}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def guidance(repo: P, run: P, baseline: str) -> dict[str, str]:
    git, texts = ["git", "-C", str(repo)], {}
    for row in read([*git, "ls-tree", baseline, "--", *NAMES], repo).splitlines():
        metadata, name = row.split("\t", 1)
        need(metadata.split()[0] in {"100644", "100755"}, "Guidance requires regular blobs.")
        texts[name] = read([*git, "show", f"{baseline}:{name}"], repo)
    guide, absent = run / "guidance" / baseline, set(NAMES) - texts.keys()
    if not guide.exists():
        texts["source.md"] = f"Baseline: {baseline}\nAbsent: {', '.join(sorted(absent))}\n"
        return {str(guide / name): text for name, text in texts.items()}
    need(regular(guide / "source.md"), "Saved guidance metadata missing.")
    saved = (guide / "source.md").read_text(encoding="utf-8")
    need(
        set(re.findall(r"[0-9a-f]{40}", saved)) == {baseline}
        and {name for name in NAMES if name in saved} == absent,
        "Guidance metadata mismatch.",
    )
    need(
        all(
            regular(guide / n) and (guide / n).read_bytes().decode("utf-8") == texts[n]
            if n in texts
            else not (guide / n).exists()
            for n in NAMES
        ),
        "Guidance mismatch.",
    )
    return {}


def expand(raw: list[str], source: str, p: Data, q: Request) -> list[str]:
    need(
        raw and all(isinstance(v, str) and 0 < len(v) <= 400 and "\0" not in v for v in raw),
        "Supply nonempty string argv arrays.",
    )
    need(not any(p["repo"] + "/" in v for v in raw), "Use relative paths or {artifact}.")
    values = [v.replace("{source}", source).replace("{artifact}", q.artifact) for v in raw]
    need(all(0 < len(v) <= 400 for v in values), "Expanded argv must fit 400 characters.")
    return values


def case_plan(q: Request, p: Data) -> dict[str, str]:
    cases = p["finding"]["repair_scope"]["cases"]
    reps = [i for i, case in enumerate(cases) if case["role"] == "representative"]
    bounded = p["finding"]["repair_scope"]["mode"] == "bounded_class"
    need(
        len(reps) >= (2 if bounded else 1) and len({x["check_id"] for x in cases}) == len(cases),
        "Invalid case scope.",
    )
    need(
        not bounded
        or (len(reps) < len(cases) and len({canonical(x["input"]) for x in cases}) == len(cases)),
        "Need distinct controls.",
    )
    need(len(q.cases) == len(cases), "Supply ordered commands for every planned case.")
    sources, commands = {}, []
    for i, (case, spec) in enumerate(zip(cases, q.cases, strict=True)):
        source = safe(spec["source_file"])
        need(
            spec["check_id"] == case["check_id"]
            and regular(source)
            and source.stat().st_size > 0
            and "{source}" in spec["argv"],
            "Invalid case/source.",
        )
        destination = str(P(p["run"]) / f"reproduce/poc/case-{i}{source.suffix}")
        sources[destination] = source.read_bytes().decode("utf-8")
        commands.append(expand(spec["argv"], destination, p, q))
    p.update(commands=commands, primary=reps[0])
    p["build"] = expand(q.build, list(sources)[reps[0]], p, q)
    need(q.kind != "compile" or p["build"] == commands[reps[0]], "Compile build mismatch.")
    return sources


@c.step
def prepare(q: Request) -> Data:
    repo, run = safe(q.repo), safe(q.run)
    need(repo.is_dir() and run.is_dir(), "Unverified: supply existing repo/run directories.")
    need(not run.is_relative_to(repo) and not repo.is_relative_to(run), "Unverified: nested paths.")
    need(not any((run / n).exists() for n in ("reproduce", "reproduce-checks")), "Stage exists.")
    need(all(not p.is_symlink() and ".git" not in p.parts for p in run.rglob("*")), "Unsafe run.")
    need(regular(run / "finding.json"), "Unverified: supply finding.json.")
    need(not (run / "run.json").exists() or regular(run / "run.json"), "Invalid run.json.")
    finding = json.loads((run / "finding.json").read_text(encoding="utf-8"))
    need(
        finding.get("status") == "hypothesis"
        and finding.get("affected_code")
        and finding.get("repair_scope", {}).get("cases"),
        "Require hypothesis/nonempty scope.",
    )
    read(helper("check", run), repo)
    git = ["git", "-C", str(repo)]
    need(q.identity.strip() and len(q.identity) <= 100 and 0 < q.timeout <= 1800, "Invalid inputs.")
    need(P(read([*git, "rev-parse", "--show-toplevel"], repo).strip()) == repo, "Use repo root.")
    baseline = read([*git, "rev-parse", "--verify", "HEAD^{commit}"], repo).strip()
    clean = not read([*git, "status", "--porcelain", "--untracked-files=no"], repo)
    need(re.fullmatch(r"[0-9a-f]{40}", baseline) and clean, "Require clean tracked HEAD.")
    need(
        all(
            (path := safe(repo / x["path"])).is_relative_to(repo) and regular(path)
            for x in finding["affected_code"]
        ),
        "Affected source missing/escaping.",
    )
    artifact = safe(repo / q.artifact) if q.kind == "runtime" else repo
    need(
        (
            q.kind == "runtime"
            and 0 < len(q.artifact) <= 400
            and artifact != repo
            and not P(q.artifact).is_absolute()
            and artifact.is_relative_to(repo)
        )
        or (
            q.kind == "compile"
            and not q.artifact
            and 0 < len(q.diagnostic.strip()) <= len(q.diagnostic) <= 400
        ),
        "Supply relative artifact or specific diagnostic.",
    )
    p: Data = {
        "repo": str(repo),
        "run": str(run),
        "baseline": baseline,
        "finding": finding,
        "artifact": str(artifact),
    }
    sources = guidance(repo, run, baseline) | case_plan(q, p)
    stems = [
        f"{R}/build",
        "reproduce-checks/manifest",
        "reproduce-checks/check",
        *(f"{R}/case-{i}" for i in range(len(q.cases))),
    ]
    files = [s + e for s in stems for e in (".stdout", ".stderr", ".exit.json")]
    files.extend(
        [
            "finding.json",
            "reproduce/reproduce.json",
            "reproduce/manifest.json",
            f"{R}/commands.json",
            f"{R}/assessment.json",
        ]
    )
    files.extend(str(P(path).relative_to(run)) for path in sources)
    c.ensure_directory(run, output_files=tuple(files), exclude_roots=(repo,), overwrite=True)
    for path, text in sources.items():
        c.write_text(path, text)
    c.write_json(run / R / "commands.json", {k: p[k] for k in ("build", "commands", "baseline")})
    p["protected"] = {
        str(x): sha(x) for x in (*run.rglob("*"), *(c.resource(n) for n in BUNDLE)) if x.is_file()
    }
    return p


@c.step
def execute(args: list[str], cwd: str, stem: str, timeout: float) -> Data:
    started = time.monotonic()
    r: Data = {
        "argv": args,
        "cwd": cwd,
        "exit_code": None,
        "error": None,
        "stdout": "",
        "stderr": "",
    }
    try:
        raw = c.run_command(args, working_directory=cwd, timeout_seconds=timeout, mutating=True)
        r.update(exit_code=raw.exit_code, stdout=raw.stdout, stderr=raw.stderr)
    except c.RecipeError as exc:
        if getattr(exc, "command_failure", None) not in {"launch", "timeout"}:
            raise
        r["error"] = f"{exc}; command API supplied no partial output"
    r["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    c.write_text(stem + ".stdout", r["stdout"])
    c.write_text(stem + ".stderr", r["stderr"])
    c.write_json(stem + ".exit.json", {k: v for k, v in r.items() if k not in {"stdout", "stderr"}})
    return r


def observation(r: Data, case: Data, p: Data, q: Request) -> tuple[bool, bool]:
    if (code := r["exit_code"]) is None or code < 0 or r["error"]:
        return False, False
    failed = code > 0 and any(q.diagnostic in r[k] for k in ("stdout", "stderr"))
    if q.kind == "compile":
        return failed or code == 0, failed
    try:
        lines = r["stdout"].splitlines()
        loaded = [json.loads(x[13:]) for x in lines if x.startswith("PATCH_LOADED ")]
        obs = [json.loads(x[11:]) for x in lines if x.startswith("PATCH_CASE ")]
        valid = (
            lines.count("PATCH_REACHED") == 1
            and lines[-1] == "PATCH_REACHED"
            and len(loaded) == 1
            and loaded[0]["path"] == p["artifact"]
            and regular(P(p["artifact"]))
            and loaded[0]["sha256"] == sha(p["artifact"]) == p["digest"]
            and len(obs) == 1
            and set(obs[0]) == {"input", "actual"}
            and canonical(obs[0]["input"]) == canonical(case["input"])
        )
        equal = canonical(obs[0]["actual"]) == canonical(case["expected"])
        return valid and (code == 0) == equal, valid and code > 0 and not equal
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return False, False


@c.step
def collect(p: Data, q: Request) -> Data:
    root, stem = P(p["run"]), f"case-{p['primary']}" if q.kind == "compile" else "build"
    built = execute(p["build"], p["repo"], str(root / R / stem), q.timeout)
    if q.kind == "runtime" and (built["exit_code"] != 0 or not regular(P(p["artifact"]))):
        return {"outcome": "blocked", "issues": ["Build/artifact."], "witness": p["primary"]}
    p["digest"] = sha(p["artifact"]) if q.kind == "runtime" else ""
    issues, witnesses = [], []
    for i, case in enumerate(p["finding"]["repair_scope"]["cases"]):
        r = (
            built
            if q.kind == "compile" and i == p["primary"]
            else execute(p["commands"][i], p["repo"], str(root / R / f"case-{i}"), q.timeout)
        )
        valid, failed = observation(r, case, p, q)
        if not valid or (case["role"] == "control" and failed):
            issues.append(case["check_id"])
        witnesses.extend([i] if case["role"] == "representative" and failed else [])
    return {
        "outcome": "blocked" if issues else "reproduced" if witnesses else "not_reproduced",
        "issues": issues,
        "witness": witnesses[0] if witnesses else p["primary"],
    }


@c.step
def finish(p: Data, q: Request, native: Data, d: Decision, review: str) -> Result:
    need(d.observed.strip() and len(d.observed) <= 400, "observed requires 1-400 characters.")
    need(all(regular(P(k)) and sha(k) == v for k, v in p["protected"].items()), "Changed input.")
    outcome = (
        d.outcome
        if native["outcome"] != "blocked"
        and (d.outcome != "reproduced" or native["outcome"] == "reproduced")
        else "blocked"
    )
    root, selected = P(p["run"]), p["commands"][native["witness"]]
    record = {
        "schema_version": 1,
        "failure_type": q.kind,
        "outcome": outcome,
        "baseline_commit": p["baseline"],
        "agent": q.identity,
        "observed": d.observed,
        "build_argv": selected if q.kind == "compile" else p["build"],
        "poc_argv": selected if q.kind == "runtime" else [],
        "target_artifact": q.artifact or None,
        "blocker": json.dumps(native) + "\n" + d.observed if outcome == "blocked" else None,
    }
    record |= {"expected_diagnostic": q.diagnostic} if q.kind == "compile" else {}
    c.write_json(
        root / R / "assessment.json",
        {"native": native, "decision": d.model_dump(), "guidance_review": review},
    )
    c.write_json(root / "reproduce/reproduce.json", record)
    if outcome != "blocked":
        finding = json.loads((root / "finding.json").read_text(encoding="utf-8"))
        finding["status"] = outcome
        c.write_json(root / "finding.json", finding)
    for operation in ("manifest", "check"):
        target = root / "reproduce" if operation == "manifest" else root
        r = execute(
            helper(operation, target),
            p["repo"],
            str(root / "reproduce-checks" / operation),
            min(q.timeout, 120),
        )
        need(r["exit_code"] == 0, f"{operation} failed: {r}")
    manifest = root / "reproduce/manifest.json"
    need(regular(manifest), "Unverified dry run: no reproduction manifest.")
    retained = json.loads(manifest.read_text(encoding="utf-8"))["files"]
    need(retained and "reproduce.json" in retained, "Empty/incomplete reproduction package.")
    need(
        all(
            (root / "reproduce" / n).stat().st_size or n.endswith((".stdout", ".stderr"))
            for n in retained
        ),
        "Empty retained file.",
    )
    need(
        all(sha(k) == v for k, v in p["protected"].items() if k != str(root / "finding.json"))
        and c.verify_artifact(manifest, sha256=sha(manifest)),
        "Evidence changed before handoff.",
    )
    receipts = [
        str(x)
        for folder in (R, "reproduce-checks")
        for x in (root / folder).rglob("*")
        if x.is_file()
    ]
    return Result(record, str(root / "reproduce/reproduce.json"), str(manifest), receipts)


@c.recipe(
    agents=("worker",),
    capabilities=("Bash",),
    output_root=".",
    budget=c.Budget(max_agent_calls=4, max_wall_seconds=3600),
)
def reproduce_bug(q: Request) -> Result:
    p = prepare(q)
    views = (p["run"], *(c.resource(n) for n in BUNDLE))
    review = c.agent(
        "worker",
        "Read full pinned guidance, contract, finding, affected sources, "
        "harnesses and commands. Review compliance; return ACCEPT or explain blocker.",
        working_directory=p["repo"],
        readable_paths=views,
        output=str,
        timeout=900,
    )
    native: Data = {"outcome": "blocked", "issues": ["Guidance declined."], "witness": p["primary"]}
    if review == "ACCEPT":
        native = collect(p, q)
    git = ["git", "-C", p["repo"]]
    clean = read([*git, "rev-parse", "HEAD"], P(p["repo"])).strip() == p["baseline"]
    if read([*git, "status", "--porcelain", "--untracked-files=no"], P(p["repo"])) or not clean:
        native = {"outcome": "blocked", "issues": ["Baseline changed."], "witness": p["primary"]}
    decision = c.agent(
        "worker",
        "Finish original reasoning over ALL raw receipts and complete "
        "sources/references: exact claim, invariant, target execution, assertions "
        "versus crashes, loader identity and controls. Host checks bind; observed "
        "requires 1-400 characters. " + json.dumps({"prior_review": review, "host_checks": native}),
        working_directory=p["repo"],
        readable_paths=views,
        output=Decision,
        timeout=900,
    )
    return c.emit(finish(p, q, native, decision, review), name="reproduction")


if __name__ == "__main__":
    raise SystemExit(reproduce_bug.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("af835d87fd4598ad5f09f7b917c4b4914066523f7984b484f81566be7789d513"),
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
        "ain separate from model output.\n\n\nImplement the reprodu"
        "ction stage, including both runtime and compile proof type"
        "s. Suggested caller interface: target_repo, run_dir, agent"
        "_id, build_argv_json, failure_type, poc_source_file, poc_a"
        "rgv_json, target_artifact, expected_diagnostic, plus trust"
        "ed scoped case command specifications if the finding plan "
        "needs multiple inputs. Expose these caller commands rather"
        " than ask a worker to select argv. Use current clean HEAD "
        "as baseline, verify Git status for tracked changes and bin"
        "d the full40-character SHA. Require finding.json, nonempty"
        " affected_code and usable planned input(s), and existing r"
        "un.json when present; source claim/invariant and planned v"
        "alid controls are the test specification.\n\nHost performs"
        " a real baseline build, saves receipts, and runs every pla"
        "nned scoped input/control before any source edit. For runt"
        "ime, copy the supplied unchanged PoC/harness into fixed re"
        "produce/poc paths under the run, use the caller-approved a"
        "rgv against the freshly built relative target_artifact, an"
        "d check the actual PATCH_LOADED JSON observation names the"
        " resolved artifact and its SHA256; PATCH_REACHED must be t"
        "he final stdout line immediately before the assertion (do "
        "not accept a setup crash or a marker mentioned in stderr)."
        " A failing assertion must be distinguishable from unrelate"
        "d failure using PATCH_CASE actual/input vs planned expecta"
        "tion for scoped cases and read-only semantic judgment of t"
        "he raw evidence. A healthy zero return with trustworthy ex"
        "pected observations is not_reproduced; a missing marker/lo"
        "ad identity, timeout, failed build, missing artifact, or u"
        "nreliable observation is blocked. At least one representat"
        "ive must genuinely reproduce, valid controls should be tru"
        "stworthy and must not manufacture bug confirmation. For co"
        "mpile, require the supplied specific expected_diagnostic l"
        "iteral in the actual failed compiler stdout/stderr, record"
        " empty poc_argv, null target_artifact; missing tool or unr"
        "elated diagnostic is blocked. Successful compiler result w"
        "ith reliable evidence is not_reproduced.\n\nUse a bounded "
        "worker semantic call after host executions to judge whethe"
        "r native observations actually establish this exact claim/"
        "invariant. It cannot override host marker/exit/load/input "
        "checks and cannot supply raw receipts. It may reject an ap"
        "parent reproduction as blocked/not_reproduced with reason."
        " Persist reproduce.json schema_version1 with failure_type,"
        " correct baseline/build/poc argv/artifact, outcome, observ"
        "ed, blocker, and agent. Keep observed <=400, identity<=100"
        ", diagnostic<=400; do not drop useful raw receipts to fit "
        "these limits. Update only finding.status: reproduced, not_"
        "reproduced, or unchanged hypothesis for blocked; preserve "
        "every other field including supplied reported and repair_s"
        "cope. Write complete reproduce manifest only after record/"
        "source/receipts are final, run records check, verify nonem"
        "pty retained files and package hash stability. Return actu"
        "al outcome and paths. Do not create validation/patch/proof"
        " records.\n\n\nFocused repair of the substantive retained "
        "taint-clean candidate: the native dry run failed only beca"
        "use its stub run/repo paths violate the correct separation"
        " guard. Preserve the guard and all native build/case/ident"
        "ity/control/manifest behavior. Use calcifier.fail/RecipeEr"
        "ror for actionable preflight failures, yielding an honest "
        "unverified dry run when simulation cannot establish direct"
        "ories or records; do not weaken guards, invent proof, or d"
        "elegate the workflow to a model. Keep trusted native selec"
        "tor context separate from agent-derived summaries. Also ap"
        "ply the plugin-local strict Ruff rules and bytecode-disabl"
        "ed packaged helper/bridge invocations from the updated com"
        "mon brief, decomposing into small module-level helpers rat"
        "her than nested functions.\n\n\nCritical cross-stage porta"
        "bility repair: the retained candidate expands {artifact} t"
        "o an absolute path in the caller baseline checkout and sto"
        "res that path in build/PoC argv. That causes independent v"
        "alidator and arms.py worktrees to load/write the caller's "
        "original artifact, so valid patches cannot satisfy loader "
        "identity. Expand the documented {artifact} placeholder to "
        "the repository-relative target_artifact string in executab"
        "le build/case argv. Resolve the separate host identity-che"
        "ck artifact path as repo/target_artifact only for actual f"
        "ile/hash/loader observations. Retained PoC source paths ma"
        "y remain absolute under the run directory, outside owned w"
        "orktrees. The stored build_argv/poc_argv must execute the "
        "same retained PoC against each cwd's independently built a"
        "rtifact when replayed unchanged by validate-bug/arms.py. R"
        "equire/document portable commands using cwd-relative targe"
        "t-project paths; reject an explicit caller-baseline absolu"
        "te target-artifact selector with an actionable request for"
        " {artifact} or the relative target path instead of silentl"
        "y retaining a nonreplayable argv. Do not rewrite arbitrary"
        " strings or delegate target selection to worker output.\n"
        "\nIf an expected worker/provider failure occurs after nati"
        "ve context/preflight, preserve actual raw diagnostics and "
        "collected receipts and remain blocked/unverified; public A"
        "gentError is not ValueError or OSError. Catch it only arou"
        "nd bounded agent calls when producing an honest failure re"
        "cord is possible. Do not catch BudgetExceeded or erase com"
        "mand failures. An invalid artifact/output boundary must st"
        "ill stop rather than bypass enforcement.\n\n\nSpecific nat"
        "ive taint repair from the last retained source: finish(p,q"
        ',native,d,review) currently does p["finding"]["status"] = '
        "outcome where outcome depends on agent decision d. This ta"
        "ints the entire mutable native p context and all later pat"
        "h/command uses, including generic read/execute, preflight "
        "and agent filesystem contracts. Never write agent-derived "
        "values anywhere in p or q. Load/copy a SEPARATE finding re"
        "cord locally solely for the fixed finding.json write, set "
        "its status there, and keep selector context and all caller"
        " input records immutable. Host path/command/working_direct"
        "ory arguments can use original trusted q input fields or a"
        " separate native-only fixed context. Agent review/decision"
        " records remain distinct and go only to summaries/data pay"
        "loads, never native context updates. Preserve exactly the "
        "published Calcifier model-taint enforcement rather than hi"
        "ding/suppressing it.\n\n\nLatest retained source already f"
        "ixes portable {artifact} expansion, native finding-state s"
        "eparation and unsupported c.AgentError API use. The only n"
        "ext native compiler diagnostic was `forbidden top-level st"
        "atement at line16: Assign` because `NAMES, R = (...), ...`"
        " uses tuple destructuring at module scope. Split it into s"
        "eparate simple constant assignments, preserve substantive "
        "behavior, and return the COMPLETE module source. Top-level"
        " constant destructuring is unsupported by published Calcif"
        "ier 0.2.0; do not introduce aliases for unsupported API cl"
        "asses. If retaining provider failures around agent calls, "
        "the published general AgentError inherits RuntimeError, so"
        " a narrow built-in RuntimeError catch around those calls m"
        "ay retain the actual diagnostic and honestly block without"
        " catching BudgetExceeded. No `calcifier.AgentError` top-le"
        "vel export exists. Do not replace this real execution work"
        "flow with a delegated wrapper. Follow all current strict R"
        "uff rules (especially C408 dict literals and RUF005 list/t"
        "uple unpacking), unchanged real native guards and Python-B"
        " helpers. Do not store model values in p/q/native selector"
        " contexts, nor mix model content and host selector names i"
        "n zip bindings.\n"
    ),
    "sha256": ("aece76bb4e7616309570caacb4268e8aedf4391ec9e75532650533b3caebae6b"),
}
_CALCIFIER_SUBRECIPES = []
