# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
    agent,
    emit,
    ensure_directory,
    output_type,
    recipe,
    resource,
    run_command,
    write_json,
)


@output_type
class Assessment:
    boundary: str
    security_review: str
    limitations: list[str]
    blocker: str | None


@output_type
class StageResult:
    status: Literal["complete", "blocked"]
    record: str | None
    result: str
    blocker: str | None


VALIDATE = (
    "import json,runpy,sys; from pathlib import Path; r=Path(sys.argv[2]).resolve(stric"
    "t=True)\nsys.path.insert(0,str(Path(sys.argv[1]).parent)); m=runpy.run_path(sys.arg"
    "v[1])\nd=m['load'](r); a=m['assigned'](d,sys.argv[3]); q=m['require']\nq((a['id'],a["
    "'stage'],a['candidate'])==(sys.argv[3],'prepare',None),'Assignment')\nc=m['changes_"
    "by_id'](m['read'](r,d['scope']['file'])['changes'])\nq(c==d['scope']['changes'] and"
    " a['change'] in c,'Frozen scope changed')\nq(a['state'] in ('running','accepted') a"
    "nd a['agent'],'Unbound or inactive assignment')\nq(a['verification'] in ('isolated'"
    ",'shared-host'),'Missing launch verification')\nb=m['host_binding'] if a['verificat"
    "ion']=='isolated' else m['agent_binding']\nq(b(r,d,a,a['agent'],a['launch']['record"
    "'])==a['launch'],'Launch changed')\nq(m['inputs_snapshot'](r,a['inputs'])==a['input"
    "_hashes'],'Inputs changed')\nq(a['directory']=='attempts/'+a['id'],'Dir'); m['local"
    "'](r,a['directory'])\nm['prerequisite_changes'](r,a['change'],a['inputs'])\nviews=se"
    "t(a['input_hashes']); pending=list(a['inputs']); seen=set()\nwhile pending:\n n=pend"
    "ing.pop(); p=n+'.seal.json'\n if n not in seen and m['local'](r,p).is_file():\n  see"
    "n.add(n); s=m['read'](r,p)\n  views.update(s['inputs']|s['artifacts']); pending.ext"
    "end(s['dependencies'])\nprint(json.dumps({'assignment':a,'input':c[a['change']],'vi"
    "ews':sorted(views)}))\n"
)


def need(value: object, message: str) -> None:
    if not value:
        raise ValueError(message)


class Preparation:
    def __init__(self) -> None:
        self.logs: list[dict[str, Any]] = []
        self.obs: dict[str, Any] = {"collected_at": datetime.now(UTC).isoformat()}
        self.s0 = self.s1 = ""
        self.source: str | None = None
        self.notes: Assessment | None = None
        self.limits: list[str] = []
        self.recording = False
        self.excluded: tuple[Path, ...] = ()
        self.files = [
            "prepare.json",
            "prepare.json.seal.json",
            "observations.json",
            "assessment.json",
        ]
        self.files += [
            "snapshot/" + p for p in ["source.json", "change.patch", "change-message.txt"]
        ]

    def save_log(self) -> None:
        if self.recording:
            name = f"diagnostic-{len(self.logs):04}.json"
            ensure_directory(self.own, output_files=(name,), exclude_roots=self.excluded)
            write_json(self.own / name, self.logs[-1])

    def command(self, argv: list[str], mutating: bool = False) -> str:
        log: dict[str, Any] = {"argv": argv, "mutating": mutating, "timeout_seconds": 3600}
        self.logs.append(log)
        try:
            result = run_command(argv, timeout_seconds=3600, mutating=mutating)
            log.update(exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr)
            need(result.exit_code == 0, f"Exit {result.exit_code}: {argv}: {result.stderr}")
            return result.stdout
        except Exception as error:
            log.update(error=traceback.format_exc())
            log.update({k: str(getattr(error, k, log.get(k, ""))) for k in ("stdout", "stderr")})
            raise
        finally:
            self.save_log()

    def failure(self, error: Exception) -> str:
        if type(error).__name__.startswith(("Budget", "DryRun")):
            raise error
        self.logs.append({"error": traceback.format_exc()})
        self.save_log()
        return f"{type(error).__name__}: {error}"

    def helper(self, script: str, action: str, args: list[str], mutating: bool = False) -> str:
        paths = {"registry": "scripts/registry.py", "evidence": "scripts/evidence.py"}
        argv = ["uv", "run", "--no-project", "python", "-B", str(resource(paths[script])), action]
        return self.command([*argv, str(self.root), *args], mutating)

    def git(self, *args: str) -> str:
        return self.command(["git", "-C", str(self.repo), *args])

    def pin(self, ref: str) -> str:
        return self.git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()

    def tree(self, sha: str) -> dict[str, str]:
        return dict(
            r.split("\t", 1)[::-1] for r in self.git("ls-tree", "-rz", sha).split("\0") if r
        )

    def boundary(self) -> str:
        parents = self.git("rev-list", "--parents", "-n", "1", self.s1).split()[1:]
        if self.kind != "pr":
            baseline = self.plan.get("baseline")
            need(baseline or (self.kind == "commit" and len(parents) == 1), "Need baseline")
            return self.pin(baseline) if baseline else parents[0]
        if self.pr["lifecycle"] != "merged":
            bases = self.git("merge-base", "--all", self.pin(self.pr["base"]), self.s1).split()
            need(len(bases) == 1, "PR needs a unique merge base or explicit boundary")
            return bases[0]
        if self.pr["strategy"] in ("merge", "squash"):
            merge = self.pr["strategy"] == "merge"
            need(len(parents) == (2 if merge else 1), "Landing ambiguity")
            need(not merge or parents[1] == self.pin(self.pr["head"]), "Head mismatch")
            return parents[0]
        return self.rebased()

    def rebased(self) -> str:
        need(self.pr["strategy"] == "rebase" and self.pr["landed"], "Need rebased series")
        landed = [self.pin(sha) for sha in self.pr["landed"]]
        need(
            landed[-1] == self.s1 and len(landed) == self.pr["collections"]["commits"]["total"],
            "Incomplete rebased series or target mismatch",
        )
        first = self.git("rev-list", "--parents", "-n", "1", landed[0]).split()[1:]
        need(len(first) == 1, "Rebased series needs a parent baseline")
        for before, after in zip([first[0], *landed[:-1]], landed, strict=True):
            parents = self.git("rev-list", "--parents", "-n", "1", after).split()[1:]
            need(parents == [before], "Rebased landing must be contiguous and single-parent")
        original = f"{self.pin(self.pr['original_base'])}..{self.pin(self.pr['head'])}"
        self.obs["range_diff"] = self.git(
            "range-diff", "--no-color", original, f"{first[0]}..{self.s1}"
        )
        return first[0]

    def pr_context(self) -> str:
        need(self.pr["lifecycle"] in ("open", "closed", "merged"), "Missing PR lifecycle")
        pr = self.pr
        need(pr["url"] and all(isinstance(pr[k], str) for k in ("title", "body")), "PR text")
        cutoff = datetime.fromisoformat(self.plan["cutoff"])
        need(cutoff.tzinfo is not None, "Context cutoff needs a timezone")
        need(datetime.fromisoformat(self.pr["as_of"]) <= cutoff, "Later PR metadata")
        for topic in ("discussion", "reviews", "inline", "commits"):
            pages = (c := self.pr["collections"][topic])["pages"]
            items = [item for page in pages for item in page["items"]]
            need(pages and c["complete"] is True, f"Incomplete {topic}")
            need(len(items) == c["total"] == len({x["id"] for x in items}), f"{topic}: IDs")
            need(all(links := [p["url"] for p in pages]), f"Missing {topic} URLs")
            need([p["next"] for p in pages] == [*links[1:], None], f"Pagination: {topic}")
            need(all(datetime.fromisoformat(x["updated_at"]) <= cutoff for x in items), topic)
        self.limits.extend(self.pr["limitations"])
        return self.pr["merge"] if self.pr["lifecycle"] == "merged" else self.pr["head"]

    def resolve(self) -> None:
        need(self.plan_input in self.a["inputs"], "Plan must be an exact assigned input")
        self.plan = json.loads((self.root / self.plan_input).read_text(encoding="utf-8"))
        need(self.plan["input"] == self.original, "Plan differs from frozen original input")
        self.repo = Path(self.plan["repository"]).resolve(strict=True)
        self.repo = Path(self.git("rev-parse", "--show-toplevel").strip()).resolve(strict=True)
        self.excluded = (self.repo,)
        self.kind, self.pr = self.plan["kind"], self.plan.get("pr", {})
        need(self.kind in ("commit", "range", "pr"), "Plan kind must be commit, range or pr")
        self.s1 = self.pin(self.pr_context() if self.kind == "pr" else self.plan.get("target", ""))
        self.trees = {"S1": self.tree(self.s1)}
        guidance = {}
        for filename in ("AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md"):
            header = self.trees["S1"].get(filename, "")
            need(not header or header.startswith(("100644 blob ", "100755 blob ")), filename)
            guidance[filename] = self.git("cat-file", "blob", header.split()[2]) if header else None
            copy = f"guidance/{self.a['change']}/{self.s1}/{filename}"
            if copy in self.a["input_hashes"]:
                need((self.root / copy).read_text(encoding="utf-8") == guidance[filename], copy)
        self.obs["guidance"] = {"revision": self.s1, "files": guidance}
        self.s0 = self.boundary()

    def collect(self) -> None:
        self.trees["S0"], security = self.tree(self.s0), {}
        for state, entries in self.trees.items():
            need(all(v.split()[0] != "120000" for v in entries.values()), "Symlink source: blocked")
            self.files.extend(f"snapshot/{state}/{p}" for p in entries)
            pattern = r"(?i)security|threat|hardening|trust.bound"
            security[state] = [p for p in entries if re.search(pattern, p)]
        self.obs.update(trees=self.trees, security=security)
        ensure_directory(self.own, output_files=tuple(self.files), exclude_roots=self.excluded)
        snapshot = self.own / "snapshot"
        argv = ["uv", "run", "--no-project", "python", "-B", str(resource("scripts/snapshot.py"))]
        self.command([*argv, str(self.repo), self.s0, self.s1, str(snapshot)], True)
        metadata = json.loads((snapshot / "source.json").read_text(encoding="utf-8"))
        expected = {
            k: self.git("rev-parse", f"{s}^{{tree}}").strip()
            for k, s in (("tree0", self.s0), ("tree1", self.s1))
        }
        need(
            metadata == {"repository": str(self.repo), "s0": self.s0, "s1": self.s1, **expected},
            "Snapshot differs from pinned Git objects",
        )
        for filename in ("source.json", "change.patch", "change-message.txt"):
            need((snapshot / filename).is_file() and (snapshot / filename).stat().st_size, filename)
        need(all((snapshot / state).is_dir() for state in self.trees), "Missing source trees")
        self.obs.update(snapshot=metadata, dependency_treatment="Snapshot guards passed; no builds")
        self.source = self.a["directory"] + "/snapshot/source.json"

    def review(self) -> None:
        refs = tuple(
            map(
                resource,
                [
                    "docs/regression-definition.md",
                    "references/evidence.md",
                    "docs/report-definitions.md",
                ],
            )
        )
        prompt = (
            "Read full assigned inputs/references and both trees; apply S1 guidance. "
            "Assess PR boundaries/lifecycle, limits, security contents beyond names. "
            "Search matches are nonexhaustive. Cite evidence IDs/files; analysis only.\n"
        )
        self.notes = agent(
            "worker",
            prompt + json.dumps(self.obs),
            working_directory=self.own,
            readable_paths=(*self.views, *refs, self.own / "snapshot"),
            output=Assessment,
            timeout=3600,
        )
        need(self.notes.boundary.strip() and self.notes.security_review.strip(), "Missing review")
        self.limits.extend(self.notes.limitations)
        need(not self.notes.blocker, self.notes.blocker or "Assessment blocked")

    def seal(self, blocker: str | None) -> StageResult:
        status: Literal["complete", "blocked"] = "blocked" if blocker else "complete"
        result = f"S0={self.s0}; S1={self.s1}; limits={'; '.join(self.limits)}"
        write_json(self.own / "assessment.json", self.notes.model_dump() if self.notes else None)
        write_json(self.own / "observations.json", self.obs)
        record = {k: self.a[k] for k in ("stage", "agent", "change", "candidate", "inputs")}
        record.update(
            attempt=self.attempt,
            status=status,
            source=self.source,
            result=result,
            blocker=blocker,
            limitations=self.limits,
            summary=blocker or (self.notes.boundary if self.notes else "Blocked"),
            security_review=(self.notes and self.notes.security_review) or str(blocker),
        )
        record["artifacts"] = [p.relative_to(self.root).as_posix() for p in self.own.iterdir()]
        write_json(self.own / "prepare.json", record)
        self.helper("evidence", "seal", [self.name], True)
        self.helper("evidence", "verify", [self.name])
        self.helper("registry", "check", [self.attempt, self.name])
        return StageResult(status, str(self.root / self.name), result, blocker)

    def run(self, campaign: str, attempt: str, plan_input: str) -> StageResult:
        try:
            self.root, self.attempt = Path(campaign).resolve(strict=True), attempt
            need(re.fullmatch(r"a[0-9]+", attempt), "Supply exact registered attempt ID")
            argv = ["uv", "run", "--no-project", "python", "-B", "-c", VALIDATE]
            data = json.loads(
                self.command([*argv, str(resource("scripts/registry.py")), str(self.root), attempt])
            )
            self.a, self.original = data["assignment"], data["input"]
            self.views = tuple(self.root / p for p in data["views"])
            self.own = self.root / self.a["directory"]
            self.name = f"{self.a['directory']}/prepare.json"
            if self.own.exists() and any(self.own.iterdir()):
                self.helper("registry", "check", [attempt, self.name])
                old = json.loads((self.root / self.name).read_text(encoding="utf-8"))
                return StageResult(
                    old["status"],
                    str(self.root / self.name),
                    old.get("result", old["summary"]),
                    old.get("blocker"),
                )
            ensure_directory(self.own, output_files=tuple(self.files))
            self.recording, self.plan_input = True, plan_input
            self.save_log()
            blocker = None
            try:
                for phase in (self.resolve, self.collect, self.review):
                    phase()
            except Exception as error:
                blocker = self.failure(error)
            return self.seal(blocker)
        except Exception as error:
            message = self.failure(error)
            return StageResult(
                "blocked",
                None,
                f"S0={self.s0}; S1={self.s1}",
                f"No validated record; coordinator must resolve/reassign: {message}",
            )


@recipe(
    name="prepare-regression",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root=".",
)
def prepare_regression(campaign: str, attempt: str, plan_input: str) -> StageResult:
    work = Preparation()
    result = work.run(campaign, attempt, plan_input)
    emit(work.logs, name="commands")
    return emit(result, name="preparation")


if __name__ == "__main__":
    raise SystemExit(prepare_regression.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("6c595e937d841173a79b618c934cb0f164501565736fe323df89b6fec40368e3"),
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
        "the complete prepare stage, including boundary resolution,"
        " context collection, snapshotting, record construction and"
        " sealing. Input may be a repository plus explicit commit/r"
        "ange or a PR URL with caller-supplied immutable metadata/A"
        "PI access. Native Git/GitHub reads must resolve full S0/S1"
        " SHAs: a single commit uses its parent unless an explicit "
        "root baseline is supplied; unmerged PRs use merge-base to "
        "frozen head; merged PRs distinguish merge first-parent, sq"
        "uash parent and the complete rebased series. Do not silent"
        "ly treat the PR merge SHA as sufficient or pick an arbitra"
        "ry branch. Validate ambiguity/root-baseline failures and f"
        "reeze exact boundary rationale. If resolving S1 changes ta"
        "rget guidance, refresh it before continuing.\n\nFreeze act"
        "ual commit title/messages or PR title/body, discussion, re"
        "views and inline comments, source URLs, pagination, collec"
        "tion timestamp and PR lifecycle/merge strategy. Implement "
        "pagination in host code or accept explicit complete frozen"
        " collection files with validation/recorded collection limi"
        "ts; a one-page response cannot be represented as complete."
        " Security/threat-model documents must be located in BOTH s"
        "tates and their paths/content or exact access/search limit"
        "ations retained. Read project guidance at S1 before target"
        " work.\n\nRun the real snapshot.py REPOSITORY S0_REF S1_RE"
        "F NEW_OUTPUT (mutating=True) into a new snapshot directory"
        " inside this attempt and outside the source checkout. It e"
        "xports S0/S1, binary change.patch, change-message.txt and "
        "source.json with full SHAs/tree IDs. Verify actual output "
        "metadata, files and nonempty change inspection scope rathe"
        "r than trust an agent summary. Keep exports pristine, neve"
        "r build there. The helper deliberately rejects submodules,"
        " Git LFS pointers and export-ignore/export-subst; preserve"
        " these as actionable blockers unless the caller provides i"
        "ndependently verified, pinned special-source materializati"
        "on. Never bypass the guard with ordinary git archive and c"
        "laim complete dependencies.\n\nWrite prepare.json (stage='"
        "prepare', candidate=null) with source pointing to the real"
        " snapshot/source.json or null if blocked. Include pristine"
        " source trees, full diff/context, boundary explanation, gu"
        "idance/security review, dependency/submodule/LFS treatment"
        " and collection limits in sealed artifacts. Native host ex"
        "ecution must perform these mechanics; a model may assess l"
        "ifecycle/boundaries/security intent from enumerated eviden"
        "ce but cannot assert unseen metadata. Return complete/bloc"
        "ked, sealed record, selected S0/S1, limitations and exact "
        "blocker. Existing identical verified preparation may be re"
        "used without overwriting.\n\n\nTargeted repair of the prio"
        "r compiled candidate included as reference: repository Ruf"
        "f C901 rejects prepare_regression complexity28 >8. Preserv"
        "e its actual native workflow and source contracts, but dec"
        "ompose the long body into small truthful helpers/steps, ea"
        "ch complexity<=8, without lint suppression. All local E,F,"
        "I,UP,B,SIM,C4,C90,PLR0913,RUF rules apply. Keep trusted fi"
        "lesystem/command selectors separate from agent-derived ass"
        "essments; do not collect them in a shared dict later mutat"
        "ed with model output. Do not replace native workflow with "
        "an opaque provider.\n\n\nSecond focused repair of the now-"
        "modular candidate, which already passed repository lint: k"
        "eep that modular native implementation. Invoke all pinned "
        "Python helper scripts as uv run --no-project python -B SCR"
        "IPT, including helper() and snapshot.py (the inline valida"
        "tion bridge already uses -B), so imports cannot write __py"
        "cache__ in packaged source directories. Retain raw command"
        "/observation diagnostics durably when later processing fai"
        "ls. AgentError is a public RuntimeError/CalcifierError; Re"
        "cipeError is CalcifierError, so the existing OSError/Value"
        "Error/TypeError/LookupError catches miss real agent/provid"
        "er/context failures. Route those failures to a source-fait"
        "hful blocked record when the assignment is valid, preservi"
        "ng diagnostics and source/attempt evidence; invalid initia"
        "l binding must remain blocked without claiming a sealed st"
        "age record. Shared budget/dry-run failures must stay hones"
        "tly failed/unverified and must not fabricate evidence. Do "
        "not change boundaries, snapshot/guidance checks, independe"
        "nce, readonly workers, immutable input hashes, actual help"
        "er binding/sealing/verification, PR context completeness o"
        "r zero-scope gates. Preserve all workflow behavior apart f"
        "rom these targeted fixes, with module-level complexity<=8 "
        "and no suppressions.\n"
    ),
    "sha256": ("4efd670e9aabaeef2b4ba9177d0aa401bd5dd92eae5907bd967ff152e2dee025"),
}
_CALCIFIER_SUBRECIPES = []
