"""The corpus integrity gate. Nothing runs against a corpus that has not passed it.

Seven checks, every one of which has to inspect something. A gate that inspects
nothing and prints a tick is worse than no gate: this repository has shipped a
validator that matched nothing and reported every plugin valid, and an eval grader
that scored a run which never happened. So each check reports how many items it
looked at, and the gate fails when that number is zero.

| Check | What it establishes |
|---|---|
| `compile` | both variants compile, and the object count equals the source count |
| `behaviour` | benign input still works — a bug that breaks the smoke test is not
  latent, it is a broken corpus |
| `reachability` | every bug has a syntactic call chain from a declared entry point |
| `decoys` | every decoy is a whitelisted no-op kind with a recorded reason, and
  none collides with a bug site |
| `deidentified` | no original identifier or filename survives, and no file is
  byte-identical to its base |
| `ground_truth` | every recorded site exists, names a function present in the file,
  and its own mechanism description matches its own keyword groups |
| `variants` | bench and control differ in exactly the bug files and nowhere else |

The reachability check is syntactic: a call edge exists in the source. It is not a
proof that an attacker can drive the path, and it is not presented as one.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import corpus as corpus_mod
from . import deidentify as deid_mod
from . import grade as grade_mod
from . import inject as inject_mod
from .recipe import DECOY_KINDS, counts


class VerifyError(Exception):
    """The gate could not run at all (missing toolchain, unbuildable recipe)."""


@dataclass
class Check:
    name: str
    ok: bool
    inspected: int
    detail: str = ""
    problems: list[str] = field(default_factory=list)

    @property
    def vacuous(self) -> bool:
        return self.inspected == 0

    def line(self) -> str:
        if self.vacuous:
            state = "VACUOUS"
        elif self.ok:
            state = "pass"
        else:
            state = "FAIL"
        head = f"  [{state:<7}] {self.name:<14} inspected {self.inspected:>4}  {self.detail}"
        return "\n".join([head, *(f"      - {p}" for p in self.problems[:12])])


def _run(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )


def check_compile(tree: Path, manifest: dict[str, Any], timeout: int) -> Check:
    expected = len(manifest["source_files"])
    if shutil.which("cc") is None:
        raise VerifyError("no `cc` on PATH; the compile gate cannot run and must not be skipped")
    build_dir = tree / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    result = _run(["sh", "build.sh"], tree, timeout)
    objects = len(list(build_dir.glob("*.o"))) if build_dir.is_dir() else 0
    problems = []
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip().splitlines()[-8:]
        problems.append(f"build.sh exited {result.returncode}: " + " | ".join(tail))
    if objects != expected:
        problems.append(f"built {objects} object(s) for {expected} source file(s)")
    shutil.rmtree(build_dir, ignore_errors=True)
    return Check(
        name=f"compile[{manifest['variant']}]",
        ok=not problems,
        inspected=expected,
        detail=f"{objects}/{expected} objects",
        problems=problems,
    )


def check_behaviour(tree: Path, recipe: dict[str, Any], variant: str, timeout: int) -> Check:
    if not recipe.get("behaviour_check"):
        reason = str(recipe.get("decoys_unverified_because") or "")
        return Check(
            name=f"behaviour[{variant}]",
            ok=bool(reason),
            inspected=1 if reason else 0,
            detail=(
                f"no behaviour check declared; recipe states: {reason}"
                if reason
                else "no behaviour_check and no decoys_unverified_because"
            ),
            problems=(
                []
                if reason
                else [
                    "declare behaviour_check (a smoke test on benign input) or state "
                    "decoys_unverified_because. Without one of the two, 'the decoys are safe' "
                    "and 'the bugs are latent rather than obvious breakage' are both unevidenced."
                ]
            ),
        )
    result = _run(["sh", "check.sh"], tree, timeout)
    problems = []
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip().splitlines()[-8:]
        problems.append(f"check.sh exited {result.returncode}: " + " | ".join(tail))
    return Check(
        name=f"behaviour[{variant}]",
        ok=not problems,
        inspected=1,
        detail="benign-input smoke test",
        problems=problems,
    )


WARNING_RE = re.compile(r"^([^:]+):\d+:\d+:\s+warning:\s+(.*)$")
WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def warning_set(tree: Path, manifest: dict[str, Any], cflags: list[str], timeout: int) -> set[str]:
    """Every `-Wall -Wextra` warning in one variant, with line numbers dropped.

    Used to compare the two variants, not to judge either one on its own.
    """
    flags = [f for f in cflags if f != "-w"] + ["-Wall", "-Wextra", "-fsyntax-only"]
    found: set[str] = set()
    for source in manifest["source_files"]:
        result = _run(["cc", *flags, source], tree, timeout)
        for line in (result.stderr or "").splitlines():
            match = WARNING_RE.match(line.strip())
            if match:
                found.add(f"{Path(match.group(1)).name}: {match.group(2)}")
    return found


def check_warnings(bench: set[str], control: set[str], inspected: int) -> Check:
    """An injected bug that the compiler points at is not a hidden bug.

    A reviewer who runs `cc -Wall` would be handed the answer, and the arms would be
    measured on whether they thought to compile rather than on whether they can read
    C. So a warning present in the bench tree and absent from the control tree fails
    the gate: change the injection until it is silent.
    """
    new = sorted(bench - control)
    return Check(
        name="warnings",
        ok=not new,
        inspected=inspected,
        detail=f"{len(bench)} warning(s) in bench, {len(control)} in control, {len(new)} new",
        problems=[f"injection announces itself: {w}" for w in new],
    )


def check_reachability(recipe: dict[str, Any], staged: Path) -> Check:
    texts = {
        str(path.relative_to(staged)): path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(staged.rglob("*"))
        if path.is_file()
    }
    entry_points = {e["function"] for e in recipe["entry_points"]}
    problems: list[str] = []
    for bug in recipe["bugs"]:
        found = inject_mod.check_edges(texts, bug["call_path"], entry_points, bug["function"])
        problems += [f"{bug['id']}: {p}" for p in found]
    return Check(
        name="reachability",
        ok=not problems,
        inspected=len(recipe["bugs"]),
        detail=(
            f"{len(recipe['bugs'])} bug(s), syntactic call chains from "
            f"{len(entry_points)} entry point(s)"
        ),
        problems=problems,
    )


ADJACENT_LINES = 3


def check_decoys(manifest: dict[str, Any], recipe: dict[str, Any]) -> Check:
    """A decoy must be distinguishable from every bug, by the grader's own rules.

    The grader keys on the enclosing function first and falls back to a line window
    only when a finding names no function. So the collision rule is: never the same
    function as a bug in the same file, and never within a few lines of one. A pure
    line window would be both too strict (adjacent functions in a small file) and
    beside the point (the function is what actually decides attribution).
    """
    problems: list[str] = []
    bug_sites = [(item["file"], item["line"], item["function"]) for item in manifest["items"]]
    for decoy in manifest["decoys"]:
        if decoy["decoy_kind"] not in DECOY_KINDS:
            problems.append(f"{decoy['id']}: unknown decoy_kind {decoy['decoy_kind']!r}")
        for file, line, function in bug_sites:
            if decoy["file"] != file:
                continue
            if decoy.get("function") == function:
                problems.append(
                    f"{decoy['id']} is in {function}(), which also holds a bug ({file}:{line}). "
                    f"The function is the grader's primary site key, so a finding there cannot "
                    f"be attributed to one rather than the other"
                )
            elif abs(decoy["line"] - line) <= ADJACENT_LINES:
                problems.append(
                    f"{decoy['id']} is {abs(decoy['line'] - line)} line(s) from a bug site "
                    f"({file}:{line}); that is the same statement as far as a reviewer is concerned"
                )
    by_kind = counts(recipe)["by_decoy_kind"]
    return Check(
        name="decoys",
        ok=not problems,
        inspected=len(manifest["decoys"]),
        detail=", ".join(f"{k}={v}" for k, v in by_kind.items()),
        problems=problems,
    )


def check_deidentified(
    tree: Path, manifest: dict[str, Any], recipe: dict[str, Any], private: Path
) -> Check:
    deid = recipe["deidentify"]
    if not deid.get("required"):
        if recipe["base"]["kind"] != "authored":
            return Check(
                name="deidentified",
                ok=False,
                inspected=1,
                detail="fetched base with de-identification switched off",
                problems=[
                    "only an authored corpus may skip de-identification. A fetched tree left "
                    "un-renamed can be diffed against upstream, which is the hole this "
                    "exists to close."
                ],
            )
        return Check(
            name="deidentified",
            ok=True,
            inspected=1,
            detail=f"not required: {deid['not_required_because'][:80]}",
        )

    maps = json.loads((private / "maps.json").read_text(encoding="utf-8"))
    identifier_map = maps["identifier_map"]
    file_map = maps["file_map"]
    if not identifier_map:
        return Check(
            name="deidentified",
            ok=False,
            inspected=0,
            detail="identifier map is empty, so nothing was renamed",
            problems=["de-identification produced an empty mapping"],
        )

    everything = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(tree.rglob("*"))
        if path.is_file()
    )
    base_texts = corpus_mod.fetch_base(recipe, allow_network=False)

    problems: list[str] = []
    # Two different questions, deliberately checked two different ways.
    #
    # 1. Could someone match this file to an upstream one? That is about *identifiers in
    #    code*, so only code regions of the corpus sources are tokenised — not comments,
    #    not string literals, and not the build scripts this harness generates. Scanning
    #    everything flagged `check` and `done` from the prose in check.sh, and `header`
    #    from an English sentence inside a message string: three false alarms that would
    #    have taught the next author to distrust the gate.
    # 2. Is a known identity tell present anywhere at all? That is `forbidden_strings`,
    #    checked over the whole tree below, strings and scripts included, because a
    #    project name in an error message gives the game away as loudly as a symbol.
    code_only: list[str] = []
    for relative in manifest["files"]:
        source = tree / relative
        if not source.is_file():
            continue
        in_block = in_string = False
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            runs, in_block, in_string = deid_mod._regions(line, in_block, in_string)
            code_only += [run for kind, run in runs if kind == "code"]
    # Tokenise once and intersect, rather than one regex per identifier over the whole
    # tree: that form was O(identifiers x bytes) and took minutes on a 9.5 KLOC corpus.
    words = set(WORD_RE.findall("\n".join(code_only)))
    survivors = [name for name in identifier_map if len(name) >= 4 and name in words]
    if survivors:
        problems.append(
            f"{len(survivors)} original identifier(s) survive, e.g. "
            f"{', '.join(sorted(survivors)[:6])}"
        )
    stems = [
        Path(original).stem
        for original in file_map
        if len(Path(original).stem) >= 4 and Path(original).stem in words
    ]
    if stems:
        problems.append(f"original filename stem(s) survive: {', '.join(sorted(set(stems))[:6])}")
    for word in deid.get("forbidden_strings") or ():
        if word.lower() in everything.lower():
            problems.append(f"forbidden string {word!r} is still present")
    identical = [
        original
        for original, renamed in file_map.items()
        if (tree / renamed).is_file()
        and (tree / renamed).read_text(encoding="utf-8", errors="replace")
        == base_texts.get(original)
    ]
    if identical:
        problems.append(f"byte-identical to the base: {', '.join(identical[:6])}")

    return Check(
        name="deidentified",
        ok=not problems,
        inspected=len(identifier_map),
        detail=(
            f"{len(identifier_map)} identifiers renamed across {len(file_map)} file(s), "
            f"{manifest['lines_of_code']} lines emitted"
        ),
        problems=problems,
    )


def _mechanism_self_match(item: dict[str, Any]) -> list[str]:
    """Does the item's own description satisfy its own keyword groups?

    This is the positive control for the grader's mechanism matcher. If a keyword
    group cannot match a correct description of the bug it exists to describe, it
    will not match a reviewer's correct description either, and recall drops for a
    reason that has nothing to do with the reviewer.
    """
    text = _mechanism_text(item)
    return [
        "/".join(group[:3])
        for group in item["mechanism_all_of"]
        if not any(term.lower() in text for term in group)
    ]


def _mechanism_text(item: dict[str, Any]) -> str:
    return " ".join(
        str(item.get(field, "")) for field in ("mechanism", "bug_class", "attacker_control")
    ).lower()


def _satisfies(text: str, groups: list[list[str]]) -> bool:
    return all(any(term.lower() in text for term in group) for group in groups)


def check_mechanism_discrimination(manifest: dict[str, Any], window: int) -> Check:
    """Can the keyword groups tell two bugs at the same grading site apart?

    `check_ground_truth` is the grader's *positive* control: each bug's own description
    must satisfy its own keyword groups, or a correct finding scores NEAR_MISS. This is the
    negative control, and it was missing.

    The grader keys on the enclosing function, falling back to a line window, so two bugs
    in one function are graded against the same set of findings. If bug X's keyword groups
    are loose enough to be satisfied by a description of bug Y, then one finding about Y is
    scored as having found both — recall goes up by one for a bug nothing in the run
    describes. That is not hypothetical: on the shipped `sigil` corpus, deleting the only
    finding that described the state-machine bypass left it scored as a HIT on a finding
    about a different bug eleven lines away in the same function.

    The probe is each bug's own `mechanism` sentence, because that is the only text this
    harness owns that is known to be a correct description of one bug and not of another.
    It is a weaker probe than a reviewer's prose — the terse sentence has less surface for
    an accidental match than twelve concatenated finding fields — so passing this is a
    floor, not a guarantee. `grade._resolve_ambiguity` is the backstop for what gets
    through.
    """
    items = manifest["items"]
    pairs = 0
    problems: list[str] = []
    for x in items:
        for y in items:
            if x["id"] == y["id"] or x["file"] != y["file"]:
                continue
            colocated = x["function"] == y["function"] or abs(x["line"] - y["line"]) <= window
            if not colocated:
                continue
            pairs += 1
            if _satisfies(_mechanism_text(x), y["mechanism_all_of"]):
                where = (
                    f"the same function {x['function']}()"
                    if x["function"] == y["function"]
                    else (
                        f"{abs(x['line'] - y['line'])} line(s) apart, inside the "
                        f"{window}-line window"
                    )
                )
                problems.append(
                    f"{y['id']}'s keyword groups are satisfied by {x['id']}'s own mechanism text, "
                    f"and the two are at {where}. One finding about {x['id']} would be scored as "
                    f"having found {y['id']} too. Make {y['id']}'s groups name something only "
                    f"{y['id']} has."
                )
    return Check(
        name="mechanism_discrim",
        ok=not problems,
        # The unit of inspection is the item, not the pair: a corpus whose bugs are all in
        # different functions has zero co-located pairs, and that is a good property rather
        # than a check that ran on nothing. Zero *items* is what would be vacuous, and the
        # recipe validator has already refused that.
        inspected=len(items),
        detail=(
            f"{len(items)} bug(s), {pairs} co-located ordered pair(s); each pair's keyword "
            f"groups must reject the other's mechanism"
        ),
        problems=problems,
    )


def check_ground_truth(tree: Path, manifest: dict[str, Any]) -> Check:
    problems: list[str] = []
    for item in manifest["items"]:
        path = tree / item["file"]
        if not path.is_file():
            problems.append(f"{item['id']}: {item['file']} is not in the emitted tree")
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not 1 <= item["line"] <= len(lines):
            problems.append(
                f"{item['id']}: line {item['line']} is outside {item['file']} ({len(lines)} lines)"
            )
            continue
        if not lines[item["line"] - 1].strip():
            problems.append(f"{item['id']}: line {item['line']} is blank")
        if item["function"] != "(file-level)" and not inject_mod.mentions(
            "\n".join(lines), item["function"]
        ):
            problems.append(
                f"{item['id']}: function {item['function']!r} does not appear in {item['file']}"
            )
        missing = _mechanism_self_match(item)
        if missing:
            problems.append(
                f"{item['id']}: its own mechanism text does not match keyword group(s) {missing} — "
                f"the grader would score a correct finding as NEAR_MISS"
            )
    ids = [item["id"] for item in manifest["items"]]
    if len(set(ids)) != len(ids):
        problems.append("duplicate ground-truth ids")
    return Check(
        name="ground_truth",
        ok=not problems,
        inspected=len(manifest["items"]),
        detail=f"{len(ids)} item(s) located, functions present, keyword groups self-matching",
        problems=problems,
    )


def check_variants(bench: dict[str, Any], control: dict[str, Any]) -> Check:
    bug_files_final = {item["file"] for item in bench["items"]}
    problems: list[str] = []
    shared = set(bench["file_sha256"]) & set(control["file_sha256"])
    if not shared:
        problems.append("the two variants share no files, so they are not variants of one corpus")
    for rel in sorted(shared):
        same = bench["file_sha256"][rel] == control["file_sha256"][rel]
        if rel in bug_files_final and same:
            problems.append(f"{rel} holds a bug but is identical in the control tree")
        if rel not in bug_files_final and not same:
            problems.append(
                f"{rel} differs between bench and control but holds no bug — the decoys are not "
                f"being applied identically to both"
            )
    missing = set(bench["file_sha256"]) ^ set(control["file_sha256"])
    if missing:
        problems.append(f"file sets differ: {', '.join(sorted(missing)[:6])}")
    return Check(
        name="variants",
        ok=not problems,
        inspected=len(shared),
        detail=(
            f"{len(bug_files_final)} file(s) carry bugs, "
            f"{len(shared) - len(bug_files_final)} identical"
        ),
        problems=problems,
    )


def verdict(checks: list[Check]) -> bool:
    """The corpus passes only if every check passed *and* inspected something.

    Separated out and tested directly, because this one boolean is the whole gate.
    A check that inspected zero items is a failure here, not a pass with an empty
    result: "0 of 0 hunter groups flagged" was printed by a previous version of this
    repository's contamination check while a reviewer was openly declaring that it
    had fetched upstream.
    """
    if not checks:
        raise VerifyError(
            "the gate ran zero checks, so it established nothing. Refusing to report a corpus "
            "as verified."
        )
    return all(check.ok and not check.vacuous for check in checks)


def gate(
    recipe: dict[str, Any],
    workdir: Path,
    allow_network: bool = True,
    build_timeout: int = 900,
) -> dict[str, Any]:
    """Build both variants and run every check. Returns the stamp document."""
    workdir = Path(workdir).resolve()
    trees = {}
    manifests = {}
    for variant in (corpus_mod.BENCH, corpus_mod.CONTROL):
        tree = workdir / variant
        private = workdir / f"{variant}-private"
        manifests[variant] = corpus_mod.build(
            recipe, variant, tree, private, allow_network=allow_network
        )
        trees[variant] = (tree, private)

    checks: list[Check] = []
    warnings: dict[str, set[str]] = {}
    for variant, (tree, _private) in trees.items():
        checks.append(check_compile(tree, manifests[variant], build_timeout))
        checks.append(check_behaviour(tree, recipe, variant, build_timeout))
        warnings[variant] = warning_set(
            tree, manifests[variant], recipe["build"]["cflags"], build_timeout
        )
    checks.append(
        check_warnings(
            warnings[corpus_mod.BENCH],
            warnings[corpus_mod.CONTROL],
            len(manifests[corpus_mod.BENCH]["source_files"]),
        )
    )
    bench_tree, bench_private = trees[corpus_mod.BENCH]
    checks.append(check_reachability(recipe, bench_private / "staged"))
    checks.append(check_decoys(manifests[corpus_mod.BENCH], recipe))
    checks.append(
        check_deidentified(bench_tree, manifests[corpus_mod.BENCH], recipe, bench_private)
    )
    checks.append(check_ground_truth(bench_tree, manifests[corpus_mod.BENCH]))
    checks.append(
        check_mechanism_discrimination(manifests[corpus_mod.BENCH], grade_mod.DEFAULT_WINDOW)
    )
    checks.append(check_variants(manifests[corpus_mod.BENCH], manifests[corpus_mod.CONTROL]))

    passed = verdict(checks)
    stamp = {
        "corpus": recipe["id"],
        "tier": recipe["tier"],
        "verified": passed,
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "counts": counts(recipe),
        "lines_of_code": manifests[corpus_mod.BENCH]["lines_of_code"],
        "tree_sha256": manifests[corpus_mod.BENCH]["file_sha256"],
        "workdir": str(workdir),
        "checks": [
            {
                "name": c.name,
                "ok": c.ok,
                "inspected": c.inspected,
                "detail": c.detail,
                "problems": c.problems,
            }
            for c in checks
        ],
    }
    (workdir / "verified.json").write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    stamp["_checks"] = checks
    return stamp
