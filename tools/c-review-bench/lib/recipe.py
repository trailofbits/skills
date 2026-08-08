"""Load and validate a corpus recipe.

A recipe is the whole answer key for one corpus: where the base code comes from,
how it is de-identified, which bugs are injected where, which decoys are injected
to make a successful upstream diff useless, and how each bug is claimed to be
reachable. Nothing about a corpus is implicit — if it is not in the recipe it does
not happen, and if the recipe is malformed the build fails before any agent runs.

The validator is deliberately unforgiving about counts. A recipe with zero bugs,
zero decoys or zero entry points would build a corpus that grades every arm at 0/0
and reports it as a clean measurement, which is the single most expensive class of
bug this repository has shipped.

`bug_class` is drawn from a fixed catalogue rather than free text, because the whole
point of the per-class breakdown is comparing the same class across corpora and
across runs. A typo that invents a new class silently splits a row.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TIERS = ("small", "medium", "large")
DIFFICULTIES = ("EASY", "MEDIUM", "HARD")

# The catalogue. Every entry is a bug *shape* seen in real C, and each corpus draws
# from it; no entry names a real bug's location.
BUG_CLASSES = (
    "buffer-overflow",
    "oob-read",
    "oob-write",
    "use-after-free",
    "double-free",
    "uninitialised-use",
    "signed-integer-overflow",
    "unsigned-integer-overflow",
    "width-truncation",
    "off-by-one",
    "missing-nul-termination",
    "unbounded-copy",
    "unchecked-return-value",
    "resource-leak",
    "unbounded-recursion",
    "toctou-race",
    "delimiter-injection",
    "state-machine-bypass",
    "validate-one-copy-use-another",
    "encoding-invariant-violation",
    "nonce-iv-reuse",
    "non-constant-time-compare",
)

# A decoy must be a mutation that provably cannot change behaviour on any input.
# Restricting the kinds is what makes "the decoy is safe" reviewable: the reason is
# recorded per decoy, and the kind says which argument the reason has to make.
DECOY_KINDS = {
    "renamed-local": "renames a local variable; no other declaration is in scope",
    "extra-init": "initialises a variable that every path already assigned before use",
    "redundant-check": "adds a condition already implied by a dominating check",
    "strengthened-bound": "tightens a bound that the reachable inputs never approach",
    "equivalent-expression": "rewrites an expression into an algebraically identical one",
    "reordered-independent": "reorders two statements with no data or control dependence",
    "dead-branch": "adds a branch whose guard is unsatisfiable at that point",
    "hoisted-invariant": "moves a loop-invariant computation out of the loop",
    "extra-assert": "adds an assertion that holds on every reachable path",
    "widened-type": "widens a local to a type that cannot narrow any value it holds",
    # The mirror of `widened-type`, and the strongest bait shape this corpus has: a
    # narrowing conversion is what a reviewer flags on sight, and `safe_because` has to
    # name the guard that bounds the value below the narrow type's maximum. It is a
    # separate kind rather than an `equivalent-expression` because the argument it owes
    # is a *range* argument, not an algebraic one.
    "value-preserving-cast": "casts a value to a narrower type that provably holds it",
}

# Words that indicate a finding is about the *mutation* rather than about something else
# that happens to live in the same function. Without this, a real finding at a decoy's
# site is charged as a false positive: the first real arm run reported a genuine key
# disclosure in the function holding a `widened-type` decoy, and was billed for falling
# for the decoy it never mentioned.
DECOY_CLAIM_TERMS = {
    "renamed-local": ["rename", "naming", "shadow", "variable name"],
    "extra-init": ["initialis", "initializ", "redundant assignment", "dead store", "unused value"],
    "redundant-check": [
        "redundant",
        "duplicate check",
        "already checked",
        "dead condition",
        "tautolog",
    ],
    "strengthened-bound": ["bound", "limit", "threshold", "too strict", "off-by"],
    "equivalent-expression": ["expression", "arithmetic", "operator", "precedence", "rewrit"],
    # Tightened after the first real run: the original list ("order", "reorder",
    # "sequence", "before", "after") is ordinary English that appears in almost any
    # use-after-free or ordering description. Combined with the grader's site window
    # reaching into a neighbouring function, ~5 of 11 decoy charges on `sigil` were a
    # correct finding that merely used a word like "after" and had nothing to do with
    # this decoy. The replacement requires the finding to assert the mutation itself --
    # that two statements were reordered or swapped -- not merely to use a temporal word.
    "reordered-independent": [
        "reorder",
        "reordered",
        "reordering",
        "swapped order",
        "swapped the order",
        "wrong order",
        "out of order",
    ],
    "dead-branch": ["dead", "unreachable", "never taken", "cannot happen"],
    "hoisted-invariant": ["hoist", "invariant", "loop", "cached value", "stale"],
    "extra-assert": ["assert", "assertion"],
    # Deliberately narrow: "type", "long" and "truncat" appear in half of all integer
    # findings, so they would charge an arm for a real bug that merely shares a function
    # with this decoy — which is exactly what happened on the first real run.
    "widened-type": ["widen", "narrow", "type mismatch", "inconsistent type", "declared type"],
    # A reviewer who falls for a narrowing cast writes "truncated" or "narrowed", not
    # "the cast is value-preserving". The terms are the vocabulary of the *report*, so
    # they have to be the words a wrong finding would use — a term list phrased in
    # refactoring language never fires and the decoy silently costs nothing.
    "value-preserving-cast": ["truncat", "narrow", "downcast", "8-bit", "16-bit", "wrap"],
}


class RecipeError(Exception):
    """A recipe that cannot be trusted. Callers exit non-zero."""


def _need(obj: dict[str, Any], key: str, where: str) -> Any:
    if key not in obj or obj[key] in (None, "", [], {}):
        raise RecipeError(f"{where}: missing or empty {key!r}")
    return obj[key]


def _as_text(value: Any) -> Any:
    """Allow a patch body to be written as a list of lines.

    JSON with `\\n` escapes is unreviewable, and an unreviewable answer key is one
    nobody checks. A list of lines diffs like source, so that is the authoring form
    and this joins it before anything else looks at it.
    """
    if isinstance(value, list):
        return "\n".join(str(line) for line in value)
    return value


def _normalise_patch(patch: dict[str, Any]) -> None:
    for key in ("anchor", "replacement", "site_marker"):
        if key in patch:
            patch[key] = _as_text(patch[key])


def _check_patch(patch: dict[str, Any], where: str) -> None:
    _normalise_patch(patch)
    for key in ("id", "file", "anchor", "replacement"):
        _need(patch, key, where)
    if patch.get("site_marker") and patch["site_marker"] not in patch["replacement"]:
        raise RecipeError(f"{where}: site_marker is not a substring of replacement")
    if patch["anchor"] == patch["replacement"]:
        raise RecipeError(f"{where}: anchor and replacement are identical, so it patches nothing")


def _check_bug(bug: dict[str, Any], where: str, entry_points: set[str]) -> None:
    _check_patch(bug, where)
    for key in ("bug_class", "difficulty", "function", "mechanism", "attacker_control"):
        _need(bug, key, where)
    if bug["bug_class"] not in BUG_CLASSES:
        raise RecipeError(
            f"{where}: bug_class {bug['bug_class']!r} is not in the catalogue. "
            f"Add it to BUG_CLASSES deliberately or fix the typo."
        )
    if bug["difficulty"] not in DIFFICULTIES:
        raise RecipeError(f"{where}: difficulty must be one of {DIFFICULTIES}")
    groups = bug.get("mechanism_all_of")
    if not isinstance(groups, list) or not groups:
        raise RecipeError(f"{where}: mechanism_all_of must be a non-empty list of term groups")
    for group in groups:
        if (
            not isinstance(group, list)
            or not group
            or not all(isinstance(t, str) and t for t in group)
        ):
            raise RecipeError(
                f"{where}: every mechanism_all_of group must be a non-empty list of terms"
            )
    path = bug.get("call_path")
    if not isinstance(path, list) or not path:
        raise RecipeError(
            f"{where}: call_path must be a non-empty list of edges. A bug with no path from an "
            f"entry point is not known to be reachable, and an unreachable bug in a ground "
            f"truth deflates every arm's recall equally and invisibly."
        )
    for edge in path:
        for key in ("from", "to"):
            _need(edge, key, f"{where} call_path edge")
        if edge.get("kind", "direct") not in ("direct", "indirect"):
            raise RecipeError(f"{where}: call_path edge kind must be 'direct' or 'indirect'")
    if path[0]["from"] not in entry_points:
        raise RecipeError(
            f"{where}: call_path starts at {path[0]['from']!r}, which is not a declared entry point"
        )


def _check_decoy(decoy: dict[str, Any], where: str) -> None:
    _check_patch(decoy, where)
    # The enclosing function is required because that is the grader's primary site
    # key: a decoy sharing a function with a bug cannot be told apart from it.
    _need(decoy, "function", where)
    kind = _need(decoy, "decoy_kind", where)
    if kind not in DECOY_KINDS:
        raise RecipeError(
            f"{where}: decoy_kind {kind!r} is not one of {sorted(DECOY_KINDS)}. The kinds are "
            f"restricted so that 'this decoy is safe' is an argument someone can check."
        )
    reason = str(_need(decoy, "safe_because", where))
    if len(reason) < 25:
        raise RecipeError(
            f"{where}: safe_because is {len(reason)} characters. Say why behaviour cannot change, "
            f"naming the dominating check or the dependence that is absent."
        )


def validate(recipe: dict[str, Any], origin: str = "<recipe>") -> dict[str, Any]:
    """Raise RecipeError on anything that would make a run unscoreable."""
    # The count guards come first and by name, because "missing or empty 'bugs'" is a
    # true but uninformative way to say that this corpus would grade every arm 0/0.
    if not recipe.get("bugs"):
        raise RecipeError(
            f"{origin}: zero injected bugs. A corpus with no ground truth grades every arm 0/0 "
            f"and reports it as a measurement."
        )
    if not recipe.get("decoys"):
        raise RecipeError(
            f"{origin}: zero decoys. Decoys are what makes a successful upstream diff useless "
            f"rather than a list of our injections; a corpus without them is not defended."
        )
    if not recipe.get("entry_points"):
        raise RecipeError(f"{origin}: entry_points is empty, so no bug can be shown reachable")
    for key in ("id", "tier", "base", "deidentify", "build", "entry_points", "bugs", "decoys"):
        _need(recipe, key, origin)
    if recipe["tier"] not in TIERS:
        raise RecipeError(f"{origin}: tier must be one of {TIERS}")

    base = recipe["base"]
    kind = _need(base, "kind", f"{origin}.base")
    if kind == "authored":
        _need(base, "source_dir", f"{origin}.base")
    elif kind == "tarball":
        for key in ("url", "sha256", "files"):
            _need(base, key, f"{origin}.base")
        if len(str(base["sha256"])) != 64:
            raise RecipeError(f"{origin}.base.sha256 must be a full 64-hex-character digest")
    else:
        raise RecipeError(f"{origin}.base.kind must be 'authored' or 'tarball'")

    deid = recipe["deidentify"]
    if deid.get("required") is True:
        _need(deid, "seed", f"{origin}.deidentify")
    elif deid.get("required") is False:
        reason = str(_need(deid, "not_required_because", f"{origin}.deidentify"))
        if len(reason) < 25:
            raise RecipeError(
                f"{origin}.deidentify.not_required_because must explain why the corpus carries no "
                f"upstream identity — the only honest reason is that it was written "
                f"for this harness"
            )
    else:
        raise RecipeError(f"{origin}.deidentify.required must be true or false, explicitly")

    entries = recipe["entry_points"]
    if not isinstance(entries, list) or not entries:
        raise RecipeError(f"{origin}: entry_points is empty, so no bug can be shown reachable")
    for entry in entries:
        for key in ("function", "file", "why"):
            _need(entry, key, f"{origin}.entry_points")
    entry_names = {e["function"] for e in entries}

    bugs, decoys = recipe["bugs"], recipe["decoys"]
    if not isinstance(bugs, list) or not bugs:
        raise RecipeError(
            f"{origin}: zero injected bugs. A corpus with no ground truth grades every arm 0/0 "
            f"and reports it as a measurement."
        )
    if not isinstance(decoys, list) or not decoys:
        raise RecipeError(
            f"{origin}: zero decoys. Decoys are what makes a successful upstream diff useless "
            f"rather than a list of our injections; a corpus without them is not defended."
        )
    for bug in bugs:
        _check_bug(bug, f"{origin}.bugs[{bug.get('id', '?')}]", entry_names)
    for decoy in decoys:
        _check_decoy(decoy, f"{origin}.decoys[{decoy.get('id', '?')}]")

    ids = [item["id"] for item in bugs + decoys]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise RecipeError(f"{origin}: duplicate patch id(s): {', '.join(duplicates)}")

    for extra in recipe.get("known_extra_findings") or ():
        for key in ("file", "function", "note"):
            _need(extra, key, f"{origin}.known_extra_findings")
        if len(str(extra["note"])) < 25:
            raise RecipeError(
                f"{origin}.known_extra_findings: note must say what the weakness is and why it "
                f"is not injected ground truth"
            )

    build = recipe["build"]
    _need(build, "sources", f"{origin}.build")
    if not build.get("cflags"):
        raise RecipeError(f"{origin}.build.cflags is empty; the gate needs the real compile flags")
    flags = " ".join(build["cflags"])
    if "-Werror=implicit-function-declaration" not in flags:
        raise RecipeError(
            f"{origin}.build.cflags must include -Werror=implicit-function-declaration. Without it "
            f"a renamed libc call compiles with a warning and the de-identifier can break the "
            f"corpus silently."
        )
    return recipe


def load(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise RecipeError(f"recipe not found: {path}")
    try:
        recipe = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RecipeError(f"{path} is not valid JSON: {exc}") from exc
    recipe.setdefault("_dir", str(path.parent))
    return validate(recipe, origin=str(path))


def load_public(path: str | Path) -> dict[str, Any]:
    """Load a *sealed* recipe — every field except the answers.

    `seal` deletes `recipe.json` and writes `recipe.public.json` beside it, holding
    everything but `bugs` and `decoys`. Nothing read that file, so after a seal
    `bench.py plan` died with "no corpora found" and the mandated verify -> seal -> plan
    order could not be run at all: the only way to get packets was to plan before
    sealing, which is the one ordering the harness exists to prevent.

    Deliberately NOT a fallback inside `load`. Building, verifying or grading a corpus
    must still refuse a recipe with no ground truth — `plan` is the only step that needs
    the tier, the scope and the threat model and never needs a bug list. The zero-item
    guard is kept in the form that is still checkable here: a sealed recipe claiming zero
    bugs or zero decoys is refused, because planning a run against an empty corpus would
    grade every arm 0/0 and print it as a measurement.
    """
    path = Path(path)
    if not path.is_file():
        raise RecipeError(f"sealed recipe not found: {path}")
    try:
        recipe = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RecipeError(f"{path} is not valid JSON: {exc}") from exc
    if not recipe.get("_sealed"):
        raise RecipeError(
            f"{path}: not marked _sealed. This loader skips every check that needs the bug "
            f"list, so it must only ever be handed a file `seal` wrote."
        )
    if recipe.get("bugs") or recipe.get("decoys"):
        raise RecipeError(
            f"{path}: carries a 'bugs' or 'decoys' key. A sealed recipe holding the answers "
            f"is not sealed; load it with `load` so it is fully validated."
        )
    for key in ("id", "tier", "base", "deidentify", "entry_points", "build"):
        _need(recipe, key, str(path))
    if recipe["tier"] not in TIERS:
        raise RecipeError(f"{path}: tier must be one of {TIERS}")
    for key in ("bug_count", "decoy_count"):
        value = _need(recipe, key, str(path))
        if not isinstance(value, int) or value < 1:
            raise RecipeError(
                f"{path}: {key} is {value!r}. A corpus with no ground truth and no decoys "
                f"grades every arm 0/0 and reports it as a measurement."
            )
    recipe.setdefault("_dir", str(path.parent))
    return recipe


def counts(recipe: dict[str, Any]) -> dict[str, Any]:
    """Class and difficulty tallies, for the plan header and the report."""
    by_class: dict[str, int] = {}
    by_difficulty: dict[str, int] = {}
    for bug in recipe["bugs"]:
        by_class[bug["bug_class"]] = by_class.get(bug["bug_class"], 0) + 1
        by_difficulty[bug["difficulty"]] = by_difficulty.get(bug["difficulty"], 0) + 1
    by_decoy: dict[str, int] = {}
    for decoy in recipe["decoys"]:
        by_decoy[decoy["decoy_kind"]] = by_decoy.get(decoy["decoy_kind"], 0) + 1
    return {
        "bugs": len(recipe["bugs"]),
        "decoys": len(recipe["decoys"]),
        "by_class": dict(sorted(by_class.items())),
        "by_difficulty": {d: by_difficulty.get(d, 0) for d in DIFFICULTIES},
        "by_decoy_kind": dict(sorted(by_decoy.items())),
    }
