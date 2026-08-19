"""Tri-state signal model and the checks that keep a report honest.

Unavailable data is never evidence of risk, and an absent measurement is never a clean
verdict. Both directions matter: an early version of this collector held three 404s
proving a package was unpublished and still reported "no advisories recorded" as a clean
result, because an empty answer from a vulnerability database was mistaken for evidence.

So `Signal.clean` demands a datum, exactly as `Signal.flagged` and `Signal.unassessable`
demand a reason. A clean state with nothing behind it is the shape of that bug.

`validate_artifact` is the guard that can actually fail. An earlier `coverage()` compared
per-state counts against a total that was computed from the same loop, so it was true by
construction and could never fire.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class State(str, Enum):
    """What we learned about one criterion for one dependency."""

    CLEAN = "assessed_clean"
    FLAGGED = "assessed_flagged"
    UNASSESSABLE = "unassessable"


@dataclass
class Signal:
    """One criterion's verdict for one dependency, with the datum behind it."""

    state: State
    detail: str
    value: object = None

    @classmethod
    def clean(cls, detail: str, value: object) -> Signal:
        """A negative finding, which is still a claim and still needs evidence.

        Raises:
            ValueError: If no detail is given, or `value` is None. A clean verdict with
                no supporting datum cannot be distinguished from an unasked question.
        """
        if not detail:
            raise ValueError("a clean signal must say what was measured")
        if value is None:
            raise ValueError(
                f"a clean signal needs the datum behind it ({detail!r} carries none); "
                f"use Signal.unassessable when nothing was measured"
            )
        return cls(State.CLEAN, detail, value)

    @classmethod
    def flagged(cls, detail: str, value: object) -> Signal:
        """A positive finding.

        Raises:
            ValueError: If no detail is given.
        """
        if not detail:
            raise ValueError("a flagged signal must say what was flagged")
        return cls(State.FLAGGED, detail, value)

    @classmethod
    def unassessable(cls, reason: str, value: object = None) -> Signal:
        """Nothing was measured, and this is not a finding.

        Raises:
            ValueError: If no reason is given.
        """
        if not reason:
            raise ValueError("an unassessable signal must say why it could not be assessed")
        return cls(State.UNASSESSABLE, reason, value)


# Comparable across every ecosystem, so only Tier A reaches the headline verdict.
TIER_A = ("advisories", "deprecated", "archived", "staleness")

# Registry-dependent: npm publishes these, PyPI publishes none of them, Go has no
# registry at all.
TIER_B = ("publisher_concentration", "install_script")

# From OpenSSF Scorecard's individual checks. Never its aggregate score, which measures
# adherence to OSS security hygiene and correlates with project size rather than with
# takeover risk: p-limit scores 3.8 and chalk 4.6 against lodash's 7.2, while lodash is
# the one with a single publisher and 165M weekly downloads.
TIER_SCORECARD = ("dangerous_workflow", "token_permissions", "binary_artifacts", "code_review")

# Measured and counted, never flagged.
#
# `provenance` and `security_policy` describe hygiene rather than likelihood of compromise,
# and are absent for most packages — flagging them put 5 of 8 dependencies in the findings
# table on a trial run and buried the real findings.
#
# `downloads` earned its place here by measurement: a floor of 1,000/week flagged 0 of 141
# dependencies across three real projects, so it detected nothing. It is retained because
# it is the number that distinguishes a single-publisher package at 450M downloads/week
# from one at 126K, which is prioritisation context rather than a finding.
TIER_INFO = ("provenance", "security_policy", "downloads")

CRITERIA = TIER_A + TIER_B + TIER_SCORECARD + TIER_INFO

# OpenSSF Scorecard check -> (criterion, flag threshold). The single source of truth for
# which Scorecard criteria can flag: the collector scores against the thresholds and the
# renderer derives its never-flags set from `threshold is None`. Keeping this knowledge
# in one place is what stops the renderer's prose from drifting against the collector's
# behaviour — an earlier draft maintained the demoted set by hand in the renderer and
# described the two checks that DO flag as "not flagged — poor precision".
#
# Only the two that name a concrete mechanism flag. Measured against axios's 43
# dependencies, `Token-Permissions` below 6 flagged 23 of 35 and `Code-Review` below 4
# flagged 15 of 39 — two thirds and a third of the tree. Both describe CI configuration
# maturity, which tracks project size rather than the likelihood of someone shipping
# malicious code, and `Code-Review` largely restates publisher concentration.
SCORECARD_CHECKS = {
    # Scorecard found an actual script-injection or untrusted-checkout pattern.
    "Dangerous-Workflow": ("dangerous_workflow", 10),
    # Binaries committed to the repository, which nobody can review.
    "Binary-Artifacts": ("binary_artifacts", 10),
    "Token-Permissions": ("token_permissions", None),
    "Code-Review": ("code_review", None),
}


@dataclass
class Dependency:
    """A direct dependency of the target project."""

    ecosystem: str
    name: str
    version: str | None = None
    # How the version was established, which decides how strong any advisory claim is:
    #   lockfile        exactly what the project installs
    #   manifest-pin    an exact pin in the manifest
    #   go-mod-minimum  go.mod's minimum; module-version selection may pick higher
    #   latest-release  the registry's current release, not the project's choice
    #   unresolved      nothing; advisory results are historical for the package
    version_source: str = "unresolved"
    # True = build-time only, False = ships in the artifact, None = the manifest declares
    # no distinction. Go is the None case: go.mod has no dev section, so claiming a module
    # ships to production would assert something the ecosystem never states.
    dev: bool | None = None
    repo: str | None = None
    # True when the package is known to exist in its registry. An empty answer from a
    # vulnerability database only means "no advisories" if the package is real.
    exists: bool | None = None
    # Set when the dependency resolves from somewhere other than its public registry
    # (file:, workspace:, git, a vendored directory). Registry-keyed data must never be
    # queried for such a dependency: a same-named public package's advisories,
    # publishers, and deprecation would be attributed to code the project never
    # installs. Every criterion becomes unassessable with this reason.
    non_registry_reason: str | None = None
    signals: dict[str, Signal] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}"

    def flagged(self) -> list[str]:
        return [c for c, s in self.signals.items() if s.state is State.FLAGGED]


class ReconciliationError(RuntimeError):
    """The artifact does not account for every dependency and criterion."""


def coverage(deps: list[Dependency], criteria: tuple[str, ...] = CRITERIA) -> dict:
    """Count each criterion's states, refusing anything that hides a dependency.

    Args:
        deps: The dependencies that were collected.
        criteria: Criterion names every dependency must carry.

    Returns:
        A mapping of criterion -> per-state counts, plus the dependency total.

    Raises:
        ReconciliationError: If two dependencies share a key, or any dependency's signal
            keys are not exactly `criteria`. Both are ways a dependency disappears from
            the report while the totals still look plausible.
    """
    keys = [dep.key for dep in deps]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        raise ReconciliationError(
            f"duplicate dependencies would be counted twice: {', '.join(duplicates)}"
        )

    expected = set(criteria)
    for dep in deps:
        present = set(dep.signals)
        if present != expected:
            missing = sorted(expected - present)
            extra = sorted(present - expected)
            raise ReconciliationError(
                f"{dep.key} carries the wrong criteria — missing {missing}, unexpected "
                f"{extra}. A missing criterion reads as a clean one; an unexpected one is "
                f"counted nowhere and rendered nowhere."
            )

    out = {}
    for criterion in criteria:
        counts = {state.value: 0 for state in State}
        for dep in deps:
            counts[dep.signals[criterion].state.value] += 1
        out[criterion] = counts
    return {"total_dependencies": len(deps), "criteria": out}


def by_ecosystem(deps: list[Dependency]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dep in deps:
        counts[dep.ecosystem] = counts.get(dep.ecosystem, 0) + 1
    return dict(sorted(counts.items()))


def assessed(counts: dict[str, int]) -> int:
    return counts[State.CLEAN.value] + counts[State.FLAGGED.value]


def tier_a_was_assessed(artifact: dict) -> bool:
    """Did the run establish anything at all on the universally-available criteria?"""
    criteria = artifact["coverage"]["criteria"]
    return any(assessed(criteria[name]) > 0 for name in TIER_A if name in criteria)


def validate_artifact(artifact: dict) -> None:
    """Refuse an artifact that cannot support a report.

    This is deliberately a checker that fails when it inspects zero items, which is what
    the repository's contributing guide asks of anything that counts or filters.

    Args:
        artifact: A collector artifact.

    Raises:
        ReconciliationError: If the artifact is empty, describes no dependencies, has a
            coverage row that does not account for every dependency, or measured nothing
            on Tier A.
    """
    total = artifact.get("coverage", {}).get("total_dependencies")
    criteria = artifact.get("coverage", {}).get("criteria") or {}
    if not total:
        raise ReconciliationError(
            "artifact describes zero dependencies; a run that assessed nothing must not "
            "be rendered as a report finding nothing"
        )
    if not criteria:
        raise ReconciliationError("artifact has no coverage rows")
    for criterion, counts in criteria.items():
        if sum(counts.values()) != total:
            raise ReconciliationError(
                f"{criterion}: {counts} does not account for all {total} dependencies"
            )
    if len(artifact.get("dependencies") or []) != total:
        raise ReconciliationError(
            f"coverage claims {total} dependencies but "
            f"{len(artifact.get('dependencies') or [])} are listed"
        )
    if not tier_a_was_assessed(artifact):
        raise ReconciliationError(
            "no Tier A criterion was assessable for any dependency, so this run measured "
            "nothing; every source was unavailable"
        )
    _validate_transitive(artifact)


def _validate_transitive(artifact: dict) -> None:
    """The transitive accounting must exist and must reconcile.

    Absence is the failure mode: a report with no transitive statement reads as though
    the tree was covered, which is the old design's absence-means-clean defect at one
    remove.
    """
    transitive = artifact.get("transitive")
    if not isinstance(transitive, dict) or "examined" not in transitive:
        raise ReconciliationError(
            "artifact carries no transitive accounting, so the report cannot state "
            "whether the transitive tree was examined"
        )
    if not transitive["examined"]:
        if not transitive.get("reason"):
            raise ReconciliationError("an unexamined transitive tree must say why")
        return
    _reconcile_transitive_counts(transitive)


def _reconcile_transitive_counts(transitive: dict) -> None:
    total, checked = transitive.get("total", 0), transitive.get("checked", 0)
    flagged = transitive.get("flagged")
    unverifiable = transitive.get("unverifiable")
    if flagged is None:
        raise ReconciliationError("transitive accounting lists no flagged collection")
    if unverifiable is None:
        raise ReconciliationError(
            "transitive accounting lists no unverifiable collection; entries that "
            "cannot be verified must be named, not folded into the checked count"
        )
    # A sweep that checked nothing is only accountable with a stated reason (OSV
    # unreachable); without one, zero must reconcile like any other number — the
    # earlier `if checked and ...` guard could not fire on the value that matters most.
    if checked + len(unverifiable) != total and not (checked == 0 and transitive.get("reason")):
        raise ReconciliationError(
            f"transitive sweep checked {checked} and lists {len(unverifiable)} "
            f"unverifiable of {total} resolved; the difference is unaccounted for"
        )
    _reconcile_transitive_ledger(transitive, total)
    if checked > total:
        raise ReconciliationError(
            f"transitive sweep claims {checked} packages checked of {total} resolved"
        )
    if len(flagged) > checked:
        raise ReconciliationError(
            f"transitive sweep flags {len(flagged)} packages but checked only {checked}"
        )
    _reconcile_transitive_entries(flagged, unverifiable)


def _reconcile_transitive_ledger(transitive: dict, total: int) -> None:
    """Every lockfile triple must land in a named bucket.

    `total` is derived from the buckets themselves, so it reconciles by construction
    even when a triple is silently dropped before bucketing — which is how a nested
    copy of a direct dependency once vanished from the sweep with the counts still
    balancing. `lockfile_entries` is counted from the lock readers' output, before any
    exclusion or bucketing, so a triple dropped after they return breaks this equation
    instead of disappearing. A drop inside a reader is outside this guard's reach: the
    readers are the origin of the count, so nothing independent can contradict them.
    """
    lockfile_entries = transitive.get("lockfile_entries")
    excluded = transitive.get("excluded_direct")
    if lockfile_entries is None or excluded is None:
        raise ReconciliationError(
            "transitive accounting carries no lockfile ledger (lockfile_entries and "
            "excluded_direct); without it a dropped entry cannot be detected"
        )
    if total + excluded != lockfile_entries:
        raise ReconciliationError(
            f"the lockfile resolves {lockfile_entries} distinct packages but only "
            f"{total} are accounted for after excluding {excluded} direct-covered "
            f"entries; the difference vanished from the sweep"
        )


def _reconcile_transitive_entries(flagged: list, unverifiable: list) -> None:
    for entry in unverifiable:
        if not entry.get("reason"):
            raise ReconciliationError(f"unverifiable entry {entry.get('name')!r} carries no reason")
    for entry in flagged:
        if not entry.get("advisories"):
            raise ReconciliationError(
                f"transitive flag for {entry.get('name')!r} carries no advisory ids"
            )


def count_flags(artifact: dict) -> dict[str, int]:
    """Flags per criterion, taken from the dependency list rather than from coverage.

    The renderer compares this against the coverage table it prints. If a criterion is
    counted in one place and rendered in the other, the report contradicts itself, and
    that is how a finding reaches the coverage table and no reader.
    """
    out: dict[str, int] = {}
    for dep in artifact["dependencies"]:
        for name, signal in dep["signals"].items():
            if signal["state"] == State.FLAGGED.value:
                out[name] = out.get(name, 0) + 1
    return out


def to_json(deps: list[Dependency], scan: dict, notes: list[str], transitive: dict) -> dict:
    """Assemble the machine-readable artifact, refusing one that cannot reconcile.

    Args:
        deps: Every direct dependency, with all criteria populated.
        scan: What was examined — subject, manifests, commit, timestamp.
        notes: Scope and caveat lines for the report.
        transitive: Accounting for the lockfile-resolved packages beyond the direct set.
    """
    artifact = {
        "scan": scan,
        "target": scan.get("path", ""),
        "ecosystems": by_ecosystem(deps),
        "coverage": coverage(deps),
        "transitive": transitive,
        "notes": notes,
        "dependencies": [
            {
                **{k: v for k, v in asdict(dep).items() if k != "signals"},
                "flagged": dep.flagged(),
                "signals": {
                    name: {"state": sig.state.value, "detail": sig.detail, "value": sig.value}
                    for name, sig in dep.signals.items()
                },
            }
            for dep in sorted(deps, key=lambda d: (d.ecosystem, d.name))
        ],
    }
    validate_artifact(artifact)
    return artifact
