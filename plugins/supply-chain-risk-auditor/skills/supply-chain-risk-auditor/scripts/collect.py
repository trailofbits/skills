#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Collect supply-chain risk signals for a project's direct dependencies.

Emits a JSON artifact; `render.py` turns it into a report. Direct dependencies only, by
design — the scope is what keeps an audit sizeable. Dependency source is never fetched or
read; every signal comes from a registry, an advisory database, or repository metadata.

Two rules the code is arranged to enforce rather than remember:

- **Unavailable data is not evidence of risk.** Every criterion resolves to
  assessed-clean, assessed-flagged, or unassessable-with-reason.
- **An absent measurement is not a clean verdict.** An empty answer from a vulnerability
  database means "no advisories" only for a package known to exist.

Usage:
    uv run collect.py <project-path> [--json out.json] [--cache DIR] [--offline]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import sources
from model import (
    CRITERIA,
    TIER_SCORECARD,
    Dependency,
    ReconciliationError,
    Signal,
    to_json,
)

# Two years without a push is "stale". A one-year threshold flagged jinja2 and
# itsdangerous at 14 months — maintained-but-finished libraries whose flags teach a
# reader to skim past the criterion — while the packages that motivated it (stream-throttle
# at 11 years, dev-null at 9, escape-html at 4) clear two years easily. Reported with the
# actual date so a reader who draws the line elsewhere can.
STALE_DAYS = 730

# An absolute floor, not a rank. The original skill defined low popularity relative to the
# target's other dependencies, which is uncomputable across ecosystems: npm gives weekly
# downloads, PyPI returns -1, Go has no concept at all.
LOW_DOWNLOADS_PER_WEEK = 1000

REPO_CRITERIA = ("archived", "staleness", "security_policy")

# Shared by every criterion of every dependency that resolves outside its public
# registry, so the report can group them into one bullet per criterion. The specific
# source is the signal's value, and each dependency also gets its own Method note.
NON_REGISTRY_REASON = (
    "the dependency resolves from outside its public registry, so registry-keyed data "
    "does not apply to it (the source is named in Method and caveats)"
)


# ------------------------------------------------------------------ npm manifests


def _npm_locked_versions(project: Path) -> dict[str, str]:
    """Resolved direct-dependency versions from an npm lockfile, if one exists."""
    for name in ("package-lock.json", "npm-shrinkwrap.json"):
        path = project / name
        if not path.exists():
            continue
        data = _read_json(path)
        out: dict[str, str] = {}
        for key, entry in (data.get("packages") or {}).items():
            if key.startswith("node_modules/") and entry.get("version"):
                out[key.removeprefix("node_modules/")] = entry["version"]
        for pkg, entry in (data.get("dependencies") or {}).items():
            if isinstance(entry, dict) and entry.get("version") and pkg not in out:
                out[pkg] = entry["version"]
        if out:
            return out
    return {}


# One lockfile-resolved package: (ecosystem, name, version, dev-only or None).
LockedPackage = tuple[str, str, str, bool | None]
# A lockfile entry whose registry existence cannot be attested, with the reason.
Unverifiable = dict


def _npm_all_locked(
    project: Path,
) -> tuple[list[LockedPackage], list[Unverifiable], str | None, str | None]:
    """Every package the npm lockfile resolves, split by registry attestation.

    Returns (attested packages, unverifiable entries, lockfile name or None, note or
    None). Attested means the entry carries an integrity hash for a registry tarball —
    the datum that lets an empty advisory answer read as clean. Git, file, and
    private-registry entries go in the unverifiable list instead: OSV data is keyed by
    public-registry name, so querying it for a package that resolves elsewhere either
    proves nothing (absence) or attributes another package's advisories to it.

    Only v2+ lockfiles carry the flat `packages` table; a v1-only lockfile yields a
    note rather than a silent zero that would read as "no transitive packages".
    """
    for lockname in ("package-lock.json", "npm-shrinkwrap.json"):
        path = project / lockname
        if not path.exists():
            continue
        packages = _read_json(path).get("packages")
        if not isinstance(packages, dict):
            return (
                [],
                [],
                None,
                f"{lockname} predates npm 7's flat package table, so the transitive tree "
                f"was not read from it.",
            )
        out: list[LockedPackage] = []
        unverifiable: list[Unverifiable] = []
        for key, entry in packages.items():
            if "node_modules/" not in key or entry.get("link") or not entry.get("version"):
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
            resolved = str(entry.get("resolved") or "")
            if entry.get("integrity") and resolved.startswith("https://registry.npmjs.org/"):
                out.append(("npm", name, entry["version"], bool(entry.get("dev"))))
            else:
                unverifiable.append(
                    {
                        "ecosystem": "npm",
                        "name": name,
                        "version": entry["version"],
                        "reason": (
                            f"resolves from {resolved or 'an undeclared source'}, not the "
                            f"npm registry, so registry-keyed advisory data does not "
                            f"apply to it"
                        )
                        if not resolved.startswith("https://registry.npmjs.org/")
                        else "lockfile entry carries no integrity hash",
                    }
                )
        return out, unverifiable, lockname, None
    return [], [], None, None


_EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?$")
_ALIAS = re.compile(r"^npm:(?P<name>@?[^@]+(?:/[^@]+)?)@")
# Specs that are not a registry version range. The dependency key is then a local or
# remote artifact rather than a package name that can be looked up.
_NON_REGISTRY = ("file:", "link:", "workspace:", "portal:", "git+", "git:", "http://", "https://")


def _npm_spec_kind(spec: str) -> str:
    """Classify an npm dependency spec: `registry`, `alias`, or a non-registry source."""
    spec = (spec or "").strip()
    if spec.startswith("npm:"):
        return "alias"
    for prefix in _NON_REGISTRY:
        if spec.startswith(prefix):
            return "non-registry"
    # `owner/repo` with no version operator is GitHub shorthand, not a registry range.
    if "/" in spec and not any(ch in spec for ch in "^~<>= .*") and spec.count("/") == 1:
        return "non-registry"
    return "registry"


def _exact_npm_pin(spec: str) -> str | None:
    """Return an exact version only for a genuine pin.

    `1.x`, `1.2.x` and `2` are ranges. Accepting them as pins fed the range string to OSV
    as if it were a version and suppressed resolution of the real release.
    """
    spec = (spec or "").strip()
    return spec if _EXACT_SEMVER.match(spec) else None


def parse_npm(project: Path) -> tuple[list[Dependency], list[str]]:
    """Direct npm dependencies from package.json, with the resolved version where known.

    Returns:
        The dependencies, and notes for anything that could not be treated as a registry
        package. `optionalDependencies` are installed by default and so are included;
        `peerDependencies` are the consumer's responsibility and are noted, not audited.
    """
    manifest = project / "package.json"
    if not manifest.exists():
        return [], []
    data = _read_json(manifest)
    locked = _npm_locked_versions(project)
    deps: list[Dependency] = []
    notes: list[str] = []
    fields = (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False))
    for field_name, is_dev in fields:
        table = data.get(field_name) or {}
        if not isinstance(table, dict):
            raise SystemExit(f"error: {manifest}: '{field_name}' is not a table of name -> spec")
        for name, spec in table.items():
            dep, note = _npm_dependency(name, str(spec), is_dev, locked)
            if dep:
                deps.append(dep)
            if note:
                notes.append(note)
    peers = data.get("peerDependencies") or {}
    if peers:
        count = "1 peerDependency was" if len(peers) == 1 else f"{len(peers)} peerDependencies were"
        notes.append(
            f"{count} not audited: they are supplied by the consuming project rather than "
            f"installed by this one."
        )
    return deps, notes


def _npm_dependency(
    name: str, spec: str, is_dev: bool, locked: dict[str, str]
) -> tuple[Dependency | None, str | None]:
    kind = _npm_spec_kind(spec)
    declared = name
    if kind == "alias":
        match = _ALIAS.match(spec)
        target = match.group("name") if match else None
        if not target:
            return None, f"`{name}` uses an npm alias this parser could not read ({spec})."
        note = f"`{name}` is an alias for `{target}`; the audit follows the target."
        name = target
        kind = "registry"
    else:
        note = None
    if kind == "non-registry":
        reason = f"resolves from {spec}, not the npm registry"
        return (
            Dependency(ecosystem="npm", name=name, dev=is_dev, non_registry_reason=reason),
            f"`{name}` {reason}, so no registry or advisory data applies to it.",
        )
    # The lockfile keys the declared name (node_modules/<declared>), so an alias must
    # be looked up under it, not under the rewritten target.
    version, source = locked.get(declared), "lockfile"
    if not version:
        version, source = _exact_npm_pin(spec), "manifest-pin"
    if not version:
        source = "unresolved"
    return Dependency(
        ecosystem="npm", name=name, version=version, version_source=source, dev=is_dev
    ), note


# ----------------------------------------------------------------- PyPI manifests

_REQ_SPLIT = re.compile(r"[<>=!~\[;@]")
# A permissive PEP 440 shape: enough to reject line-continuation and inline-option
# debris ("2.19.0 \\", "2.19.0 --hash") that would otherwise be sent to OSV as a
# version and printed in the report as a version-matched claim.
#
# The optional `v` is load-bearing: PEP 440 permits it, pip accepts `django==v3.2.0`,
# and requiring a leading digit turned that legal pin into an unresolved version, so
# advisories were matched against the latest release and 62 real ones read as clean. The
# prefix is stripped rather than kept, because the canonical form is what OSV, the
# report, and any hand-check should agree on.
_VALID_VERSION = re.compile(r"^v?[0-9][0-9A-Za-z.+!_-]*$")
_PEP503 = re.compile(r"[-_.]+")
_VALID_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalisation: lowercase, runs of -_. collapsed to one hyphen."""
    return _PEP503.sub("-", name).lower()


def _strip_marker(line: str) -> str:
    """Drop a PEP 508 environment marker.

    Markers contain `==`, so leaving one in place made `psutil; sys_platform == 'win32'`
    resolve to the version `'win32'` — fabricated, then sent to OSV and reported as fact.
    """
    return line.split(";", 1)[0].strip()


# `name [extras] @ url` — PEP 508's direct-reference form. `@` is also a name
# terminator in _REQ_SPLIT, so without this check the URL is silently discarded and a
# git or file fork is looked up on PyPI under the public package's name.
_DIRECT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\]\s*)?@\s*(\S+)")


def _direct_reference_url(line: str) -> str | None:
    """The URL of a PEP 508 direct reference, if this requirement uses one."""
    spec = _strip_marker(line.split("#", 1)[0].strip())
    match = _DIRECT_REF.match(spec)
    return match.group(1) if match else None


def _requirement_name(line: str) -> str | None:
    """Extract a distribution name, or None when the line declares no requirement."""
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    candidate = _REQ_SPLIT.split(_strip_marker(line), 1)[0].strip()
    return candidate or None


# Extra and requirements-file names that conventionally hold development dependencies.
# `coverage` and `pytest` arriving from a `test` extra are not production dependencies, and
# saying they ship in the built artifact is a claim the manifest does not support.
# Matched as whole tokens, not substrings: substring matching classified the runtime
# extras `docker` ("doc") and `tracing` ("ci") as build-time only, which understates
# blast radius — the unsafe direction for this report.
_DEV_GROUP_TOKENS = frozenset(
    "test tests testing dev development doc docs lint linting type types typing "
    "typecheck check checks bench benchmark benchmarks ci".split()
)
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _is_dev_group(name: str) -> bool:
    return any(token in _DEV_GROUP_TOKENS for token in _TOKEN_SPLIT.split(name.lower()))


def _pypi_specs(project: Path) -> tuple[dict[str, tuple[str, bool]], list[str]]:
    """Gather name -> (raw spec, is_dev) for every direct Python requirement."""
    specs: dict[str, tuple[str, bool]] = {}
    notes: list[str] = []
    pyproject = project / "pyproject.toml"
    if pyproject.exists():
        data = _read_toml(pyproject)
        groups = [((data.get("project") or {}).get("dependencies") or [], False)]
        for extra, items in (
            (data.get("project") or {}).get("optional-dependencies") or {}
        ).items():
            groups.append((items, _is_dev_group(extra)))
        for group in (data.get("dependency-groups") or {}).values():
            # PEP 735 groups exist for development dependencies by definition.
            groups.append(([g for g in group if isinstance(g, str)], True))
        poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
        if poetry:
            notes.append(
                f"{len(poetry)} Poetry dependencies in the tool.poetry.dependencies "
                f"table were not parsed; only PEP 621 and PEP 735 tables are read."
            )
        for group, is_dev in groups:
            _absorb_specs(group, specs, notes, is_dev)
    for candidate in sorted(project.glob("requirements*.txt")):
        lines = _read_text(candidate).splitlines()
        includes = [ln for ln in lines if ln.strip().startswith(("-r", "--requirement"))]
        if includes:
            notes.append(
                f"{candidate.name} includes {len(includes)} other requirements file(s) that "
                f"were not followed, so its dependency list may be incomplete."
            )
        _absorb_specs(lines, specs, notes, _is_dev_group(candidate.stem))
    return specs, notes


def _absorb_specs(
    raw_lines: list[str], specs: dict[str, tuple[str, bool]], notes: list[str], is_dev: bool
) -> None:
    for raw in raw_lines:
        if not isinstance(raw, str):
            continue
        name = _requirement_name(raw)
        if not name:
            continue
        if not _VALID_NAME.match(name):
            notes.append(f"skipped an unparseable requirement: {raw.strip()!r}")
            continue
        canonical = normalize_pypi_name(name)
        existing = specs.get(canonical)
        if existing is None or (existing[1] and not is_dev):
            specs[canonical] = (raw, is_dev)


# What terminates the value of a `==` pin. Deliberately not `_REQ_SPLIT`, which also
# splits on `!` for the `!=` operator and would truncate a PEP 440 epoch — `1!2.0`
# became the version `1`, a wrong pin reported as version-matched.
_VERSION_END = re.compile(r"[\s,;]")


def _pypi_version(raw: str, locked: dict[str, str], canonical: str) -> tuple[str | None, str]:
    if canonical in locked:
        return locked[canonical], "lockfile"
    spec = _strip_marker(raw)
    if "==" in spec:
        candidate = _VERSION_END.split(spec.split("==", 1)[1].strip().strip(","), 1)[0].strip()
        # `1.0.*` is a range, not a pin, and pip-compile hash lines leave debris
        # (`2.19.0 \\`) that must not be reported as a version.
        if candidate and "*" not in candidate and _VALID_VERSION.match(candidate):
            return candidate.removeprefix("v"), "manifest-pin"
    return None, "unresolved"


def _uv_lock_versions(project: Path) -> dict[str, str]:
    lock = project / "uv.lock"
    if not lock.exists():
        return {}
    data = _read_toml(lock)
    return {
        normalize_pypi_name(pkg["name"]): pkg["version"]
        for pkg in data.get("package") or []
        if pkg.get("name") and pkg.get("version")
    }


def _uv_non_registry_sources(project: Path) -> dict[str, str]:
    """Canonical name -> source kind for uv.lock entries that do not resolve from PyPI.

    A direct dependency in this map must not be looked up on PyPI by name: the lock
    says the project installs it from git, a directory, or a local path, so a
    same-named public package's advisories and metadata do not apply to it.
    """
    lock = project / "uv.lock"
    if not lock.exists():
        return {}
    out: dict[str, str] = {}
    for pkg in _read_toml(lock).get("package") or []:
        source = pkg.get("source") or {}
        if not pkg.get("name") or source.get("registry"):
            continue
        if source.get("editable") or source.get("virtual"):
            continue
        out[normalize_pypi_name(pkg["name"])] = next(iter(source), "unknown")
    return out


def _uv_all_locked(
    project: Path,
) -> tuple[list[LockedPackage], list[Unverifiable], str | None, str | None]:
    """Every package uv.lock resolves, split by registry attestation.

    The lock includes the audited project itself as an editable or virtual source; that
    entry is the subject, not a dependency. Git, directory, and path sources are
    unverifiable against PyPI — a vendored fork at `../vendor/flask` must not inherit
    PyPI flask's advisories, since vendoring a patched fork is a common way to fix
    exactly those. uv.lock does not mark which packages are development-only per entry,
    so the dev marker is None throughout.
    """
    lock = project / "uv.lock"
    if not lock.exists():
        return [], [], None, None
    out: list[LockedPackage] = []
    unverifiable: list[Unverifiable] = []
    for pkg in _read_toml(lock).get("package") or []:
        source = pkg.get("source") or {}
        if not pkg.get("name") or not pkg.get("version"):
            continue
        if source.get("editable") or source.get("virtual"):
            continue
        name = normalize_pypi_name(pkg["name"])
        if source.get("registry"):
            out.append(("PyPI", name, pkg["version"], None))
        else:
            kind = next(iter(source), "unknown")
            unverifiable.append(
                {
                    "ecosystem": "PyPI",
                    "name": name,
                    "version": pkg["version"],
                    "reason": (
                        f"resolves from a {kind} source, not PyPI, so PyPI-keyed "
                        f"advisory data does not apply to it"
                    ),
                }
            )
    return out, unverifiable, "uv.lock", None


def parse_pypi(project: Path) -> tuple[list[Dependency], list[str]]:
    """Direct Python dependencies from pyproject.toml and/or requirements files."""
    specs, notes = _pypi_specs(project)
    if not specs:
        return [], notes
    locked = _uv_lock_versions(project)
    non_registry = _uv_non_registry_sources(project)
    deps = []
    for canonical, (raw, is_dev) in specs.items():
        version, source = _pypi_version(raw, locked, canonical)
        reason = None
        url = _direct_reference_url(raw)
        if url:
            reason = f"resolves from {url}, not PyPI"
        elif canonical in non_registry:
            reason = f"resolves from a {non_registry[canonical]} source, not PyPI"
        if reason:
            notes.append(f"`{canonical}` {reason}, so no registry or advisory data applies to it.")
        deps.append(
            Dependency(
                ecosystem="PyPI",
                name=canonical,
                version=version,
                version_source=source,
                dev=is_dev,
                non_registry_reason=reason,
            )
        )
    return deps, notes


# ------------------------------------------------------------------- Go manifests

_GOMOD_REQUIRE = re.compile(r"^\s*(?:require\s+)?([\w.\-]+(?:\.[\w.\-]+)*/[^\s]+)\s+(v[^\s]+)")
_GOMOD_BLOCK_OPEN = re.compile(r"^(require|replace|exclude|retract)\s*\($")
_GOMOD_OTHER = ("replace ", "exclude ", "retract ")


def _gomod_line_kind(line: str, block: str | None) -> tuple[str | None, str]:
    """Classify one go.mod line, tracking which block it sits in.

    Returns:
        The block in effect after this line, and one of `require`, `indirect`,
        `directive`, or `ignore`. Block context is what separates a requirement from a
        `replace` entry, since both read as `module version`.
    """
    stripped = line.strip()
    opener = _GOMOD_BLOCK_OPEN.match(stripped)
    if opener:
        return opener.group(1), "ignore"
    if stripped == ")":
        return None, "ignore"
    if block in {"replace", "exclude", "retract"} or stripped.startswith(_GOMOD_OTHER):
        return block, "directive"
    if block not in {"require", None}:
        return block, "ignore"
    if not _GOMOD_REQUIRE.match(line):
        return block, "ignore"
    if block is None and not stripped.startswith("require "):
        return block, "ignore"
    if "// indirect" in line:
        return block, "indirect"
    return block, "require"


def _go_dependency(line: str) -> Dependency:
    module, version = _GOMOD_REQUIRE.match(line).groups()
    return Dependency(
        ecosystem="Go",
        name=module,
        # OSV wants Go versions without the `v` prefix.
        version=version.removeprefix("v"),
        # go.mod records a *minimum*; module-version selection can pick higher.
        version_source="go-mod-minimum",
        # go.mod has no dev section; asserting either way would invent a distinction.
        dev=None,
    )


def parse_go(project: Path) -> tuple[list[Dependency], list[str]]:
    """Direct Go modules from go.mod.

    Block context matters: every block-form directive line looks like `module version`, so
    a parser without it reads `replace (...)` entries as requirements. That reports the
    module the project replaced *away from*, at the abandoned version, while never
    assessing the replacement actually built — and reports `exclude` entries as used.
    """
    gomod = project / "go.mod"
    if not gomod.exists():
        return [], []
    deps: list[Dependency] = []
    notes: list[str] = []
    block: str | None = None
    replaced = 0
    for line in _read_text(gomod).splitlines():
        block, kind = _gomod_line_kind(line, block)
        if kind == "directive":
            replaced += 1
        elif kind == "require":
            deps.append(_go_dependency(line))
    if replaced:
        notes.append(
            f"{replaced} replace/exclude/retract directives in go.mod were not treated as "
            f"dependencies; where a module is replaced, the replacement was not audited."
        )
    return deps, notes


_GO_DIRECTIVE = re.compile(r"^go\s+(\d+)\.(\d+)", re.MULTILINE)


def _go_indirect(
    project: Path,
) -> tuple[list[LockedPackage], list[Unverifiable], str | None, str | None]:
    """Indirect modules from go.mod, which is complete only for go 1.17 and later.

    Modules declaring an older go directive list an arbitrary subset of their indirect
    requirements, so reading them would report "the transitive tree was checked" about a
    tree that was mostly absent. go.mod carries no dev marker; None throughout.

    go.mod attests nothing about existence — the split into attested and unverifiable
    happens in `sweep_transitive`, which asks the Go module proxy about each entry.
    """
    gomod = project / "go.mod"
    if not gomod.exists():
        return [], [], None, None
    text = _read_text(gomod)
    match = _GO_DIRECTIVE.search(text)
    if not match or (int(match.group(1)), int(match.group(2))) < (1, 17):
        return (
            [],
            [],
            None,
            "go.mod declares a go directive older than 1.17 (or none), so its indirect "
            "module list is incomplete and the transitive tree was not read from it.",
        )
    out: list[LockedPackage] = []
    block: str | None = None
    for line in text.splitlines():
        block, kind = _gomod_line_kind(line, block)
        if kind == "indirect":
            module, version = _GOMOD_REQUIRE.match(line).groups()
            out.append(("Go", module, version.removeprefix("v"), None))
    return out, [], "go.mod", None


PARSERS = (parse_npm, parse_pypi, parse_go)


def _read_text(path: Path) -> str:
    """Read a plain-text manifest as UTF-8, refusing anything that will not decode.

    The JSON and TOML readers below already turn an undecodable file into a refusal.
    Without this, `requirements*.txt` and `go.mod` did not: `main()` catches only
    `ReconciliationError`, so a `UnicodeDecodeError` escaped as a traceback. That is not
    hypothetical on the platform this exists to support — PowerShell 5.1 redirection
    writes UTF-16LE with a BOM, so any requirements file generated with `>` on a stock
    Windows box begins with two bytes that are invalid UTF-8.

    Args:
        path: The file to read.

    Returns:
        The decoded text.

    Raises:
        SystemExit: The file is not UTF-8, or could not be read.
    """
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(
            f"error: {path} is not UTF-8, so its contents cannot be read: {exc}. "
            f"A file produced by PowerShell redirection is UTF-16 — re-save it as "
            f"UTF-8, or regenerate it through `Out-File -Encoding utf8`."
        ) from exc
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"), strict=False)
        if not isinstance(data, dict):
            raise SystemExit(
                f"error: {path} holds a JSON {type(data).__name__}, not the object this "
                f"manifest format requires"
            )
        return data
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {path} is not valid JSON: {exc}") from exc
    # UnicodeDecodeError is a ValueError, not a JSONDecodeError, so the two clauses
    # around this one do not catch it and it used to escape as a traceback. JSON is
    # UTF-8 by RFC 8259, so a manifest that is not decodable is malformed input and
    # earns the same refusal as invalid syntax.
    except UnicodeDecodeError as exc:
        raise SystemExit(f"error: {path} is not UTF-8, which JSON requires: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def _read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"error: {path} is not valid TOML: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise SystemExit(f"error: {path} is not UTF-8, which TOML requires: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def discover(project: Path) -> tuple[list[Dependency], list[str]]:
    """Parse every manifest, dropping the weaker of any duplicate."""
    found: list[Dependency] = []
    notes: list[str] = []
    for parser in PARSERS:
        deps, parser_notes = parser(project)
        found.extend(deps)
        notes.extend(parser_notes)
    seen: dict[str, Dependency] = {}
    for dep in found:
        existing = seen.get(dep.key)
        if existing is None or (existing.dev is True and dep.dev is not True):
            seen[dep.key] = dep
    return list(seen.values()), notes


# ---------------------------------------------------------------------- signalling


def _reason(exc: Exception, source: str) -> str:
    """A human-facing reason. The raw URL stays in the artifact, not in the report."""
    text = str(exc)
    if isinstance(exc, sources.NotFound):
        return f"not published in {source}"
    if "rate limited" in text:
        return f"{source} rate-limited this audit"
    if "offline" in text:
        return f"{source} was not in the local cache and this run was offline"
    return f"{source} did not answer"


def _advisory_signal(dep: Dependency, found: dict[str, list[str]]) -> Signal:
    """Advisories, refusing to read an empty answer as safety for an unknown package."""
    if dep.key not in found:
        return Signal.unassessable("OSV did not answer for this package")
    ids = found[dep.key]
    if not ids:
        if dep.exists is not True:
            return Signal.unassessable(
                "OSV recorded no advisories, but this package was not confirmed to exist "
                "in its registry, and an empty answer cannot distinguish 'no advisories' "
                "from 'unknown package'"
            )
        return Signal.clean("no advisories recorded", [])
    count = f"{len(ids)} advisory" if len(ids) == 1 else f"{len(ids)} advisories"
    verb = "affects" if len(ids) == 1 else "affect"
    described = {
        "lockfile": f"{count} {verb} the installed {dep.version}",
        "manifest-pin": f"{count} {verb} the pinned {dep.version}",
        "go-mod-minimum": (
            f"{count} {verb} {dep.version}, go.mod's minimum — module-version selection "
            f"may build a higher version"
        ),
        "latest-release": (
            f"{count} {verb} {dep.version}, the current latest release; the manifest gives "
            f"a range, so the version this project installs was not resolved"
        ),
    }
    return Signal.flagged(
        described.get(
            dep.version_source,
            f"{count} recorded for the package; no version resolved, so this is historical "
            f"rather than a statement about what is installed",
        ),
        ids,
    )


def human_days(days: int) -> str:
    """A duration at the precision a reader can use.

    "no push in 3,884 days" is four significant figures on a decade, and reads as scanner
    output rather than as a judgement. The exact date travels alongside for anyone who
    wants it.
    """
    if days < 60:
        return f"{days} days"
    if days < 730:
        return f"{round(days / 30.4)} months"
    return f"{days / 365.25:.0f} years"


def _staleness_signal(pushed: str | None) -> Signal:
    if not pushed:
        return Signal.unassessable("repository reports no last-push date")
    try:
        when = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
    except ValueError:
        return Signal.unassessable(f"could not read the last-push date ({pushed!r})")
    if when.tzinfo is None:
        return Signal.unassessable(f"last-push date has no timezone ({pushed!r})")
    days = (datetime.now(UTC) - when).days
    if days < 0:
        return Signal.clean("pushed today (repository clock is ahead)", pushed)
    if days > STALE_DAYS:
        return Signal.flagged(f"no push in {human_days(days)} (last {pushed[:10]})", pushed)
    return Signal.clean(f"pushed {human_days(days)} ago", pushed)


def _concentration_signal(meta: dict) -> Signal:
    """Who can actually ship code into this package.

    Branches on provenance because CI publishing moves the trust boundary off the registry
    ACL and onto repository merge rights, which GitHub does not expose to third parties
    (`/collaborators` returns 403). "1 maintainer, low risk" for a CI-published package
    would be confidently wrong.
    """
    if meta["provenance"]:
        return Signal.unassessable(
            "publishes from CI with provenance, so the effective publisher set is whoever "
            "can merge to the release branch — not externally observable",
            meta["maintainers"],
        )
    if not meta["maintainers"]:
        return Signal.unassessable("registry lists no maintainers", [])
    humans, bots = meta["human_maintainers"], meta["automated_maintainers"]
    if not humans:
        return Signal.unassessable(
            "every listed maintainer looks automated; the human population is unknown",
            meta["maintainers"],
        )
    if len(humans) == 1:
        # Name the filtering: the bot heuristic is a guess, and it is the step that turns
        # two listed maintainers into a flag.
        aside = f"; {', '.join(bots)} looked automated and was excluded" if bots else ""
        return Signal.flagged(
            f"single human publisher ({humans[0]}) of {len(meta['maintainers'])} listed{aside}",
            meta["maintainers"],
        )
    return Signal.clean(f"{len(humans)} human publishers hold publish rights", meta["maintainers"])


def _fill(dep: Dependency, criteria: tuple[str, ...], signal: Signal) -> None:
    for criterion in criteria:
        dep.signals[criterion] = signal


# ------------------------------------------------------------------- enrichment


def enrich_repo(http: sources.Http, dep: Dependency, token: str | None) -> None:
    """Repository-derived signals, shared by every ecosystem."""
    if dep.repo is None:
        _fill(
            dep,
            REPO_CRITERIA,
            Signal.unassessable("no source repository could be resolved for this package"),
        )
        _fill(dep, TIER_SCORECARD, Signal.unassessable("no source repository to score"))
        return
    try:
        repo = sources.github_repo(http, dep.repo, token)
    except sources.RepoIdentifierError as exc:
        _fill(dep, REPO_CRITERIA, Signal.unassessable(str(exc), dep.repo))
        _fill(dep, TIER_SCORECARD, Signal.unassessable(str(exc), dep.repo))
        return
    except sources.Unavailable as exc:
        _fill(dep, REPO_CRITERIA, Signal.unassessable(_reason(exc, "the GitHub API"), str(exc)))
        _fill(dep, TIER_SCORECARD, Signal.unassessable(_reason(exc, "the GitHub API"), str(exc)))
        return

    dep.signals["archived"] = (
        Signal.flagged("repository is archived", True)
        if repo["archived"]
        else Signal.clean("repository is active", False)
    )
    dep.signals["staleness"] = _staleness_signal(repo["pushed_at"])
    policy = repo["security_policy"]
    dep.signals["security_policy"] = (
        Signal.unassessable("could not determine whether a security policy is published")
        if policy is None
        else Signal.clean(
            "publishes a security policy" if policy else "no security policy found", policy
        )
    )
    enrich_scorecard(http, dep)


def enrich_scorecard(http: sources.Http, dep: Dependency) -> None:
    """OpenSSF Scorecard individual checks. Never the aggregate score."""
    try:
        scores = sources.scorecard_checks(http, dep.repo or "")
    except sources.Unavailable as exc:
        reason = (
            "OpenSSF Scorecard has no report for this repository"
            if isinstance(exc, sources.NotFound)
            else _reason(exc, "the Scorecard API")
        )
        _fill(dep, TIER_SCORECARD, Signal.unassessable(reason))
        return
    for check, (criterion, threshold) in sources.SCORECARD_CHECKS.items():
        score = scores.get(check)
        if score is None:
            dep.signals[criterion] = Signal.unassessable(
                f"Scorecard did not report {check} for this repository"
            )
        elif score < 0:
            # Scorecard's own "could not evaluate", commonly for want of admin access.
            dep.signals[criterion] = Signal.unassessable(
                f"Scorecard could not evaluate {check} (score -1)"
            )
        elif threshold is not None and score < threshold:
            dep.signals[criterion] = Signal.flagged(
                f"{check} scores {score}/10 (below {threshold})", score
            )
        else:
            dep.signals[criterion] = Signal.clean(f"{check} scores {score}/10", score)


def enrich_npm(http: sources.Http, dep: Dependency, token: str | None) -> None:
    """npm publishes the richest metadata of the three ecosystems."""
    try:
        meta = sources.npm_metadata(http, dep.name)
    except sources.Unavailable as exc:
        reason = _reason(exc, "the npm registry")
        _fill(
            dep,
            ("deprecated", "publisher_concentration", "install_script"),
            Signal.unassessable(reason),
        )
        dep.signals["provenance"] = Signal.unassessable(reason)
    else:
        dep.signals["deprecated"] = (
            Signal.flagged(
                f"deprecated by its maintainers: {meta['deprecated']}", meta["deprecated"]
            )
            if meta["deprecated"]
            else Signal.clean("not deprecated", False)
        )
        dep.signals["publisher_concentration"] = _concentration_signal(meta)
        dep.signals["install_script"] = (
            Signal.flagged(
                "runs an install script; `npm ci --ignore-scripts` prevents execution", True
            )
            if meta["has_install_script"]
            else Signal.clean("no install script", False)
        )
        dep.signals["provenance"] = Signal.clean(
            "publishes with provenance" if meta["provenance"] else "no publish provenance",
            meta["provenance"],
        )
    try:
        dep.signals["downloads"] = _download_signal(sources.npm_downloads(http, dep.name))
    except sources.Unavailable as exc:
        dep.signals["downloads"] = Signal.unassessable(
            _reason(exc, "the npm download API"), str(exc)
        )
    enrich_repo(http, dep, token)


def _download_signal(count: int) -> Signal:
    """Download volume, measured and never flagged.

    A floor of 1,000/week flagged nothing across 141 dependencies in three real projects,
    so as a detector it did no work. As context it does a great deal: a single-publisher
    package at 450M downloads/week is a different proposition from one at 126K, and that
    belongs beside the finding rather than as a finding of its own.
    """
    scale = "low" if count < LOW_DOWNLOADS_PER_WEEK else "normal"
    return Signal.clean(f"{count:,} downloads/week ({scale} volume)", count)


def enrich_pypi(http: sources.Http, dep: Dependency, token: str | None) -> None:
    """PyPI publishes no upload ACL and disables its download counters."""
    dep.signals["publisher_concentration"] = Signal.unassessable(
        "PyPI publishes no upload ACL, so who can publish this package is not observable"
    )
    dep.signals["downloads"] = Signal.unassessable(
        "PyPI's download counters are disabled and return -1"
    )
    dep.signals["provenance"] = Signal.unassessable(
        "PyPI publish attestations are not read by this collector"
    )
    dep.signals["install_script"] = Signal.unassessable(
        "install-time execution depends on whether a wheel or an sdist is installed, which "
        "this collector does not determine"
    )
    try:
        meta = sources.pypi_metadata(http, dep.name, dep.version)
    except sources.Unavailable as exc:
        dep.signals["deprecated"] = Signal.unassessable(_reason(exc, "PyPI"), str(exc))
    else:
        dep.signals["deprecated"] = _yank_signal(meta, dep)
    enrich_repo(http, dep, token)


def _yank_signal(meta: dict, dep: Dependency) -> Signal:
    """Yank status is per release, so it must be read for the version in play."""
    if meta["yanked"] is None:
        return Signal.unassessable(
            f"PyPI does not list release {dep.version} for this package, so its yank "
            f"status is unknown"
        )
    if meta["yanked"]:
        return Signal.flagged(
            f"release {meta['yank_version']} is yanked: "
            f"{meta['yanked_reason'] or 'no reason given'}",
            True,
        )
    return Signal.clean(f"release {meta['yank_version']} is not yanked", False)


def enrich_go(http: sources.Http, dep: Dependency, token: str | None) -> None:
    """Go has no registry: a module path is a VCS path, so there is no ACL to read."""
    dep.signals["publisher_concentration"] = Signal.unassessable(
        "Go has no registry ACL; publishing is repository write access, which GitHub does "
        "not expose to third parties"
    )
    dep.signals["downloads"] = Signal.unassessable("Go has no download-count concept")
    dep.signals["provenance"] = Signal.unassessable(
        "Go has no publish-provenance concept; module integrity comes from the checksum "
        "database instead"
    )
    dep.signals["deprecated"] = Signal.unassessable(
        "module deprecation is declared in the module's own go.mod, which is not read"
    )
    # Not a gap: the Go toolchain has no install-time script hook, so the risk is absent.
    dep.signals["install_script"] = Signal.clean(
        "Go modules have no install-time script execution", False
    )
    enrich_repo(http, dep, token)


ENRICHERS = {"npm": enrich_npm, "PyPI": enrich_pypi, "Go": enrich_go}


# ----------------------------------------------------------------------- resolve


def resolve_from_registry(http: sources.Http, deps: list[Dependency]) -> None:
    """Establish existence, a version, and a repository before querying OSV.

    Existence matters most: an empty OSV answer only means "no advisories" for a package
    that is really published. Version resolution matters because "every advisory ever
    recorded against tornado" is close to useless next to "advisories affecting the
    release you would install". Repository resolution needs a concrete version, so
    without this step every unpinned dependency lost its repository signals.
    """
    for dep in deps:
        meta = _registry_metadata(http, dep)
        if meta is None:
            continue
        dep.exists = True
        if not dep.version and meta.get("latest"):
            dep.version = meta["latest"]
            dep.version_source = "latest-release"
        if not dep.repo and meta.get("repository"):
            dep.repo = meta["repository"]


def _registry_metadata(http: sources.Http, dep: Dependency) -> dict | None:
    try:
        if dep.ecosystem == "npm":
            return sources.npm_metadata(http, dep.name)
        if dep.ecosystem == "PyPI":
            return sources.pypi_metadata(http, dep.name, dep.version)
        if dep.ecosystem == "Go":
            # The proxy answering is the existence proof — so the proxy must be asked.
            # An earlier version asserted this in a comment while never making the
            # request, and nonexistent modules read as assessed-clean.
            sources.go_module_latest(http, dep.name)
            dep.exists = True
    except sources.NotFound:
        dep.exists = False
        return None
    except sources.Unavailable:
        return None
    return None


def resolve_go_repos(http: sources.Http, deps: list[Dependency]) -> None:
    """Map Go module paths to repositories, preferring deps.dev over the path itself.

    Vanity paths are not VCS paths: truncating go.opentelemetry.io/otel to three segments
    yields a host that does not exist, and the fallback must not then be stated as fact.
    """
    for dep in deps:
        if dep.ecosystem != "Go" or dep.repo:
            continue
        try:
            dep.repo = sources.depsdev_repo(http, dep.ecosystem, dep.name, dep.version)
        except sources.Unavailable:
            parts = dep.name.split("/")
            guess = "/".join(parts[:3]) if len(parts) >= 3 else dep.name
            dep.repo = guess if guess.startswith(("github.com/", "gitlab.com/")) else None


def resolve_repos(http: sources.Http, deps: list[Dependency]) -> None:
    for dep in deps:
        if dep.repo or not dep.version:
            continue
        try:
            dep.repo = sources.depsdev_repo(http, dep.ecosystem, dep.name, dep.version)
        except sources.Unavailable:
            continue


# --------------------------------------------------------------------------- run


def _advisory_map(
    http: sources.Http, deps: list[Dependency], notes: list[str]
) -> dict[str, list[str]]:
    queries = [(d.ecosystem, d.name, d.version) for d in deps]
    try:
        ids_per_query = sources.osv_advisories(http, queries)
    except sources.Unavailable as exc:
        notes.append(f"OSV was unreachable ({exc}); advisory coverage is zero.")
        return {}
    return {dep.key: ids for dep, ids in zip(deps, ids_per_query, strict=True)}


def _locked_beyond_direct(
    project: Path, deps: list[Dependency]
) -> tuple[dict[tuple[str, str, str], bool | None], list[Unverifiable], dict, list[str], list[str]]:
    """Lockfile-resolved (ecosystem, name, version) triples that are not direct deps.

    Returns the attested triples with their dev-only markers, the unverifiable entries
    with reasons, the ledger (distinct lockfile triples, and how many were excluded as
    direct-covered), the lockfiles read, and notes.

    Exclusion is keyed on the full triple, never on the name: the direct sweep checks a
    direct dependency only at its own resolved version, so a nested copy of the same
    package pinned at another version by some other dependency is still this sweep's
    responsibility. A name-keyed exclusion silently dropped exactly that copy — a
    genuinely installed, possibly vulnerable version checked by neither sweep while the
    counts still balanced.
    """
    notes: list[str] = []
    gathered: list[LockedPackage] = []
    unverifiable: list[Unverifiable] = []
    lock_sources: list[str] = []
    for packages, unattested, source, note in (
        _npm_all_locked(project),
        _uv_all_locked(project),
        _go_indirect(project),
    ):
        gathered.extend(packages)
        unverifiable.extend(unattested)
        if source:
            lock_sources.append(source)
        if note:
            notes.append(note)
    direct_triples = {(d.ecosystem, d.name, d.version) for d in deps if d.version}
    # Counted from the lock readers' output, before any exclusion or bucketing, so a
    # triple dropped without landing in a named bucket breaks validation instead of
    # vanishing while the remaining counts reconcile among themselves.
    all_triples = {(e, n, v) for e, n, v, _ in gathered}
    all_triples.update((e["ecosystem"], e["name"], e["version"]) for e in unverifiable)
    merged: dict[tuple[str, str, str], bool | None] = {}
    for eco, name, version, dev in gathered:
        key = (eco, name, version)
        if key in direct_triples:
            continue
        # npm hoists one package into several paths, dev-only in one and runtime in
        # another; runtime wins, matching discover()'s rule for duplicate declarations.
        if key not in merged or dev is False:
            merged[key] = dev
    deduped = _dedup_unverifiable(unverifiable, direct_triples, set(merged))
    ledger = {
        "lockfile_entries": len(all_triples),
        "excluded_direct": len(all_triples & direct_triples),
    }
    return merged, deduped, ledger, lock_sources, notes


def _dedup_unverifiable(
    unverifiable: list[Unverifiable],
    direct_triples: set[tuple[str, str, str]],
    seen: set[tuple[str, str, str]],
) -> list[Unverifiable]:
    """Drop unverifiable entries that duplicate a direct triple or an attested triple."""
    out = []
    for entry in unverifiable:
        key = (entry["ecosystem"], entry["name"], entry["version"])
        if key in direct_triples or key in seen:
            continue
        seen.add(key)
        out.append(entry)
    return out


def _attest_go_modules(
    http: sources.Http,
    merged: dict[tuple[str, str, str], bool | None],
    unverifiable: list[Unverifiable],
) -> None:
    """Split Go entries by whether the module proxy resolves them.

    go.mod carries no integrity data for its indirect list, so existence must be
    measured per module; without this, a typo'd or private module path reads as
    assessed-clean the moment OSV has nothing recorded against it.
    """
    for eco, name, version in sorted(merged):
        if eco != "Go":
            continue
        try:
            sources.go_module_latest(http, name)
        except sources.NotFound:
            reason = "the Go module proxy has no such module"
        except sources.Unavailable:
            reason = "the Go module proxy did not answer, so existence is unestablished"
        else:
            continue
        del merged[(eco, name, version)]
        unverifiable.append({"ecosystem": eco, "name": name, "version": version, "reason": reason})


def sweep_transitive(
    http: sources.Http, project: Path, deps: list[Dependency]
) -> tuple[dict, list[str]]:
    """Check every attested lockfile package beyond the direct set for advisories.

    Advisories only: no other criterion is assessed at this depth, and the report says
    so. The existence rule still holds — an empty advisory answer may only read as clean
    for a package known to exist — so only attested entries are queried: npm entries
    with a registry integrity hash, uv.lock entries from a registry source, and Go
    modules the module proxy resolves. Everything else is reported as unverifiable with
    its reason, never as clean.

    Returns:
        The transitive accounting for the artifact, and notes for the report.
    """
    merged, unverifiable, ledger, lock_sources, notes = _locked_beyond_direct(project, deps)
    empty = {
        "examined": False,
        "reason": None,
        "sources": [],
        "total": 0,
        "checked": 0,
        "lockfile_entries": 0,
        "excluded_direct": 0,
        "unverifiable": [],
    }
    if not lock_sources:
        return {
            **empty,
            "reason": "no lockfile resolves the transitive tree (package-lock.json, "
            "uv.lock, or a go 1.17+ go.mod)",
            "flagged": [],
        }, notes
    _attest_go_modules(http, merged, unverifiable)
    triples = sorted(merged)
    accounted = {
        **empty,
        "examined": True,
        "sources": lock_sources,
        "total": len(triples) + len(unverifiable),
        **ledger,
        "unverifiable": sorted(unverifiable, key=lambda e: (e["ecosystem"], e["name"])),
    }
    if not triples:
        return {**accounted, "flagged": []}, notes
    try:
        ids_per_query = sources.osv_advisories(http, [(e, n, v) for e, n, v in triples])
    except sources.Unavailable as exc:
        notes.append(
            f"OSV was unreachable for the transitive sweep ({exc}); transitive advisory "
            f"coverage is zero."
        )
        return {**accounted, "reason": "OSV was unreachable", "flagged": []}, notes
    flagged = [
        {"ecosystem": e, "name": n, "version": v, "dev": merged[(e, n, v)], "advisories": ids}
        for (e, n, v), ids in zip(triples, ids_per_query, strict=True)
        if ids
    ]
    return {**accounted, "checked": len(triples), "flagged": flagged}, notes


def _cross_check_pip_audit(deps: list[Dependency], found: dict[str, list[str]]) -> str | None:
    """Compare OSV's PyPI verdicts against pip-audit, when pip-audit is installed.

    The versions checked are whatever the collector resolved — a lockfile's, a pin's, or
    the latest release. Calling them "pinned" claimed the project chose them when it may
    not have, so the note says "resolved" and the version-source caveats stay in force.
    """
    resolved = [d for d in deps if d.ecosystem == "PyPI" and d.version]
    if not resolved:
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        for dep in resolved:
            handle.write(f"{dep.name}=={dep.version}\n")
        path = Path(handle.name)
    try:
        flagged_by_tool = {normalize_pypi_name(n) for n in sources.pip_audit_vulnerable(path)}
    except sources.Unavailable as exc:
        return f"pip-audit is installed but did not produce a cross-check ({exc})."
    finally:
        path.unlink(missing_ok=True)
    osv_flagged = {d.name for d in resolved if found.get(d.key)}
    only_tool = sorted(flagged_by_tool - osv_flagged)
    only_osv = sorted(osv_flagged - flagged_by_tool)
    if not only_tool and not only_osv:
        return (
            f"pip-audit agreed with OSV on all {len(resolved)} Python dependencies at "
            f"their resolved versions."
        )
    parts = []
    if only_tool:
        parts.append(f"pip-audit alone flagged {', '.join(only_tool)}")
    if only_osv:
        parts.append(f"OSV alone flagged {', '.join(only_osv)}")
    return "Advisory databases disagree, which is itself worth knowing: " + "; ".join(parts) + "."


def _tooling_notes(deps: list[Dependency], found: dict[str, list[str]]) -> list[str]:
    tools = sources.detect_tools()
    present = sorted(name for name, ok in tools.items() if ok)
    absent = sorted(name for name, ok in tools.items() if not ok)
    notes = [
        f"Optional tooling detected: {', '.join(present) or 'none'}. "
        f"Not installed, so not used: {', '.join(absent) or 'none'}."
    ]
    if tools.get("pip-audit"):
        cross = _cross_check_pip_audit(deps, found)
        if cross:
            notes.append(cross)
    return notes


# Recognised but unread; each produces a note so the fallback to pins or
# latest-release is disclosed where the reader will see it.
UNREAD_LOCKFILES = ("yarn.lock", "pnpm-lock.yaml", "poetry.lock")


def _unread_lockfile_notes(project: Path) -> list[str]:
    return [
        f"{name} is present but not read: direct-dependency versions fall back to "
        f"manifest pins or the latest release, and its transitive tree was not examined."
        for name in UNREAD_LOCKFILES
        if (project / name).exists()
    ]


MANIFEST_NAMES = (
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pyproject.toml",
    "uv.lock",
    "go.mod",
)


def _git_commit(project: Path) -> str | None:
    """The scanned project's own HEAD commit, for reproducibility.

    Reads the target's git metadata, never a dependency's source. Returns None when the
    target is not a git checkout, which is the normal case for an extracted tarball.
    """
    git_dir = project / ".git"
    head = git_dir / "HEAD"
    if not head.exists():
        return None
    # The target's .git contents are untrusted input: a crafted HEAD can point outside
    # .git (`ref: ../../etc/passwd`) or hold bytes that are not UTF-8. Both degrade to
    # None rather than leaking file content into the report or aborting the run —
    # UnicodeDecodeError is a ValueError, which the original OSError guard missed.
    try:
        content = head.read_text(encoding="utf-8").strip()
        if content.startswith("ref: "):
            ref = (git_dir / content.removeprefix("ref: ")).resolve()
            if not ref.is_relative_to(git_dir.resolve()):
                return None
            content = ref.read_text(encoding="utf-8").strip() if ref.exists() else ""
        return content[:12] or None
    except (OSError, ValueError):
        return None


def scan_metadata(project: Path) -> dict:
    """What was examined, so a reader knows whose dependency tree this describes.

    A report that says "43 direct dependencies" without naming the subject is ambiguous
    between the reader's project and someone else's, and a reader who assumes wrongly acts
    on recommendations they have no authority over.
    """
    manifests = [name for name in MANIFEST_NAMES if (project / name).exists()]
    manifests += [p.name for p in sorted(project.glob("requirements*.txt"))]
    return {
        "subject": project.resolve().name,
        "path": str(project),
        "commit": _git_commit(project),
        "manifests": manifests,
        "scanned_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def _repo_sharing_note(deps: list[Dependency]) -> str | None:
    """Warn when repository-level findings will appear more times than they occur.

    Archived, maintenance activity, security policy and every Scorecard check describe the
    source repository, not the package. Monorepos publish many packages from one
    repository, so a single fact becomes several findings: six of axios's `@rollup/*`
    dependencies share github.com/rollup/plugins, and all six carried the same
    checked-in-binaries score.
    """
    repos = [d.repo for d in deps if d.repo]
    if not repos:
        return None
    distinct = len(set(repos))
    if distinct == len(repos):
        return None
    shared = sorted({r for r in repos if repos.count(r) > 1})
    return (
        f"Repository-level criteria (archived, maintenance activity, security policy, and "
        f"the Scorecard checks) describe the source repository rather than the package. "
        f"{len(repos)} dependencies resolve to {distinct} distinct repositories, so one "
        f"repository can appear as several findings. Shared: {', '.join(shared[:5])}"
        + (" ..." if len(shared) > 5 else "")
    )


def _version_notes(deps: list[Dependency]) -> list[str]:
    notes = []
    for source, wording in (
        (
            "latest-release",
            "are specified as a version range with no lockfile, so their advisories were "
            "matched against the current latest release rather than against what this "
            "project installs — commit a lockfile for an exact answer",
        ),
        (
            "unresolved",
            "had no resolvable version, so their advisory results are historical for the "
            "package rather than version-matched",
        ),
        (
            "go-mod-minimum",
            "come from go.mod, which records a minimum version; module-version selection "
            "may build something higher",
        ),
    ):
        named = sorted(d.name for d in deps if d.version_source == source)
        if named:
            notes.append(
                f"{len(named)} dependencies {wording}: {', '.join(named[:8])}"
                + (" ..." if len(named) > 8 else "")
            )
    return notes


def collect(project: Path, cache: Path, offline: bool) -> dict:
    """Collect every signal for every direct dependency and assemble the artifact."""
    deps, notes = discover(project)
    if not deps:
        hints = (" " + " ".join(notes)) if notes else ""
        raise SystemExit(
            f"error: no direct dependencies found under {project}. A run that assesses "
            f"nothing must not report that nothing is wrong.{hints}"
        )

    token = sources.gh_token()
    http = sources.Http(cache, offline=offline, auth_marker="gh" if token else "anon")
    if http.cache_owner_caveat:
        notes.append(http.cache_owner_caveat)
    if token is None:
        notes.append(
            "gh is not authenticated. GitHub allows 60 requests/hour unauthenticated "
            "against 5000 authenticated, so repository signals may be unassessable."
        )
    notes.extend(_unread_lockfile_notes(project))

    # The one choke point for registry identity: a dependency that resolves from
    # somewhere other than its public registry is never looked up by name — a
    # same-named public package's advisories, publishers, and deprecation belong to
    # code this project does not install. Every criterion is unassessable, with the
    # source as the reason, and the dependency stays in the report and its coverage.
    registry_deps = [d for d in deps if not d.non_registry_reason]
    for dep in deps:
        if dep.non_registry_reason:
            # One shared reason across all 13 criteria, with the per-dependency source
            # carried in the signal's value and in the Method note. Embedding the source
            # in the reason gave every dependency a unique string, which defeated the
            # report's grouping: 13 criteria x 7 workspace packages produced 91
            # near-identical bullets, scaling linearly with monorepo size.
            _fill(
                dep,
                CRITERIA,
                Signal.unassessable(NON_REGISTRY_REASON, dep.non_registry_reason),
            )

    resolve_from_registry(http, registry_deps)
    found = _advisory_map(http, registry_deps, notes)
    transitive, transitive_notes = sweep_transitive(http, project, deps)
    notes.extend(transitive_notes)
    resolve_repos(http, registry_deps)
    resolve_go_repos(http, registry_deps)

    for dep in registry_deps:
        dep.signals["advisories"] = _advisory_signal(dep, found)
        ENRICHERS[dep.ecosystem](http, dep, token)
        sources.polite_pause()

    notes.extend(_version_notes(registry_deps))
    sharing = _repo_sharing_note(deps)
    if sharing:
        notes.append(sharing)
    notes.extend(_tooling_notes(registry_deps, found))
    notes.append(_scope_note(transitive))
    notes.append(_cache_note(http))
    return to_json(deps, scan_metadata(project), notes, transitive)


def _scope_note(transitive: dict) -> str:
    """State what depth each claim in the report reaches.

    The umbrella-package caveat matters most when the transitive tree went unexamined:
    advisories attach to the package that ships the affected code, so a clean direct
    tree says little about what it pulls in.
    """
    unverifiable = len(transitive.get("unverifiable") or [])
    if transitive["examined"] and transitive["checked"] + unverifiable == transitive["total"]:
        if transitive["total"] == 0:
            return (
                f"The lockfile ({', '.join(transitive['sources'])}) resolves no packages "
                f"beyond the direct dependencies."
            )
        caveat = (
            f" {unverifiable} lockfile entries could not be verified against a public "
            f"registry and were not checked."
            if unverifiable
            else ""
        )
        return (
            f"Every criterion except advisories applies to direct dependencies only. The "
            f"{transitive['checked']} registry-verified packages resolved by "
            f"{', '.join(transitive['sources'])} were checked for known advisories at "
            f"their locked versions, and for nothing else." + caveat
        )
    reason = transitive["reason"] or "the transitive sweep did not complete"
    return (
        "Direct dependencies only. Advisories attach to the package that ships the "
        "affected code, so an umbrella package can look clean while its components are "
        "not — rails 5.0.0 reports 0 advisories where actionpack 5.0.0 reports 10. "
        f"Transitive dependencies were not examined: {reason}."
    )


def _cache_note(http: sources.Http) -> str:
    stats = http.stats
    oldest = http.oldest_hit_seconds / 3600
    note = (
        f"HTTP sources: {stats['fetched']} fetched, {stats['hits']} served from cache "
        f"(oldest {oldest:.1f}h old), {stats['stale']} refetched as stale, "
        f"{stats['offline_misses']} unavailable offline, {stats['errors']} errors."
    )
    if http.offline and http.oldest_hit_seconds > sources.CACHE_MAX_AGE_SECONDS:
        note += (
            " This offline run served entries past the freshness bound; "
            "repository-derived signals such as maintenance activity describe the state "
            "at fetch time, not today."
        )
    return note


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path, help="path to the project to audit")
    parser.add_argument("--json", type=Path, help="write the artifact here (default: stdout)")
    parser.add_argument(
        "--cache",
        type=Path,
        # Outside the working directory: the target of an audit is somebody else's
        # repository and this should not leave a directory in it.
        default=Path(tempfile.gettempdir()) / "supply-chain-risk-auditor-cache",
        help="HTTP cache directory (default: a stable path under the system temp dir)",
    )
    parser.add_argument("--offline", action="store_true", help="use only cached responses")
    args = parser.parse_args()

    if not args.project.is_dir():
        raise SystemExit(f"error: {args.project} is not a directory")

    try:
        artifact = collect(args.project, args.cache, args.offline)
    except ReconciliationError as exc:
        # A refusal, not a crash: say what is wrong rather than printing a traceback.
        raise SystemExit(f"error: this run cannot be reported: {exc}") from exc
    text = json.dumps(artifact, indent=2, sort_keys=True)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.json} ({artifact['coverage']['total_dependencies']} dependencies)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
