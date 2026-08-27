"""Collector tests: manifest parsing, signal judgement, and the offline pipeline.

The end-to-end tests seed the HTTP cache through `Http`'s own writer and run with
`offline=True`, so they exercise the real cache and code paths with no network. The
negatives are the point: a package that 404s everywhere must produce no flag and no
clean verdict, and a run in which every source is down must refuse to report.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sources
from collect import (
    STALE_DAYS,
    _read_json,
    _advisory_signal,
    _concentration_signal,
    _exact_npm_pin,
    _go_indirect,
    _npm_all_locked,
    _npm_spec_kind,
    _pypi_version,
    _staleness_signal,
    _uv_all_locked,
    collect,
    discover,
    parse_go,
    parse_npm,
    parse_pypi,
    sweep_transitive,
)
from model import Dependency, ReconciliationError, State, _validate_transitive

# ---------------------------------------------------------------------- npm parsing


def test_ranges_are_not_pins():
    assert _exact_npm_pin("1.2.3") == "1.2.3"
    for spec in ("^1.2.3", "~1.2", "1.x", "1.2.x", "2", "*", ">=1.0.0"):
        assert _exact_npm_pin(spec) is None, spec


def test_non_registry_specs_classified():
    for spec in ("file:../local", "workspace:*", "git+https://x/y.git", "owner/repo"):
        assert _npm_spec_kind(spec) == "non-registry", spec
    assert _npm_spec_kind("npm:real@^2") == "alias"
    assert _npm_spec_kind("^1.0.0") == "registry"


def test_npm_alias_audits_the_target(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"my-alias": "npm:real-pkg@^2.0.0"}})
    )
    deps, notes = parse_npm(tmp_path)
    assert [d.name for d in deps] == ["real-pkg"]
    assert any("alias" in n for n in notes)


def test_peer_dependencies_noted_not_audited(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"a": "^1"}, "peerDependencies": {"react": "^18"}})
    )
    deps, notes = parse_npm(tmp_path)
    assert [d.name for d in deps] == ["a"]
    assert any("peerDependenc" in n for n in notes)


def test_duplicate_declaration_keeps_the_runtime_one(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"a": "^1"}, "devDependencies": {"a": "^1"}})
    )
    deps, _ = discover(tmp_path)
    assert len(deps) == 1 and deps[0].dev is False


REG = "https://registry.npmjs.org"


def registry_entry(name: str, version: str, **extra: object) -> dict:
    return {
        "version": version,
        "resolved": f"{REG}/{name}/-/{name}-{version}.tgz",
        "integrity": "sha512-fake",
        **extra,
    }


def test_npm_lockfile_closure_reads_nested_paths_and_dev(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/direct": registry_entry("direct", "1.0.0"),
                    "node_modules/leftover": registry_entry("leftover", "2.0.0", dev=True),
                    "node_modules/leftover/node_modules/inner": registry_entry(
                        "inner", "3.0.0", dev=True
                    ),
                    "node_modules/linked": {"version": "9.9.9", "link": True},
                }
            }
        )
    )
    packages, unverifiable, source, note = _npm_all_locked(tmp_path)
    assert source == "package-lock.json" and note is None
    assert ("npm", "inner", "3.0.0", True) in packages
    assert all(name != "linked" for _, name, _, _ in packages)
    assert unverifiable == []


def test_npm_lockfile_git_and_hashless_entries_are_unverifiable(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/good": registry_entry("good", "1.0.0"),
                    "node_modules/evil-git-dep": {
                        "version": "2.0.0",
                        "resolved": "git+ssh://git@github.com/acme/evil-git-dep.git#abc",
                    },
                    "node_modules/@acme/private": {
                        "version": "3.0.0",
                        "resolved": "https://npm.acme.internal/@acme/private/-/private-3.0.0.tgz",
                        "integrity": "sha512-x",
                    },
                }
            }
        )
    )
    packages, unverifiable, _, _ = _npm_all_locked(tmp_path)
    assert [n for _, n, _, _ in packages] == ["good"]
    names = {e["name"] for e in unverifiable}
    assert names == {"evil-git-dep", "@acme/private"}
    assert all("not the npm registry" in e["reason"] for e in unverifiable)


def test_v1_lockfile_yields_a_note_not_a_silent_zero(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"dependencies": {"a": {"version": "1.0.0"}}})
    )
    packages, unverifiable, source, note = _npm_all_locked(tmp_path)
    assert packages == [] and unverifiable == [] and source is None
    assert note and "transitive tree was not read" in note


# --------------------------------------------------------------------- PyPI parsing


def test_pep508_marker_does_not_fabricate_a_version():
    version, source = _pypi_version("psutil; sys_platform == 'win32'", {}, "psutil")
    assert version is None and source == "unresolved"


def test_pinned_version_extraction():
    assert _pypi_version("requests==2.19.0", {}, "requests") == ("2.19.0", "manifest-pin")
    assert _pypi_version("foo==1.0.*", {}, "foo") == (None, "unresolved")
    # pip-compile continuation and inline options end the version without corrupting it
    assert _pypi_version("requests==2.19.0 \\", {}, "requests") == ("2.19.0", "manifest-pin")
    assert _pypi_version("requests==2.19.0 --hash=sha256:abc", {}, "requests") == (
        "2.19.0",
        "manifest-pin",
    )
    # PEP 440 permits a `v` prefix and pip accepts it; requiring a leading digit made
    # this legal pin unresolved, so advisories matched the latest release and 62 real
    # ones for django v3.2.0 read as clean
    assert _pypi_version("django==v3.2.0", {}, "django") == ("3.2.0", "manifest-pin")
    # an epoch must survive: splitting on `!` (there for `!=`) truncated 1!2.0 to 1
    assert _pypi_version("x==1!2.0+local", {}, "x") == ("1!2.0+local", "manifest-pin")
    # anything the gate cannot recognise stays unresolved rather than reaching OSV
    assert _pypi_version("x==1.2.3[extra]", {}, "x") == (None, "unresolved")


def test_requirements_filename_hints_dev(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
    # sorts before requirements.txt; a package in both must stay runtime at the
    # runtime pin, not collapse to the first-seen dev entry
    (tmp_path / "requirements-dev.txt").write_text("pytest==8.0.0\nflask==1.0.2\n")
    # PEP 508 direct reference: the fork URL is the identity, not the public name
    (tmp_path / "requirements.txt").write_text(
        "flask==2.0.0\ninternal-lib @ git+ssh://git@github.com/acme/internal-lib.git\n"
    )
    deps, _ = parse_pypi(tmp_path)
    by_name = {d.name: d for d in deps}
    assert by_name["flask"].dev is False and by_name["flask"].version == "2.0.0"
    assert by_name["pytest"].dev is True
    assert by_name["internal-lib"].non_registry_reason
    assert "git+ssh://" in by_name["internal-lib"].non_registry_reason


def test_uv_lock_closure_skips_the_project_itself(tmp_path: Path):
    (tmp_path / "uv.lock").write_text(
        "\n".join(
            [
                "[[package]]",
                'name = "demo"',
                'version = "0.1.0"',
                'source = { editable = "." }',
                "",
                "[[package]]",
                'name = "Left_Pad"',
                'version = "1.0.0"',
                'source = { registry = "https://pypi.org/simple" }',
            ]
        )
    )
    packages, unverifiable, source, note = _uv_all_locked(tmp_path)
    assert source == "uv.lock" and note is None
    assert packages == [("PyPI", "left-pad", "1.0.0", None)]
    assert unverifiable == []


def test_uv_lock_non_registry_sources_are_unverifiable(tmp_path: Path):
    (tmp_path / "uv.lock").write_text(
        "\n".join(
            [
                "[[package]]",
                'name = "internal-lib"',
                'version = "3.0.0"',
                'source = { git = "ssh://git@github.com/acme/internal-lib" }',
                "",
                "[[package]]",
                'name = "vendored-flask"',
                'version = "1.0.2"',
                'source = { directory = "../vendor/flask" }',
                "",
                "[[package]]",
                'name = "real"',
                'version = "2.0.0"',
                'source = { registry = "https://pypi.org/simple" }',
            ]
        )
    )
    packages, unverifiable, _, _ = _uv_all_locked(tmp_path)
    assert [n for _, n, _, _ in packages] == ["real"]
    reasons = {e["name"]: e["reason"] for e in unverifiable}
    assert "git source" in reasons["internal-lib"]
    assert "directory source" in reasons["vendored-flask"]
    # a DIRECT dependency with a non-registry lock source carries the marker, so the
    # pipeline never looks it up on PyPI by name
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0"\ndependencies = ["internal-lib", "real"]\n'
    )
    deps, _ = parse_pypi(tmp_path)
    by_name = {d.name: d for d in deps}
    assert by_name["internal-lib"].non_registry_reason
    assert "git source" in by_name["internal-lib"].non_registry_reason
    assert by_name["real"].non_registry_reason is None


# ----------------------------------------------------------------------- Go parsing

GOMOD = """\
module example.com/demo

go 1.21

require (
\tgithub.com/direct/one v1.2.3
\tgolang.org/x/text v0.9.0 // indirect
)

replace (
\tgithub.com/direct/one => github.com/fork/one v9.9.9
)

exclude github.com/bad/mod v0.0.1
"""


def test_gomod_blocks_and_dev_tristate(tmp_path: Path):
    (tmp_path / "go.mod").write_text(GOMOD)
    deps, notes = parse_go(tmp_path)
    assert [(d.name, d.version) for d in deps] == [("github.com/direct/one", "1.2.3")]
    # go.mod declares no runtime/dev split; asserting one would invent a distinction.
    assert deps[0].dev is None
    assert any("replace/exclude" in n for n in notes)


def test_go_indirect_modules_are_the_transitive_set(tmp_path: Path):
    (tmp_path / "go.mod").write_text(GOMOD)
    packages, unverifiable, source, note = _go_indirect(tmp_path)
    assert source == "go.mod" and note is None
    assert packages == [("Go", "golang.org/x/text", "0.9.0", None)]
    assert unverifiable == []


def test_pre_117_gomod_is_not_a_closure(tmp_path: Path):
    (tmp_path / "go.mod").write_text(GOMOD.replace("go 1.21", "go 1.16"))
    packages, unverifiable, source, note = _go_indirect(tmp_path)
    assert packages == [] and unverifiable == [] and source is None
    assert note and "1.17" in note


# ------------------------------------------------------------------ signal judgement


def test_empty_advisory_answer_needs_proof_of_existence():
    dep = Dependency(ecosystem="npm", name="ghost", version="1.0.0", exists=None)
    signal = _advisory_signal(dep, {dep.key: []})
    assert signal.state is State.UNASSESSABLE
    dep.exists = True
    assert _advisory_signal(dep, {dep.key: []}).state is State.CLEAN


def test_advisory_wording_matches_version_source():
    dep = Dependency(
        ecosystem="Go",
        name="example.com/m",
        version="1.0.0",
        version_source="go-mod-minimum",
        exists=True,
    )
    signal = _advisory_signal(dep, {dep.key: ["GO-2026-1"]})
    assert signal.state is State.FLAGGED and "minimum" in signal.detail


def test_staleness_threshold():
    old = (datetime.now(UTC) - timedelta(days=STALE_DAYS + 30)).isoformat()
    fresh = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    assert _staleness_signal(old).state is State.FLAGGED
    # 400 days is a finished library, not an abandoned one; flagging it buried the
    # decade-abandoned packages this criterion exists for.
    assert _staleness_signal(fresh).state is State.CLEAN
    assert _staleness_signal(None).state is State.UNASSESSABLE
    assert _staleness_signal("2020-01-01T00:00:00").state is State.UNASSESSABLE


def test_concentration_judgement():
    base = {
        "provenance": False,
        "maintainers": [],
        "human_maintainers": [],
        "automated_maintainers": [],
    }
    assert _concentration_signal({**base, "provenance": True}).state is State.UNASSESSABLE
    assert _concentration_signal(base).state is State.UNASSESSABLE
    lone = {
        **base,
        "maintainers": ["alice", "release-bot"],
        "human_maintainers": ["alice"],
        "automated_maintainers": ["release-bot"],
    }
    signal = _concentration_signal(lone)
    assert signal.state is State.FLAGGED and "release-bot" in signal.detail
    two = {**base, "maintainers": ["alice", "bob"], "human_maintainers": ["alice", "bob"]}
    assert _concentration_signal(two).state is State.CLEAN


# ------------------------------------------------------------------- offline seeding


def seeded_http(cache_dir: Path, responses: dict[tuple[str, str, str], object]) -> sources.Http:
    """Write canned responses through Http's own cache writer, then serve offline."""
    http = sources.Http(cache_dir, offline=True)
    for (method, url, body), payload in responses.items():
        path = http._path(method, url, body)
        if payload is None:
            http._write_cache(path, {}, 404)
        else:
            http._write_cache(path, payload, 200)
    return http


def osv_body(triples: list[tuple[str, str, str | None]]) -> str:
    queries = []
    for eco, name, version in triples:
        query: dict = {"package": {"name": name, "ecosystem": eco}}
        if version:
            query["version"] = version
        queries.append(query)
    return json.dumps({"queries": queries}, sort_keys=True)


OSV = "https://api.osv.dev/v1/querybatch"


# ------------------------------------------------------------------ transitive sweep


def test_sweep_without_lockfile_is_not_examined(tmp_path: Path):
    http = seeded_http(tmp_path / "cache", {})
    transitive, _ = sweep_transitive(http, tmp_path, [])
    assert transitive["examined"] is False and "lockfile" in transitive["reason"]


def test_sweep_excludes_direct_merges_dev_and_flags(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/direct": registry_entry("direct", "1.0.0"),
                    "node_modules/leftover": registry_entry("leftover", "2.0.0", dev=True),
                    "node_modules/leftover/node_modules/inner": registry_entry(
                        "inner", "3.0.0", dev=True
                    ),
                    "node_modules/other/node_modules/inner": registry_entry("inner", "3.0.0"),
                    # a nested copy of the direct dep at an OLDER version: covered by
                    # neither the direct sweep (which checks 1.0.0) nor a name-keyed
                    # exclusion — it must reach this sweep
                    "node_modules/other/node_modules/direct": registry_entry("direct", "0.9.0"),
                }
            }
        )
    )
    triples = [
        ("npm", "direct", "0.9.0"),
        ("npm", "inner", "3.0.0"),
        ("npm", "leftover", "2.0.0"),
    ]
    http = seeded_http(
        tmp_path / "cache",
        {("POST", OSV, osv_body(triples)): {"results": [{}, {"vulns": [{"id": "GHSA-1"}]}, {}]}},
    )
    direct = [Dependency(ecosystem="npm", name="direct", version="1.0.0")]
    transitive, _ = sweep_transitive(http, tmp_path, direct)
    # total==3 only holds if the nested direct@0.9.0 was queried: the seeded cache
    # answers only the exact three-triple OSV payload built above
    assert transitive["total"] == transitive["checked"] == 3
    assert transitive["lockfile_entries"] == 4 and transitive["excluded_direct"] == 1
    assert transitive["unverifiable"] == []
    # inner appears on a dev-only path and a runtime path; runtime wins.
    assert transitive["flagged"] == [
        {
            "ecosystem": "npm",
            "name": "inner",
            "version": "3.0.0",
            "dev": False,
            "advisories": ["GHSA-1"],
        }
    ]


def test_sweep_osv_unreachable_reports_zero_coverage(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/a": registry_entry("a", "1.0.0")}})
    )
    http = seeded_http(tmp_path / "cache", {})
    transitive, notes = sweep_transitive(http, tmp_path, [])
    assert transitive["examined"] and transitive["checked"] == 0 and transitive["total"] == 1
    assert any("transitive advisory coverage is zero" in n for n in notes)


def test_ledger_is_sourced_independently_of_the_buckets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A drop between reading the lockfile and bucketing must be refused.

    The ledger only detects that if `lockfile_entries` is counted from the lock readers'
    output rather than from the buckets themselves. Deriving it from the buckets makes
    the equation true by construction — the artifact reconciles while a package is
    missing from the sweep — so the drop is injected at a real seam here rather than
    hand-doctoring a dict, which is what the validator-level test already covers.
    """
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/attested": registry_entry("attested", "1.0.0"),
                    "node_modules/vendored": {
                        "version": "2.0.0",
                        "resolved": "git+ssh://git@github.com/acme/vendored.git#abc",
                    },
                }
            }
        )
    )
    triples = [("npm", "attested", "1.0.0")]
    http = seeded_http(tmp_path / "cache", {("POST", OSV, osv_body(triples)): {"results": [{}]}})
    transitive, _ = sweep_transitive(http, tmp_path, [])
    assert transitive["lockfile_entries"] == 2
    assert transitive["checked"] == 1 and len(transitive["unverifiable"]) == 1

    # Drop the unverifiable bucket on the way out of the gatherer.
    monkeypatch.setattr("collect._dedup_unverifiable", lambda *args: [])
    dropped, _ = sweep_transitive(http, tmp_path, [])
    assert dropped["lockfile_entries"] == 2, "the ledger must not follow the buckets down"
    with pytest.raises(ReconciliationError, match="vanished"):
        _validate_transitive({"transitive": dropped})


PROXY = "https://proxy.golang.org"


def test_go_existence_is_measured_not_asserted(tmp_path: Path):
    """The skill's worst prior bug: a comment claimed a proxy check no code performed,
    so nonexistent Go modules read as assessed-clean the moment OSV had nothing."""
    from collect import resolve_from_registry

    real = Dependency(ecosystem="Go", name="github.com/real/mod", version="1.0.0")
    ghost = Dependency(ecosystem="Go", name="github.com/none/xyzzy", version="9.9.9")
    http = seeded_http(
        tmp_path / "cache",
        {
            ("GET", f"{PROXY}/github.com/real/mod/@latest", ""): {"Version": "v1.0.0"},
            ("GET", f"{PROXY}/github.com/none/xyzzy/@latest", ""): None,
        },
    )
    resolve_from_registry(http, [real, ghost])
    assert real.exists is True and ghost.exists is False
    assert _advisory_signal(real, {real.key: []}).state is State.CLEAN
    # the empty answer for the nonexistent module must never read as clean
    assert _advisory_signal(ghost, {ghost.key: []}).state is State.UNASSESSABLE


def test_sweep_go_modules_need_proxy_attestation(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        "module example.com/demo\n\ngo 1.21\n\nrequire (\n"
        "\tgithub.com/real/mod v1.2.3 // indirect\n"
        "\tgithub.com/none/xyzzy v9.9.9 // indirect\n)\n"
    )
    triples = [("Go", "github.com/real/mod", "1.2.3")]
    http = seeded_http(
        tmp_path / "cache",
        {
            ("GET", f"{PROXY}/github.com/real/mod/@latest", ""): {"Version": "v1.2.3"},
            ("GET", f"{PROXY}/github.com/none/xyzzy/@latest", ""): None,
            ("POST", OSV, osv_body(triples)): {"results": [{}]},
        },
    )
    transitive, _ = sweep_transitive(http, tmp_path, [])
    assert transitive["total"] == 2 and transitive["checked"] == 1
    assert transitive["unverifiable"][0]["name"] == "github.com/none/xyzzy"
    assert "no such module" in transitive["unverifiable"][0]["reason"]


# --------------------------------------------------------------- offline end-to-end


def seed_full_project(tmp_path: Path) -> Path:
    """One healthy dependency and one that 404s everywhere."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"tiny-dep": "1.2.3", "ghost-dep": "9.9.9"}})
    )
    pushed = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    gh = "https://api.github.com/repos"
    responses = {
        ("GET", "https://registry.npmjs.org/tiny-dep", ""): {
            "dist-tags": {"latest": "1.2.3"},
            "versions": {"1.2.3": {"dist": {}}},
            "maintainers": [{"name": "alice"}, {"name": "bob"}],
            "repository": {"url": "git+https://github.com/acme/tiny-dep.git"},
        },
        ("GET", "https://registry.npmjs.org/ghost-dep", ""): None,
        ("GET", "https://api.npmjs.org/downloads/point/last-week/tiny-dep", ""): {
            "downloads": 5000
        },
        ("GET", "https://api.npmjs.org/downloads/point/last-week/ghost-dep", ""): None,
        (
            "GET",
            "https://api.deps.dev/v3alpha/systems/npm/packages/ghost-dep/versions/9.9.9",
            "",
        ): None,
        ("GET", f"{gh}/acme/tiny-dep", ""): {"pushed_at": pushed, "archived": False},
        ("GET", f"{gh}/acme/tiny-dep/contents/SECURITY.md", ""): {},
        ("GET", "https://api.scorecard.dev/projects/github.com/acme/tiny-dep", ""): {
            "checks": [
                {"name": "Dangerous-Workflow", "score": 10},
                {"name": "Binary-Artifacts", "score": 10},
                {"name": "Token-Permissions", "score": 9},
                {"name": "Code-Review", "score": 7},
            ]
        },
        (
            "POST",
            OSV,
            osv_body([("npm", "tiny-dep", "1.2.3"), ("npm", "ghost-dep", "9.9.9")]),
        ): {"results": [{}, {}]},
    }
    seeded_http(tmp_path / "cache", responses)
    return project


def test_offline_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sources, "gh_token", lambda: None)
    project = seed_full_project(tmp_path)
    artifact = collect(project, tmp_path / "cache", offline=True)

    by_name = {d["name"]: d for d in artifact["dependencies"]}
    tiny, ghost = by_name["tiny-dep"], by_name["ghost-dep"]

    # The healthy dependency is assessed clean with data behind every verdict.
    assert tiny["signals"]["advisories"]["state"] == State.CLEAN.value
    assert tiny["signals"]["staleness"]["state"] == State.CLEAN.value
    assert tiny["signals"]["publisher_concentration"]["state"] == State.CLEAN.value
    assert tiny["signals"]["downloads"]["value"] == 5000

    # The package that 404s everywhere yields zero flags and no clean advisory verdict:
    # an empty answer about an unpublished package is not evidence of safety.
    assert ghost["flagged"] == []
    assert ghost["signals"]["advisories"]["state"] == State.UNASSESSABLE.value
    assert not any(s["state"] == State.CLEAN.value for s in ghost["signals"].values())

    assert artifact["transitive"]["examined"] is False


def test_every_source_unavailable_refuses_to_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(sources, "gh_token", lambda: None)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0.0"}}))
    with pytest.raises(ReconciliationError, match="measured nothing"):
        collect(project, tmp_path / "empty-cache", offline=True)


def test_zero_dependencies_exits_nonzero(tmp_path: Path):
    project = tmp_path / "empty"
    project.mkdir()
    with pytest.raises(SystemExit, match="no direct dependencies"):
        collect(project, tmp_path / "cache", offline=True)


def test_non_registry_direct_dep_is_never_queried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A workspace/file/git direct dependency must never be looked up by bare name:
    a same-named public package's advisories and publishers would be attributed to
    code the project never installs."""
    monkeypatch.setattr(sources, "gh_token", lambda: None)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"utils": "workspace:*", "tiny-dep": "1.2.3"}})
    )
    pushed = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    gh = "https://api.github.com/repos"
    seeded_http(
        tmp_path / "cache",
        {
            # only tiny-dep is seeded; a lookup of "utils" would be an offline miss,
            # which reads as unassessable-source-down rather than proving the choke —
            # so the assertions below also require the non-registry *reason*
            ("GET", "https://registry.npmjs.org/tiny-dep", ""): {
                "dist-tags": {"latest": "1.2.3"},
                "versions": {"1.2.3": {"dist": {}}},
                "maintainers": [{"name": "alice"}, {"name": "bob"}],
                "repository": {"url": "git+https://github.com/acme/tiny-dep.git"},
            },
            ("GET", "https://api.npmjs.org/downloads/point/last-week/tiny-dep", ""): {
                "downloads": 5000
            },
            ("GET", f"{gh}/acme/tiny-dep", ""): {"pushed_at": pushed, "archived": False},
            ("GET", f"{gh}/acme/tiny-dep/contents/SECURITY.md", ""): {},
            ("GET", "https://api.scorecard.dev/projects/github.com/acme/tiny-dep", ""): {
                "checks": [{"name": "Dangerous-Workflow", "score": 10}]
            },
            ("POST", OSV, osv_body([("npm", "tiny-dep", "1.2.3")])): {"results": [{}]},
        },
    )
    artifact = collect(project, tmp_path / "cache", offline=True)
    utils = next(d for d in artifact["dependencies"] if d["name"] == "utils")
    assert utils["non_registry_reason"] and "not the npm registry" in utils["non_registry_reason"]
    assert utils["flagged"] == []
    for signal in utils["signals"].values():
        assert signal["state"] == State.UNASSESSABLE.value
        # one shared reason so the report can group these, with the specific source
        # carried alongside it
        assert "resolves from outside its public registry" in signal["detail"]
        assert "not the npm registry" in signal["value"]


# ---------------------------------------------------------------- text encoding


def test_non_ascii_manifest_is_read_as_utf8(tmp_path: Path):
    """A manifest with non-ASCII text must survive the read intact (issue #273).

    On Windows `read_text()` with no `encoding=` decodes with the ANSI code page, so an
    accented author name either raises UnicodeDecodeError or, where the bytes happen to
    be cp1252-decodable, is silently mojibaked into the report.
    """
    manifest = tmp_path / "package.json"
    manifest.write_bytes(
        json.dumps({"name": "p", "author": "José Álvarez", "dependencies": {}}).encode("utf-8")
    )

    assert _read_json(manifest)["author"] == "José Álvarez"


def test_utf16_requirements_is_refused_not_a_traceback(tmp_path: Path):
    """PowerShell 5.1 redirection writes UTF-16LE, so this is a stock Windows file.

    A requirements file generated with `>` there begins with a BOM whose first two
    bytes are invalid UTF-8. main() catches only ReconciliationError, so before this
    the run died with a raw UnicodeDecodeError — on the platform the fix supports.
    """
    # encode("utf-16"), not "utf-16-le": the BOM is what makes it invalid UTF-8.
    # Without it, UTF-16LE ASCII decodes as UTF-8 with embedded nulls and no error —
    # silent corruption rather than a crash, which is its own problem.
    (tmp_path / "requirements.txt").write_bytes("flask==2.0.0\n".encode("utf-16"))

    with pytest.raises(SystemExit, match="not UTF-8"):
        parse_pypi(tmp_path)


def test_utf16_gomod_is_refused_not_a_traceback(tmp_path: Path):
    """Same defect, same fix, the other plain-text reader."""
    (tmp_path / "go.mod").write_bytes("module x\n\ngo 1.21\n".encode("utf-16"))

    with pytest.raises(SystemExit, match="not UTF-8"):
        parse_go(tmp_path)


def test_utf16_gomod_is_refused_by_the_indirect_reader_too(tmp_path: Path):
    """go.mod is read in two places and `parse_go` short-circuits before the second.

    `_go_indirect` has its own read, so reverting only that one left every test green.
    The static encoding check cannot see it either: the omission there is the guard, not
    the encoding, so this needs its own case.
    """
    (tmp_path / "go.mod").write_bytes("module x\n\ngo 1.21\n".encode("utf-16"))

    with pytest.raises(SystemExit, match="not UTF-8"):
        _go_indirect(tmp_path)


def test_non_utf8_manifest_is_refused_not_a_traceback(tmp_path: Path):
    """JSON is UTF-8 by RFC 8259, so an undecodable manifest is malformed input.

    UnicodeDecodeError is a ValueError but not a JSONDecodeError, so before this it
    escaped both `except` clauses and surfaced as a traceback.
    """
    manifest = tmp_path / "package.json"
    manifest.write_bytes(b'{"author": "Jos\xe9"}')  # latin-1, invalid UTF-8

    with pytest.raises(SystemExit, match="is not UTF-8"):
        _read_json(manifest)


TEXT_IO_ATTRS = ("read_text", "write_text")


def _is_binary_call(node: ast.Call) -> bool:
    """True when the call names a binary mode, where an encoding is meaningless."""
    modes = [a for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
    modes += [
        kw.value for kw in node.keywords if kw.arg == "mode" and isinstance(kw.value, ast.Constant)
    ]
    return any("b" in m.value for m in modes if isinstance(getattr(m, "value", None), str))


def _text_io_without_encoding(source: str) -> list[str]:
    """Call sites that decode or encode text without naming the encoding.

    Parsed rather than grepped. The previous line-based version tried to handle a
    multi-line `subprocess.run(..., text=True, encoding=...)` by looking for both on one
    line, could not, and shunted those hits into a list nothing asserted on — so
    deleting an `encoding=` from either subprocess call passed. An AST sees the whole
    call however it is wrapped.

    Only the builtin `open` is flagged, not `x.open(...)`: `self.opener.open(request)` is
    a urllib call returning bytes, and an encoding there would be nonsense. A
    `Path.open()` in text mode would therefore slip past this check, which is one of the
    reasons the behavioural test below exists alongside it.

    Args:
        source: Python source text.

    Returns:
        One `line: description` string per offending call.
    """
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        kwargs = {kw.arg for kw in node.keywords}
        if "encoding" in kwargs or _is_binary_call(node):
            continue

        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in TEXT_IO_ATTRS:
            out.append(f"{node.lineno}: {func.attr}() with no encoding=")
        elif isinstance(func, ast.Name) and func.id == "open":
            out.append(f"{node.lineno}: open() with no encoding=")
        # A text-mode subprocess decodes the child's output with the locale encoding,
        # so it is the same defect wearing different clothes.
        elif "text" in kwargs or "universal_newlines" in kwargs:
            name = getattr(func, "attr", None) or getattr(func, "id", "call")
            out.append(f"{node.lineno}: {name}(text=True) with no encoding=")
    return out


def test_every_text_io_call_names_its_encoding():
    """No text I/O anywhere in the package may fall back to the platform default.

    The static half of the pair below, covering sites the behavioural driver does not
    execute — `render.py`'s artifact read and report write, and `pip_audit_vulnerable`'s
    subprocess, which needs pip-audit installed to run at all.

    Modules are globbed rather than listed, so a new one added to `scripts/` is covered
    the day it lands. Tests are excluded: their fixtures write ASCII through
    `write_text` by the dozen and are not what ships to a user.
    """
    package = Path(__file__).parent
    modules = sorted(p for p in package.glob("*.py") if not p.name.startswith("test_"))
    assert len(modules) >= 4, f"module discovery found only {[p.name for p in modules]}"

    offenders = [
        f"{path.name}:{hit}"
        for path in modules
        for hit in _text_io_without_encoding(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, "text I/O without an explicit encoding:\n" + "\n".join(offenders)


def test_the_encoding_check_detects_a_missing_encoding():
    """The checker above must fail on the code it exists to reject.

    Its predecessor passed while a real regression was present, so the guard is itself
    guarded: both shapes it must catch are asserted here, including the multi-line
    subprocess form that defeated the line-based version.
    """
    assert _text_io_without_encoding("p.read_text()")
    assert _text_io_without_encoding("open(p)")
    assert _text_io_without_encoding("p.write_text(x)")
    assert _text_io_without_encoding(
        "subprocess.run(\n    ['gh'],\n    capture_output=True,\n    text=True,\n)"
    )
    # ...and must not fire on the fixed forms.
    assert not _text_io_without_encoding('p.read_text(encoding="utf-8")')
    assert not _text_io_without_encoding(
        'subprocess.run(\n    ["gh"],\n    text=True,\n    encoding="utf-8",\n)'
    )
    assert not _text_io_without_encoding("p.read_bytes()")
    assert not _text_io_without_encoding('open(p, "rb")')
    # urllib: bytes, so an encoding would be nonsense
    assert not _text_io_without_encoding("self.opener.open(request, timeout=5)")


def test_no_text_io_relies_on_the_platform_default_encoding():
    """The behavioural half: run the real code paths and let CPython catch omissions.

    Under `-X warn_default_encoding` an omitted `encoding=` raises EncodingWarning
    (PEP 597), which is exactly the Windows defect in issue #273 — the platform default
    is cp1252 there, not UTF-8. This drives `collect.py` and `sources.py` for real, so
    it catches an omission the static check above could miss (a call built dynamically,
    or one in a stdlib helper the package hands a file to). `render.py`'s two sites are
    not on this path and are covered statically instead.
    """
    # Drives the readers and writers directly rather than `collect()`, which refuses an
    # offline run against an empty cache ("this run measured nothing") before it reaches
    # the render path. Every text I/O site in the package is on one of these calls.
    driver = textwrap.dedent(
        """
        import sys, warnings
        from pathlib import Path
        warnings.simplefilter("error", EncodingWarning)

        project = Path(sys.argv[1])

        import collect, render, sources

        collect.discover(project)                    # manifest, requirements and go.mod readers
        collect.scan_metadata(project)               # .git/HEAD and its ref
        collect._read_toml(project / "pyproject.toml")

        http = sources.Http(project / ".cache", offline=True)
        path = http._path("GET", "https://example.com/x")
        http._write_cache(path, {"name": "José"}, 200)   # cache write
        http.get_json("https://example.com/x")          # cache read

        sources.gh_token()                           # subprocess(text=True), if gh exists
        print("ok")
        """
    )
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp) / "project"
        project.mkdir()
        # Non-ASCII on purpose: the bytes must survive every layer.
        (project / "package.json").write_text(
            json.dumps({"name": "p", "author": "José", "dependencies": {"left-pad": "1.3.0"}}),
            encoding="utf-8",
        )
        (project / "requirements.txt").write_text("flask==2.0.0  # José\n", encoding="utf-8")
        (project / "go.mod").write_text("module x\n\ngo 1.21\n", encoding="utf-8")
        (project / "pyproject.toml").write_text('[project]\nname = "José"\n', encoding="utf-8")
        (project / ".git").mkdir()
        (project / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        script = Path(tmp) / "driver.py"
        script.write_text(driver, encoding="utf-8")

        scripts_dir = Path(__file__).parent
        env = {**os.environ, "PYTHONPATH": str(scripts_dir)}
        result = subprocess.run(
            [
                sys.executable,
                "-X",
                "warn_default_encoding",
                str(script),
                str(project),
            ],
            capture_output=True,
            text=True,
            cwd=scripts_dir,
            env=env,
        )

    assert "EncodingWarning" not in result.stderr, (
        f"a text I/O call omitted encoding=:\n{result.stderr}"
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout
