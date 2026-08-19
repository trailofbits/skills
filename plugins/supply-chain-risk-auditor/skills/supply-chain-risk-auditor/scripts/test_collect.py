"""Collector tests: manifest parsing, signal judgement, and the offline pipeline.

The end-to-end tests seed the HTTP cache through `Http`'s own writer and run with
`offline=True`, so they exercise the real cache and code paths with no network. The
negatives are the point: a package that 404s everywhere must produce no flag and no
clean verdict, and a run in which every source is down must refuse to report.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sources
from collect import (
    STALE_DAYS,
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
