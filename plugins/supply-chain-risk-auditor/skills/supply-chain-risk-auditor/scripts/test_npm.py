"""npm metadata regressions using full registry documents and offline collection."""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from urllib.parse import quote

import pytest
import sources
from collect import collect
from model import State
from render import render

REGISTRY = "https://registry.npmjs.org"


def version_doc(version: str, **properties: object) -> dict:
    """Minimal full version manifest; hasInstallScript is not a full-format field."""
    return {"name": "fixture", "version": version, "dist": {}, **properties}


@pytest.fixture
def packument() -> dict:
    return {
        "name": "fixture",
        "dist-tags": {"latest": "2.0.0"},
        "versions": {
            "1.0.0": version_doc(
                "1.0.0",
                deprecated="use a supported release",
                scripts={"postinstall": "node install.js"},
                maintainers=[{"name": "historical-publisher"}],
            ),
            "2.0.0": version_doc(
                "2.0.0",
                scripts={"test": "node test.js"},
                dist={"attestations": {"url": "https://example.com/attestations"}},
            ),
        },
        "maintainers": [{"name": "alice"}, {"name": "bob"}],
        "repository": "git+https://github.com/current/fixture.git",
        "deprecated": "a root message must not override a clean selected release",
    }


def seed(http: sources.Http, method: str, url: str, body: dict, payload: dict | None = None):
    key = json.dumps(payload, sort_keys=True) if payload else ""
    http._write_cache(http._path(method, url, key), body, 200)


def metadata_http(tmp_path: Path, doc: dict, name: str = "fixture") -> sources.Http:
    http = sources.Http(tmp_path / "cache", offline=True)
    encoded = quote(name, safe="@")
    seed(http, "GET", f"{REGISTRY}/{encoded}", doc)
    return http


@pytest.mark.parametrize(
    ("deprecated", "install", "provenance"), list(itertools.product((False, True), repeat=3))
)
def test_release_properties_are_independent_and_version_matched(
    tmp_path: Path, packument: dict, deprecated: bool, install: bool, provenance: bool
):
    for version, inverse in (("1.0.0", False), ("2.0.0", True)):
        packument["versions"][version] = version_doc(
            version,
            deprecated="retired" if deprecated != inverse else "",
            scripts={"install": "node install.js"} if install != inverse else {},
            dist={"attestations": {"url": "https://example.com/provenance"}}
            if provenance != inverse
            else {},
        )
    meta = sources.npm_metadata(metadata_http(tmp_path, packument), "fixture", "1.0.0")
    release = meta["release"]
    assert release["version"] == "1.0.0"
    assert release["deprecated"] == ("retired" if deprecated else "")
    assert release["install_hooks"] == (["install"] if install else [])
    assert release["provenance"] is provenance
    assert meta["publisher_provenance"] is not provenance
    assert meta["maintainers"] == ["alice", "bob"]


@pytest.mark.parametrize("hook", ["preinstall", "install", "postinstall"])
def test_full_metadata_install_hooks(tmp_path: Path, packument: dict, hook: str):
    packument["versions"]["1.0.0"]["scripts"] = {hook: "node hook.js"}
    release = sources.npm_metadata(metadata_http(tmp_path, packument), "fixture", "1.0.0")[
        "release"
    ]
    assert release["install_hooks"] == [hook]


@pytest.mark.parametrize(
    "scripts",
    [{}, {"test": "node test.js", "build": "node build.js", "prepare": "node prepare.js"}],
)
def test_other_scripts_are_not_registry_install_hooks(
    tmp_path: Path, packument: dict, scripts: dict
):
    packument["versions"]["1.0.0"]["scripts"] = scripts
    release = sources.npm_metadata(metadata_http(tmp_path, packument), "fixture", "1.0.0")[
        "release"
    ]
    assert release["install_hooks"] == []


@pytest.mark.parametrize(
    ("selected", "canonical"),
    [
        ("1.0.0+build.7", "1.0.0"),
        ("1.0.0-rc.1+build.7", "1.0.0-rc.1"),
        ("v1.0.0", "1.0.0"),
        ("= v1.0.0", "1.0.0"),
        ("01.0.0", "1.0.0"),
        ("1.0.0-01", "1.0.0-1"),
        ("1.0.0alpha.01", "1.0.0-alpha.1"),
        ("\ufeff1.0.0", "1.0.0"),
        ("1.0.0\ufeff", "1.0.0"),
    ],
)
def test_npm_exact_version_is_canonical_for_release_lookup(
    tmp_path: Path, packument: dict, selected: str, canonical: str
):
    packument["versions"][canonical] = version_doc(canonical, deprecated="selected release")
    meta = sources.npm_metadata(metadata_http(tmp_path, packument), "fixture", selected)
    assert meta["release"]["version"] == canonical
    assert meta["release"]["deprecated"] == "selected release"


@pytest.mark.parametrize(
    "spec", ["\u00851.0.0", "1.0.0\u001c", "1.0.0+bad+build", "9007199254740992.0.0"]
)
def test_non_npm_exact_forms_are_not_canonicalized(spec: str):
    assert sources.npm_exact_version(spec) is None


@pytest.mark.parametrize("tags", [{}, {"next": "1.0.0"}, {"latest": "9.9.9"}])
def test_selected_release_and_package_data_survive_unusable_latest(
    tmp_path: Path, packument: dict, tags: dict
):
    packument["dist-tags"] = tags
    meta = sources.npm_metadata(metadata_http(tmp_path, packument), "fixture", "1.0.0")
    assert meta["latest"] is None
    assert meta["publisher_provenance"] is None
    assert meta["release"]["deprecated"] == "use a supported release"
    assert meta["maintainers"] == ["alice", "bob"]
    assert meta["repository"] == "github.com/current/fixture"


@pytest.mark.parametrize(
    "selected_doc",
    [
        None,
        [],
        "invalid",
        {},
        {"dist": {}},
        {"name": "fixture"},
        {"version": "1.0.0"},
        {"name": "other", "version": "1.0.0"},
        {"name": "fixture", "version": "9.9.9"},
        {"name": [], "version": "1.0.0"},
        {"name": "fixture", "version": []},
    ],
)
def test_missing_or_malformed_selected_release_does_not_borrow_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict, selected_doc: object
):
    packument["versions"]["1.0.0"] = selected_doc
    dep, report = collected_project(tmp_path, monkeypatch, packument)
    for criterion in ("deprecated", "install_script", "provenance"):
        assert dep["signals"][criterion]["state"] == State.UNASSESSABLE.value
    assert dep["signals"]["publisher_concentration"]["state"] == State.UNASSESSABLE.value
    assert (
        "publishes from CI with provenance" in dep["signals"]["publisher_concentration"]["detail"]
    )
    assert dep["repo"] == "github.com/current/fixture"
    assert dep["signals"]["downloads"]["value"] == 5000
    assert "no usable release metadata for 1.0.0" in report


@pytest.mark.parametrize("doc", [None, [], "invalid"])
def test_malformed_package_document_is_unavailable(tmp_path: Path, doc: object):
    http = metadata_http(tmp_path, doc)
    with pytest.raises(sources.Unavailable, match="malformed package document"):
        sources.npm_metadata(http, "fixture", "1.0.0")


@pytest.mark.parametrize(
    "latest_doc",
    [None, [], "invalid", {}, {"name": "other", "version": "2.0.0"}, version_doc("9.9.9")],
)
def test_malformed_latest_does_not_hide_selected_release(
    tmp_path: Path, packument: dict, latest_doc: object
):
    packument["versions"]["2.0.0"] = latest_doc
    meta = sources.npm_metadata(metadata_http(tmp_path, packument), "fixture", "1.0.0")
    assert meta["latest"] is None
    assert meta["publisher_provenance"] is None
    assert meta["release"]["version"] == "1.0.0"
    assert sources.npm_metadata(metadata_http(tmp_path, packument), "fixture")["release"] is None


def collected_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    doc: dict,
    spec: str = "1.0.0",
    locked: str | None = None,
    name: str = "fixture",
    resolved: str = "1.0.0",
) -> tuple[dict, str]:
    monkeypatch.setattr(sources, "gh_token", lambda: None)
    monkeypatch.setattr(sources, "polite_pause", lambda: None)
    project = tmp_path / "project"
    project.mkdir()
    target = "@scope/fixture" if spec.startswith("npm:") else name
    doc["name"] = target
    for version in doc["versions"].values():
        if isinstance(version, dict) and version.get("name") == "fixture":
            version["name"] = target
    (project / "package.json").write_text(json.dumps({"dependencies": {name: spec}}))
    if locked:
        (project / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {name: spec}},
                        f"node_modules/{name}": {
                            "name": target,
                            "version": locked,
                            "resolved": f"{REGISTRY}/{target}/-/fixture-{locked}.tgz",
                            "integrity": "synthetic-test-marker",
                        },
                    },
                }
            )
        )
    http = metadata_http(tmp_path, doc, target)
    encoded = quote(target, safe="@")
    seed(
        http,
        "GET",
        f"https://api.npmjs.org/downloads/point/last-week/{encoded}",
        {"downloads": 5000},
    )
    seed(
        http,
        "POST",
        "https://api.osv.dev/v1/querybatch",
        {"results": [{}]},
        {"queries": [{"package": {"name": target, "ecosystem": "npm"}, "version": resolved}]},
    )
    artifact = collect(project, tmp_path / "cache", offline=True)
    return artifact["dependencies"][0], render(artifact)


@pytest.mark.parametrize(
    ("spec", "locked", "name", "source"),
    [
        ("2.0.0", "1.0.0", "fixture", "lockfile"),
        ("1.0.0", None, "fixture", "manifest-pin"),
        ("1.0.0+build.7", None, "fixture", "manifest-pin"),
        ("v1.0.0", None, "fixture", "manifest-pin"),
        ("=1.0.0", None, "fixture", "manifest-pin"),
        ("01.0.0", None, "fixture", "manifest-pin"),
        ("npm:@scope/fixture@^1", "1.0.0", "alias", "lockfile"),
        ("npm:@scope/fixture@1.0.0", None, "alias", "manifest-pin"),
    ],
)
def test_selected_release_reaches_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    packument: dict,
    spec: str,
    locked: str | None,
    name: str,
    source: str,
):
    dep, report = collected_project(tmp_path, monkeypatch, packument, spec, locked, name)
    assert dep["version_source"] == source
    assert dep["version"] == "1.0.0"
    assert dep["signals"]["advisories"]["state"] == State.CLEAN.value
    assert dep["signals"]["deprecated"]["state"] == State.FLAGGED.value
    assert dep["signals"]["install_script"]["state"] == State.FLAGGED.value
    assert dep["signals"]["provenance"]["value"] is False
    assert dep["signals"]["publisher_concentration"]["state"] == State.UNASSESSABLE.value
    assert "use a supported release" in report
    assert "runs declared install hooks" in report
    assert "Declared install hooks" in report
    assert "root message" not in report
    assert dep["signals"]["downloads"]["value"] == 5000


@pytest.mark.parametrize("spec", ["2.0.0", "^1.0.0"])
def test_selected_latest_and_range_fallback_are_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict, spec: str
):
    dep, report = collected_project(tmp_path, monkeypatch, packument, spec, resolved="2.0.0")
    assert dep["version"] == "2.0.0"
    assert dep["version_source"] == ("latest-release" if spec.startswith("^") else "manifest-pin")
    assert dep["signals"]["deprecated"]["state"] == State.CLEAN.value
    assert dep["signals"]["install_script"]["state"] == State.CLEAN.value
    assert dep["signals"]["provenance"]["value"] is True
    assert "use a supported release" not in report
    assert "root message" not in report


def test_missing_selected_preserves_current_package_measurements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict
):
    packument["versions"]["2.0.0"]["dist"] = {}
    dep, report = collected_project(tmp_path, monkeypatch, packument, "0.5.0", resolved="0.5.0")
    for criterion in ("deprecated", "install_script", "provenance"):
        assert dep["signals"][criterion]["state"] == State.UNASSESSABLE.value
    assert dep["signals"]["publisher_concentration"]["state"] == State.CLEAN.value
    assert dep["signals"]["publisher_concentration"]["value"] == ["alice", "bob"]
    assert dep["repo"] == "github.com/current/fixture"
    assert dep["signals"]["downloads"]["value"] == 5000
    assert "0.5.0" in report and "release metadata" in report


@pytest.mark.parametrize("latest_doc", [None, {}, version_doc("9.9.9")])
def test_unusable_latest_preserves_selected_release_and_unknown_publisher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict, latest_doc: object
):
    packument["versions"]["2.0.0"] = latest_doc
    dep, _ = collected_project(tmp_path, monkeypatch, packument)
    assert dep["signals"]["deprecated"]["state"] == State.FLAGGED.value
    assert dep["signals"]["install_script"]["state"] == State.FLAGGED.value
    assert dep["signals"]["publisher_concentration"]["state"] == State.UNASSESSABLE.value
    assert dep["signals"]["advisories"]["state"] == State.CLEAN.value


@pytest.mark.parametrize("include_dist", [False, True])
def test_valid_identity_allows_absent_optional_release_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict, include_dist: bool
):
    manifest = {"name": "fixture", "version": "1.0.0"}
    if include_dist:
        manifest["dist"] = {}
    packument["versions"]["1.0.0"] = manifest
    dep, _ = collected_project(tmp_path, monkeypatch, packument)
    for criterion in ("deprecated", "install_script"):
        assert dep["signals"][criterion]["state"] == State.CLEAN.value
        assert dep["signals"][criterion]["value"] is False
    assert dep["signals"]["provenance"]["state"] == (
        State.CLEAN.value if include_dist else State.UNASSESSABLE.value
    )


def test_no_selected_or_latest_release_preserves_package_data(tmp_path: Path, packument: dict):
    packument["dist-tags"] = {}
    meta = sources.npm_metadata(metadata_http(tmp_path, packument), "fixture")
    assert meta["release"] is None and meta["latest"] is None
    assert meta["maintainers"] == ["alice", "bob"]
    assert meta["repository"] == "github.com/current/fixture"


@pytest.mark.parametrize("dist", [None, [], {"attestations": "invalid"}])
def test_malformed_provenance_does_not_hide_other_release_properties(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict, dist: object
):
    packument["versions"]["1.0.0"]["dist"] = dist
    dep, _ = collected_project(tmp_path, monkeypatch, packument)
    assert dep["signals"]["provenance"]["state"] == State.UNASSESSABLE.value
    assert dep["signals"]["deprecated"]["state"] == State.FLAGGED.value
    assert dep["signals"]["install_script"]["state"] == State.FLAGGED.value


def test_malformed_latest_provenance_keeps_publisher_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict
):
    packument["versions"]["2.0.0"]["dist"] = None
    dep, _ = collected_project(tmp_path, monkeypatch, packument)
    assert dep["signals"]["publisher_concentration"]["state"] == State.UNASSESSABLE.value
    assert dep["signals"]["provenance"]["value"] is False


@pytest.mark.parametrize("deprecated", [None, [], {"message": "invalid"}])
def test_malformed_deprecation_does_not_become_a_risk_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict, deprecated: object
):
    packument["versions"]["1.0.0"]["deprecated"] = deprecated
    dep, _ = collected_project(tmp_path, monkeypatch, packument)
    assert dep["signals"]["deprecated"]["state"] == State.UNASSESSABLE.value
    assert dep["signals"]["install_script"]["state"] == State.FLAGGED.value
    assert dep["signals"]["provenance"]["value"] is False


@pytest.mark.parametrize("scripts", [None, [], "node install.js", {"install": 42}])
def test_malformed_scripts_only_make_install_measurement_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict, scripts: object
):
    packument["versions"]["1.0.0"]["scripts"] = scripts
    dep, _ = collected_project(tmp_path, monkeypatch, packument)
    assert dep["signals"]["install_script"]["state"] == State.UNASSESSABLE.value
    assert dep["signals"]["deprecated"]["state"] == State.FLAGGED.value
    assert dep["signals"]["provenance"]["value"] is False


def test_native_release_without_declared_hooks_is_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict
):
    packument["versions"]["1.0.0"].update(scripts={}, gypfile=True)
    dep, report = collected_project(tmp_path, monkeypatch, packument)
    assert dep["signals"]["install_script"]["state"] == State.UNASSESSABLE.value
    assert "native" in dep["signals"]["install_script"]["detail"]
    assert "tarballs" in report


def test_valid_install_hook_survives_malformed_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict
):
    packument["versions"]["1.0.0"]["scripts"] = {
        "preinstall": None,
        "postinstall": "node execute.js",
    }
    dep, report = collected_project(tmp_path, monkeypatch, packument)
    assert dep["signals"]["install_script"]["state"] == State.FLAGGED.value
    assert "postinstall" in report


def test_published_node_gyp_hook_is_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packument: dict
):
    packument["versions"]["1.0.0"].update(scripts={"install": "node-gyp rebuild"}, gypfile=True)
    dep, _ = collected_project(tmp_path, monkeypatch, packument)
    assert dep["signals"]["install_script"]["state"] == State.FLAGGED.value
