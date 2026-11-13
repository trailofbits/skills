"""Psalm 7 mechanisms need independent native evidence and immutable contracts."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from psalm_feature_probes import PROFILE, check_feature_runs, feature_capability, run_feature
from psalm_features import FEATURES, Feature, feature_expectations, feature_files
from psalm_version import psalm_major
from runner import check_probe, probe
from runner_artifacts import artifact

PSALM = os.environ.get("TAINT_TRACE_PSALM")


@pytest.fixture(scope="module")
def native_proof(tmp_path_factory):
    if not PSALM:
        pytest.skip("Set TAINT_TRACE_PSALM to execute native modeling contracts")
    path = tmp_path_factory.mktemp("psalm-features") / "proof.json"
    proof = probe(backend="psalm", language="php", executable=PSALM, output=path)
    assert proof["status"] == "passed", proof["errors"]
    assert check_probe(proof, path) == []
    core = json.loads(Path(proof["run"]).read_text())
    return proof, core


def test_every_modeling_contract_has_vulnerable_and_negative_native_sites():
    assert len(FEATURES) == 15
    for name in FEATURES:
        expected = feature_expectations(name)
        assert expected["positive"], name
        assert expected["negative"], name
        files = feature_files(name)
        assert "probe.php" in files and "psalm.xml" in files
        assert all(site.get("rule_id", "").startswith("Tainted") for site in expected["positive"])


def test_legacy_profiles_cannot_establish_psalm7_capabilities():
    proof = {"profile": "psalm-taint-contracts-v3", "feature_runs": {"custom_taints": {}}}
    assert check_feature_runs(proof, {}) == ["Psalm 7 feature evidence requires the v4 profile"]


@pytest.mark.parametrize("missing", list(FEATURES))
def test_psalm7_profile_requires_every_independent_contract(missing):
    proof = {"profile": PROFILE, "feature_runs": {name: {} for name in FEATURES if name != missing}}
    core = {"version": {"output": "Psalm 7.1.0"}}
    assert check_feature_runs(proof, core) == [
        "Psalm 7 capability proof lacks the exact built-in feature inventory"
    ]


def test_native_psalm7_contracts_preserve_exact_positive_and_negative_sites(native_proof):
    proof, core = native_proof
    if psalm_major(core["version"]["output"]) != 7:
        assert proof["profile"] == "psalm-taint-contracts-v3"
        assert "feature_runs" not in proof
        return
    assert proof["profile"] == PROFILE
    assert set(proof["feature_runs"]) == set(FEATURES)
    for name, evidence in proof["feature_runs"].items():
        capability = proof["optional_capabilities"][name]
        assert capability["status"] == "passed", capability["limitations"]
        assert capability["run"] == evidence["run"]
        assert feature_capability(name, evidence) == capability


@pytest.mark.parametrize("field", ["expect", "diagnostics", "fixture_files"])
def test_native_feature_rejects_changed_contract_metadata(native_proof, field):
    proof, core = copy.deepcopy(native_proof)
    if proof["profile"] != PROFILE:
        return
    proof["feature_runs"]["custom_taints"][field] = [] if field == "fixture_files" else {}
    assert any("contract" in error for error in check_feature_runs(proof, core))


@pytest.mark.parametrize("field", ["version", "config_files", "native_output"])
def test_native_feature_revalidates_version_configuration_and_artifacts(
    native_proof, tmp_path, field
):
    proof, core = copy.deepcopy(native_proof)
    if proof["profile"] != PROFILE:
        return
    evidence = proof["feature_runs"]["custom_taints"]
    run = json.loads(Path(evidence["run"]["path"]).read_text())
    if field == "version":
        run["version"]["output"] = "Psalm 7.0.0"
    elif field == "config_files":
        run["config_files"] = []
    else:
        run["native_output"]["sha256"] = "0" * 64
    path = tmp_path / "changed-run.json"
    path.write_text(json.dumps(run))
    evidence["run"] = artifact(path)
    assert check_feature_runs(proof, core)


def test_changed_feature_limits_capability_without_failing_core(
    native_proof, tmp_path, monkeypatch
):
    proof, _ = native_proof
    if proof["profile"] != PROFILE:
        return
    name = "automatic_specialization"
    original = FEATURES[name]
    # Keep a valid native run but require a taint issue at its literal control.
    changed = original.source.replace(
        "// negative", "// positive:TaintedHtml\n        echo 'safe'; // negative"
    )
    for other in list(FEATURES):
        if other != name:
            monkeypatch.delitem(FEATURES, other)
    monkeypatch.setitem(FEATURES, name, Feature(changed, original.models, original.configuration))
    path = tmp_path / "proof.json"
    result = probe(backend="psalm", language="php", executable=PSALM, output=path)
    capability = result["optional_capabilities"][name]
    assert capability["status"] == "limited"
    assert any("finding missing for positive" in item for item in capability["limitations"])
    assert result["status"] == "passed", result["errors"]
    assert check_probe(result, path) == []


def test_capabilities_require_declared_effects_for_opaque_functions(
    native_proof, tmp_path, monkeypatch
):
    proof, _ = native_proof
    if proof["profile"] != PROFILE:
        return
    name = "capabilities"
    original = FEATURES[name]
    models = original.models.replace(" * @psalm-capabilities pure\n", "")
    monkeypatch.setitem(FEATURES, name, Feature(original.source, models, original.configuration))
    evidence = run_feature(
        name,
        tmp_path / name,
        [PSALM, "--taint-analysis", "--debug", "--no-cache", "--output-format=json"],
    )
    capability = feature_capability(name, evidence)
    assert capability["status"] == "limited"
    assert any(
        "negative diagnostic expectation failed" in item for item in capability["limitations"]
    )
