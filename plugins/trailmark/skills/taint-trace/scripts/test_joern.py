"""The optional Joern engine must prove findings, negatives, and native callees."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from joern_fixture import FIXTURES, QUERY, write_contract
from runner import check_probe, probe


@pytest.mark.parametrize("language", sorted(FIXTURES))
def test_contract_anchors_and_commands_stay_inside_copied_fixture(tmp_path, language):
    contract_path = write_contract(tmp_path / language, language)
    contract = json.loads(contract_path.read_text())
    source_root = contract_path.parent / contract["fixture_root"]
    for sites in contract["expect"].values():
        for site in sites:
            source = source_root / site["file"]
            assert 0 < site["line"] <= len(source.read_text().splitlines())
    assert "{workdir}/source" in contract["commands"][0]
    # --nooverlays also disables frontend post-processing (including Ruby call
    # resolution), so parsing must run its normal native frontend passes.
    assert "--nooverlays" not in contract["commands"][0]
    assert "--script" in contract["commands"][1]
    # Native traversal into relay_value is tested; no summary may replace it.
    assert 'FlowSemantic.from("relay_value"' not in QUERY
    assert contract["expect"]["cross_function"]
    assert len(contract["expect"]["negative"]) == 2


@pytest.mark.parametrize("language", sorted(FIXTURES))
def test_installed_joern_native_capability(tmp_path, language):
    configured = os.environ.get("TAINT_TRACE_JOERN")
    if not configured:
        pytest.skip("Set TAINT_TRACE_JOERN to run native Joern capability tests")
    executable = configured
    proof_path = tmp_path / "proof.json"
    proof = probe(backend="joern", language=language, output=proof_path, executable=executable)
    assert proof["status"] == "passed", proof["errors"]
    assert not check_probe(proof, proof_path)
    # Generated CPG/build artifacts must not replace the immutable source/query
    # snapshots captured before the frontend command runs.
    assert all(Path(item["path"]).name != "cpg.bin" for item in proof["fixture_files"])
    native_run = json.loads(Path(proof["run"]).read_text())
    assert native_run["scanned_files"]
    assert not native_run["errors"]
    assert all(item["source_line"] for item in native_run["findings"])
    by_site = {(Path(item["file"]).name, item["line"]): item for item in native_run["findings"]}
    cross = proof["expect"]["cross_function"][0]
    flow = by_site[(Path(cross["file"]).name, cross["line"])]
    assert any("relay_value" in node.get("method", "") for node in flow["trace"]), flow
    sql_site = proof["expect"]["positive"][1]
    sql_flow = by_site[(Path(sql_site["file"]).name, sql_site["line"])]
    assert sql_flow["rule_id"] == "trailmark.request-to-sql"
