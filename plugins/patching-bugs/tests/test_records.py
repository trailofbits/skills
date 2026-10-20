import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from records import RecordError, check, load, validate, verify_manifest, write_manifest

FIXTURE = Path(__file__).parent / "fixtures/run-ready"


def test_valid_finding_loads(tmp_path):
    record = {
        "schema_version": 1,
        "title": "Bug",
        "claim": "Escapes root",
        "affected_code": [],
        "invariant": "Stay inside root",
        "poc": None,
        "source": "user",
        "status": "hypothesis",
    }
    path = tmp_path / "finding.json"
    path.write_text(json.dumps(record))
    assert load(path, "finding") == record


def test_ready_fixture_passes_record_check_and_readiness(tmp_path):
    from verdict import verdict

    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    check(run)
    assert verdict(run) == ("READY", [])


@pytest.mark.parametrize("kind", ["patch", "prove"])
def test_attempt_record_must_match_its_directory(tmp_path, kind):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    path = run / kind / "attempt-1" / f"{kind}.json"
    record = json.loads(path.read_text())
    record["attempt"] = 2
    path.write_text(json.dumps(record))
    write_manifest(path.parent)
    with pytest.raises(RecordError, match=rf"{kind}/attempt-1.*attempt"):
        check(run)


@pytest.mark.parametrize("name", ["attempt-01", "attempt-x", "attempt-4"])
@pytest.mark.parametrize("kind", ["patch", "prove"])
def test_attempt_directory_must_have_a_canonical_supported_number(tmp_path, kind, name):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    (run / kind / "attempt-1").rename(run / kind / name)
    with pytest.raises(RecordError, match=rf"{kind}/{name}"):
        check(run)


@pytest.mark.parametrize("scope_present", [False, True])
def test_repair_entry_requires_scope_without_blocking_inconclusive_report(tmp_path, scope_present):
    from render import render

    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    finding_path = run / "finding.json"
    finding = json.loads(finding_path.read_text())
    if not scope_present:
        del finding["repair_scope"]
        finding_path.write_text(json.dumps(finding))
    script = Path(__file__).resolve().parents[1] / "scripts/records.py"
    result = subprocess.run(
        [sys.executable, str(script), "check", "--before-repair", str(run)],
        capture_output=True,
        text=True,
        check=False,
    )
    if scope_present:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode == 1
        assert "repair_scope" in result.stderr
        check(run)
        output = render(run).read_text()
        assert "INCONCLUSIVE" in output
        assert "repair scope is missing" in output
        assert "REPAIR SUCCEEDED" not in output


@pytest.mark.parametrize(
    "problem", ["empty", "one_representative", "no_control", "repeat_id", "repeat_input"]
)
def test_repair_entry_requires_a_usable_case_plan(tmp_path, problem):
    from render import render

    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    path = run / "finding.json"
    finding = json.loads(path.read_text())
    cases = finding["repair_scope"]["cases"]
    if problem == "empty":
        cases.clear()
    elif problem == "one_representative":
        cases.pop(1)
    elif problem == "no_control":
        cases.pop()
    elif problem == "repeat_id":
        cases[1]["check_id"] = cases[0]["check_id"]
    else:
        cases[1]["input"] = cases[0]["input"]
    path.write_text(json.dumps(finding))
    check(run)
    with pytest.raises(RecordError, match="repair scope"):
        check(run, before_repair=True)
    assert "INCONCLUSIVE" in render(run).read_text()


def test_attempt_gap_assessment_handles_malformed_directory_without_check(tmp_path):
    from records import attempt_gaps

    directory = tmp_path / "patch/attempt-bad"
    directory.mkdir(parents=True)
    gaps = attempt_gaps(tmp_path, 1)
    assert len(gaps) == 1
    assert "patch/attempt-bad" in gaps[0]


@pytest.mark.parametrize(
    ("relative", "kind", "fields"),
    [
        ("finding.json", "finding", ("title",)),
        ("finding.json", "finding", ("claim",)),
        ("finding.json", "finding", ("invariant",)),
        ("finding.json", "finding", ("source",)),
        ("finding.json", "finding", ("affected_code", 0, "path")),
        ("run.json", "run", ("finding_id",)),
        ("reproduce/reproduce.json", "reproduce", ("observed",)),
        ("reproduce/reproduce.json", "reproduce", ("agent",)),
        ("validate/validate.json", "validate", ("reason",)),
        ("validate/validate.json", "validate", ("agent",)),
        ("patch/attempt-1/patch.json", "patch", ("agent",)),
        ("patch/attempt-1/patch.json", "patch", ("suite_before", "command")),
        ("patch/attempt-1/patch.json", "patch", ("suite_after", "command")),
        ("patch/attempt-1/patch.json", "patch", ("variants", 0, "location")),
        ("patch/attempt-1/patch.json", "patch", ("variants", 0, "reason")),
        ("regression/regression.json", "regression", ("campaign_dir",)),
        ("regression/regression.json", "regression", ("outcomes", 0, "candidate_id")),
        ("regression/regression.json", "regression", ("outcomes", 0, "decision_receipt")),
        ("report-input.json", "report-input", ("bug",)),
        ("report-input.json", "report-input", ("open_risks", 0)),
    ],
)
def test_required_descriptions_and_identities_cannot_be_empty(tmp_path, relative, kind, fields):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    path = run / relative
    record = json.loads(path.read_text())
    if fields[0] == "variants":
        record["variants"] = [{"location": "app.py", "status": "not_fixed", "reason": "Deferred"}]
    elif fields[0] == "outcomes":
        record["outcomes"] = [
            {"candidate_id": "c1", "outcome": "UNRESOLVED", "decision_receipt": "decision.txt"}
        ]
    elif fields[0] == "open_risks":
        record["open_risks"] = ["Other inputs were not assessed."]
    target = record
    for field in fields[:-1]:
        target = target[field]
    target[fields[-1]] = ""
    path.write_text(json.dumps(record))
    with pytest.raises(RecordError, match=str(fields[-1])):
        load(path, kind)


def test_unknown_field_names_path():
    with pytest.raises(RecordError, match=r"\$\.extra"):
        validate({"extra": 1}, {"type": "object", "additionalProperties": False})


def test_bad_enum():
    with pytest.raises(RecordError, match="outcome"):
        validate(
            {"outcome": "wrong"}, {"type": "object", "properties": {"outcome": {"enum": ["ready"]}}}
        )


def test_schema_version_rejects_boolean_alias_for_integer():
    with pytest.raises(RecordError, match="expected"):
        validate(True, {"const": 1})


@pytest.mark.parametrize("field", ["cases", "project_checks", "unproven"])
def test_prove_record_requires_native_contract_fields(tmp_path, field):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    path = run / "prove/attempt-1/prove.json"
    proof = json.loads(path.read_text())
    proof.pop(field)
    path.write_text(json.dumps(proof))
    with pytest.raises(RecordError, match=field):
        load(path, "prove")


@pytest.mark.parametrize(
    "hashes",
    [
        {"baseline": "1" * 64, "patched": None, "reverted": "1" * 64},
        {"baseline": "1" * 64, "patched": "1" * 64, "reverted": "1" * 64},
    ],
)
def test_passing_runtime_identity_requires_distinct_complete_hashes(tmp_path, hashes):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    path = run / "prove/attempt-1/prove.json"
    proof = json.loads(path.read_text())
    proof["hashes"] = hashes
    path.write_text(json.dumps(proof))
    with pytest.raises(RecordError, match="hashes"):
        load(path, "prove")


def test_unsupported_keyword():
    with pytest.raises(RecordError, match="unsupported"):
        validate("x", {"format": "date"})


def test_manifest_round_trip_and_tamper(tmp_path):
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    receipt = receipts / "output.txt"
    receipt.write_text("original")
    write_manifest(tmp_path)
    verify_manifest(tmp_path)
    receipt.write_text("changed")
    with pytest.raises(RecordError, match=r"output\.txt"):
        verify_manifest(tmp_path)


@pytest.mark.parametrize("change", ["extra", "missing", "symlink"])
def test_manifest_rejects_file_set_changes(tmp_path, change):
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    receipt = receipts / "output.txt"
    receipt.write_text("original")
    write_manifest(tmp_path)
    if change == "extra":
        (receipts / "extra.txt").write_text("new")
    elif change == "missing":
        receipt.unlink()
    else:
        receipt.unlink()
        receipt.symlink_to(tmp_path / "target")
    with pytest.raises(RecordError):
        verify_manifest(tmp_path)


def test_schema_files_only_use_supported_keywords():
    from records import KEYWORDS, SCHEMA_DIR

    def walk(schema):
        assert set(schema) <= KEYWORDS
        for child in schema.get("properties", {}).values():
            walk(child)
        if "items" in schema:
            walk(schema["items"])

    for path in SCHEMA_DIR.glob("*.schema.json"):
        walk(json.loads(path.read_text()))


def test_deleted_step_manifest_fails_check(tmp_path):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    (run / "reproduce/manifest.json").unlink()
    with pytest.raises(RecordError, match=r"reproduce/manifest\.json"):
        check(run)


@pytest.mark.parametrize(
    "relative",
    [
        "patch/attempt-1/fix.patch",
        "reproduce/poc/poc.py",
    ],
)
def test_changed_step_file_fails_check(tmp_path, relative):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    (run / relative).write_text("tampered")
    with pytest.raises(RecordError, match=Path(relative).name.replace(".", r"\.")):
        check(run)


def test_receipt_named_like_record_is_not_parsed(tmp_path):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    (run / "reproduce/receipts/patch.json").write_text("arbitrary receipt")
    write_manifest(run / "reproduce")
    check(run)


def test_manifest_cli_writes_checkable_step(tmp_path):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    manifest = run / "reproduce/manifest.json"
    manifest.unlink()
    script = Path(__file__).resolve().parents[1] / "scripts/records.py"
    result = subprocess.run(
        [sys.executable, str(script), "manifest", str(run / "reproduce")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert manifest.is_file()
    check(run)


def test_reproduce_and_patch_require_agent(tmp_path):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    for relative, kind in (
        ("reproduce/reproduce.json", "reproduce"),
        ("patch/attempt-1/patch.json", "patch"),
    ):
        path = run / relative
        record = json.loads(path.read_text())
        record.pop("agent", None)
        path.write_text(json.dumps(record))
        with pytest.raises(RecordError, match=r"\$\.agent"):
            load(path, kind)
