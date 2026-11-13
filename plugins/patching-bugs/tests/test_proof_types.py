import json
import subprocess
import sys
from pathlib import Path

import pytest
from arms import ArmSpec, run_arms
from records import RecordError, check, load, verify_manifest
from render import render
from test_arms import git
from test_render import case, change
from verdict import verdict

COMPILER = [
    sys.executable,
    "-c",
    "import py_compile; py_compile.compile('value.py', cfile='value.pyc', doraise=True)",
]
DIAGNOSTIC = "SyntaxError: expected ':'"


def compile_spec(build=None, diagnostic=DIAGNOSTIC):
    return ArmSpec(
        COMPILER if build is None else build,
        [],
        None,
        30,
        failure_type="compile",
        expected_diagnostic=diagnostic,
    )


def toy_repo(tmp_path, files, changes):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.org")
    git(repo, "config", "user.name", "Test")
    for name, content in files.items():
        (repo / name).write_text(content)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "baseline")
    baseline = git(repo, "rev-parse", "HEAD")
    for index, revision in enumerate(changes):
        for name, content in revision.items():
            (repo / name).write_text(content)
        git(repo, "add", ".")
        git(repo, "commit", "-qm", f"repair part {index + 1}")
    return repo, baseline, git(repo, "rev-parse", "HEAD")


def test_compiler_failure_proves_a_fix_without_a_baseline_binary(tmp_path):
    repo, baseline, patch = toy_repo(
        tmp_path,
        {"value.py": "def value()\n    return 1\n"},
        [{"value.py": "def value():\n    return 1\n"}],
    )
    out = tmp_path / "proof"
    result = run_arms(repo, baseline, patch, compile_spec(), out)
    codes = [
        json.loads((out / "receipts" / name / "build/exit.json").read_text())["exit_code"]
        for name in ("baseline", "patched", "reverted")
    ]
    assert codes == [1, 0, 1]
    assert result["reverted"] == "pass"
    assert result["failure_type"] == "compile"
    assert result["build_identity"] == "not_applicable"
    assert result["hashes"] == dict.fromkeys(("baseline", "patched", "reverted"))
    assert not list(out.glob("receipts/*/poc"))
    verify_manifest(out)


@pytest.mark.parametrize(
    ("build", "expected"),
    [
        ([sys.executable, "-c", "raise SyntaxError('unrelated diagnostic')"], "inconclusive"),
        (["missing-test-compiler"], "inconclusive"),
        ([sys.executable, "-c", "pass"], "fail"),
    ],
)
def test_unrelated_compile_failure_is_not_the_target_bug(tmp_path, build, expected):
    repo, baseline, patch = toy_repo(
        tmp_path, {"value.py": "VALUE = 0\n"}, [{"value.py": "VALUE = 1\n"}]
    )
    result = run_arms(repo, baseline, patch, compile_spec(build), tmp_path / "proof")
    assert result["reverted"] == expected


def test_compile_bug_still_present_fails_proof(tmp_path):
    repo, baseline, patch = toy_repo(
        tmp_path,
        {"value.py": "def value()\n    return 1\n"},
        [{"value.py": "def value()\n    return 2\n"}],
    )
    result = run_arms(repo, baseline, patch, compile_spec(), tmp_path / "proof")
    assert result["reverted"] == "fail"


def test_runtime_identity_follows_the_loaded_module(tmp_path):
    repo, baseline, patch = toy_repo(
        tmp_path,
        {"value.py": "VALUE = 0\n"},
        [{"value.py": "VALUE = 1\n"}],
    )
    installed = tmp_path / "installed.py"
    installed.write_text("VALUE = 0\n")
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import hashlib, importlib.util, json, pathlib, sys\n"
        "spec = importlib.util.spec_from_file_location('value', sys.argv[1])\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        "loaded = pathlib.Path(module.__file__).resolve()\n"
        "print('PATCH_LOADED ' + json.dumps({'path': str(loaded), "
        "'sha256': hashlib.sha256(loaded.read_bytes()).hexdigest()}))\n"
        "print('PATCH_REACHED')\n"
        "sys.exit(0 if module.VALUE == 1 else 1)\n"
    )
    spec = ArmSpec(
        [sys.executable, "-m", "py_compile", "value.py"],
        [sys.executable, str(driver), str(installed)],
        "value.py",
        30,
    )
    result = run_arms(repo, baseline, patch, spec, tmp_path / "proof")
    assert result["build_identity"] == "fail"


@pytest.mark.parametrize("observation", ["", "PATCH_LOADED []", "PATCH_LOADED not-json"])
def test_missing_or_malformed_loader_identity_cannot_pass(tmp_path, observation):
    repo, baseline, patch = toy_repo(
        tmp_path, {"value.py": "VALUE = 0\n"}, [{"value.py": "VALUE = 1\n"}]
    )
    spec = ArmSpec(
        [sys.executable, "-m", "py_compile", "value.py"],
        [sys.executable, "-c", f"print({observation!r}); print('PATCH_REACHED')"],
        "value.py",
        30,
    )
    result = run_arms(repo, baseline, patch, spec, tmp_path / "proof")
    assert result["build_identity"] == "fail"


def test_loader_hash_must_match_the_built_artifact(tmp_path):
    repo, baseline, patch = toy_repo(
        tmp_path, {"value.py": "VALUE = 0\n"}, [{"value.py": "VALUE = 1\n"}]
    )
    poc = (
        "import json, pathlib; "
        "print('PATCH_LOADED ' + json.dumps({'path':str(pathlib.Path('value.py').resolve()),"
        "'sha256':'wrong'})); print('PATCH_REACHED')"
    )
    spec = ArmSpec(COMPILER, [sys.executable, "-c", poc], "value.py", 30)
    assert run_arms(repo, baseline, patch, spec, tmp_path / "proof")["build_identity"] == "fail"


def test_revert_restores_every_file_across_the_complete_repair(tmp_path):
    driver = (
        "import hashlib, json, pathlib, sys\n"
        "import left, right\n"
        "loaded = pathlib.Path(left.__file__).resolve()\n"
        "print('PATCH_LOADED ' + json.dumps({'path': str(loaded), "
        "'sha256': hashlib.sha256(loaded.read_bytes()).hexdigest()}))\n"
        "print(json.dumps({'left': left.VALUE, 'right': right.VALUE}))\n"
        "print('PATCH_REACHED')\n"
        "sys.exit(0 if left.VALUE == right.VALUE == 1 else 1)\n"
    )
    repo, baseline, patch = toy_repo(
        tmp_path,
        {"left.py": "VALUE = 0\n", "right.py": "VALUE = 0\n", "driver.py": driver},
        [{"left.py": "VALUE = 1\n"}, {"right.py": "VALUE = 1\n"}],
    )
    spec = ArmSpec(
        [sys.executable, "-m", "py_compile", "left.py", "right.py"],
        [sys.executable, "driver.py"],
        "left.py",
        30,
    )
    out = tmp_path / "proof"
    result = run_arms(repo, baseline, patch, spec, out)
    reverted = (out / "receipts/reverted/poc/stdout.txt").read_text()
    assert '{"left": 0, "right": 0}' in reverted
    assert result["hashes"]["reverted"] == result["hashes"]["baseline"]
    assert result["reverted"] == "pass"
    assert result["build_identity"] == "pass"
    source = json.loads((out / "receipts/source.json").read_text())
    assert source == {
        "baseline_commit": baseline,
        "patch_commit": patch,
        "trees": {
            "baseline": git(repo, "rev-parse", f"{baseline}^{{tree}}"),
            "patched": git(repo, "rev-parse", f"{patch}^{{tree}}"),
            "reverted": git(repo, "rev-parse", f"{baseline}^{{tree}}"),
        },
    }
    assert git(repo, "rev-parse", "HEAD") == patch
    verify_manifest(out)


def compile_run(tmp_path):
    run = case(tmp_path)
    change(
        run,
        "reproduce/reproduce.json",
        failure_type="compile",
        expected_diagnostic=DIAGNOSTIC,
        build_argv=COMPILER,
        poc_argv=[],
        target_artifact=None,
        observed=DIAGNOSTIC,
    )
    change(
        run,
        "prove/attempt-1/prove.json",
        failure_type="compile",
        build_identity="not_applicable",
        hashes=dict.fromkeys(("baseline", "patched", "reverted")),
    )
    return run


def test_compile_records_and_report_do_not_claim_runtime_artifact(tmp_path):
    run = compile_run(tmp_path)
    check(run)
    assert verdict(run) == ("READY", [])
    output = render(run).read_text()
    assert "Bounded class repaired" in output
    assert (
        "Compiler failed with the target diagnostic, passed after repair, and failed again"
        in output
    )
    assert "Runtime artifact identity is not applicable to a compile failure" in output
    assert "Patched artifact differs from baseline" not in output
    assert "--artifact None" not in output
    assert "py_compile" in output


def test_runtime_report_uses_recorded_loader_identity(tmp_path):
    run = case(tmp_path)
    assert "Loaded implementation matches" in render(run).read_text()


@pytest.mark.parametrize("failure_type", ["compile", "runtime"])
def test_proof_type_must_match_reproduction(tmp_path, failure_type):
    run = compile_run(tmp_path) if failure_type == "runtime" else case(tmp_path)
    change(run, "prove/attempt-1/prove.json", failure_type=failure_type)
    if failure_type == "runtime":
        change(
            run,
            "prove/attempt-1/prove.json",
            build_identity="pass",
            hashes={"baseline": "1" * 64, "patched": "2" * 64, "reverted": "1" * 64},
        )
    else:
        change(
            run,
            "prove/attempt-1/prove.json",
            build_identity="not_applicable",
            hashes=dict.fromkeys(("baseline", "patched", "reverted")),
        )
    assert verdict(run) == ("NOT_READY", ["proof failure type differs from reproduction"])


def test_mismatched_proof_type_cannot_claim_repair_in_any_report_section(tmp_path):
    run = case(tmp_path)
    change(
        run,
        "prove/attempt-1/prove.json",
        failure_type="compile",
        build_identity="not_applicable",
        hashes=dict.fromkeys(("baseline", "patched", "reverted")),
    )
    change(run, "validate/validate.json", agent="reproducer")
    check(run)
    output = render(run).read_text()
    assert "Automated patch verdict:</strong> NOT_READY" in output
    assert "INCONCLUSIVE" in output
    assert "FAILED REPAIR" not in output
    assert "Exact example repaired" not in output
    assert "target bug no longer reproduces" not in output
    assert "Compiler failed with the target diagnostic, passed after repair" not in output
    assert "Repair not established" in output
    assert "Proof failure type differs from reproduction" in output


@pytest.mark.parametrize(
    ("relative", "fields", "message"),
    [
        ("reproduce/reproduce.json", {"expected_diagnostic": ""}, "expected_diagnostic"),
        ("reproduce/reproduce.json", {"poc_argv": ["runtime-poc"]}, "poc_argv"),
        ("reproduce/reproduce.json", {"target_artifact": "old-binary"}, "target_artifact"),
        ("prove/attempt-1/prove.json", {"build_identity": "pass"}, "build_identity"),
    ],
)
def test_compile_contract_rejects_inconsistent_fields(tmp_path, relative, fields, message):
    run = compile_run(tmp_path)
    change(run, relative, **fields)
    with pytest.raises(RecordError, match=message):
        load(run / relative, Path(relative).stem)


def test_compile_cli_does_not_require_poc_or_artifact(tmp_path):
    repo, baseline, patch = toy_repo(
        tmp_path,
        {"value.py": "def value()\n    return 1\n"},
        [{"value.py": "def value():\n    return 1\n"}],
    )
    script = Path(__file__).resolve().parents[1] / "scripts/arms.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "run",
            "--repo",
            str(repo),
            "--baseline",
            baseline,
            "--patch",
            patch,
            "--build",
            json.dumps(COMPILER),
            "--failure-type",
            "compile",
            "--expected-diagnostic",
            DIAGNOSTIC,
            "--out",
            str(tmp_path / "proof"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["reverted"] == "pass"
