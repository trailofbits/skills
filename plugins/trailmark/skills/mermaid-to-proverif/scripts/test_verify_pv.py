"""Tests for verify_pv.py using a fake ProVerif binary; the real one is exercised when present."""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("verify_pv", SCRIPTS / "verify_pv.py")
verify_pv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_pv)

GOOD = """Verification summary:
RESULT not event(endC(nc_1,ns_1)) is false.
RESULT not event(endS(nc_1,ns_1)) is false.
RESULT not attacker(secret_C[]) is true.
RESULT inj-event(endC(nc_1,ns_1)) ==> inj-event(beginS(nc_1,ns_1)) is true.
"""


def fake_proverif(tmp_path: Path, output: str, status: int = 0) -> Path:
    binary = tmp_path / "proverif"
    binary.write_text(f"#!/bin/sh\nprintf '%s' {sh_quote(output)}\nexit {status}\n")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    return binary


def sh_quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def run(tmp_path: Path, output: str, status: int = 0, model_text: str = "process 0.\n") -> int:
    model = tmp_path / "model.pv"
    model.write_text(model_text)
    binary = fake_proverif(tmp_path, output, status)
    os.environ["PROVERIF_BIN"] = str(binary)
    try:
        return verify_pv.main([str(model)])
    finally:
        del os.environ["PROVERIF_BIN"]


def test_classification_and_judgement():
    assert verify_pv.judge("not event(endC(a,b))", "is false")[1] is True
    assert verify_pv.judge("not event(endC(a,b))", "is true")[1] is False
    assert verify_pv.judge("not attacker(secret[])", "is true")[1] is True
    assert verify_pv.judge("not attacker(secret[])", "is false")[1] is False
    assert verify_pv.judge("inj-event(a) ==> inj-event(b)", "is true")[1] is True
    assert verify_pv.judge("event(a) ==> event(b)", "is false")[1] is False
    assert verify_pv.judge("not attacker(secret[])", "cannot be proved")[1] is False
    assert verify_pv.classify("inj-event(a) ==> inj-event(b)") == "correspondence"
    assert verify_pv.classify("not attacker(s[])") == "secrecy"
    assert verify_pv.classify("not event(e(x))") == "reachability"


def test_all_good_passes(tmp_path):
    assert run(tmp_path, GOOD) == 0


def test_unreachable_event_fails(tmp_path):
    assert (
        run(
            tmp_path,
            GOOD.replace(
                "not event(endS(nc_1,ns_1)) is false", "not event(endS(nc_1,ns_1)) is true"
            ),
        )
        == 1
    )


def test_secrecy_violation_fails(tmp_path):
    assert (
        run(
            tmp_path,
            GOOD.replace("not attacker(secret_C[]) is true", "not attacker(secret_C[]) is false"),
        )
        == 1
    )


def test_broken_authentication_fails(tmp_path):
    assert (
        run(
            tmp_path,
            GOOD.replace(
                "inj-event(beginS(nc_1,ns_1)) is true", "inj-event(beginS(nc_1,ns_1)) is false"
            ),
        )
        == 1
    )


def test_cannot_be_proved_fails(tmp_path):
    assert run(tmp_path, GOOD.replace("is true.\nRESULT inj", "cannot be proved.\nRESULT inj")) == 1


def test_no_result_lines_fails(tmp_path):
    assert run(tmp_path, "Verification summary:\n") == 1


def test_compile_error_fails(tmp_path):
    assert run(tmp_path, 'File "model.pv", line 3: Syntax error\n', status=2) == 1


def test_missing_verifier_and_model(tmp_path, capsys):
    os.environ["PROVERIF_BIN"] = str(tmp_path / "not-installed")
    try:
        assert verify_pv.main([str(tmp_path / "model.pv")]) == 127
    finally:
        del os.environ["PROVERIF_BIN"]
    fake_proverif(tmp_path, GOOD)
    os.environ["PROVERIF_BIN"] = str(tmp_path / "proverif")
    try:
        assert verify_pv.main([str(tmp_path / "missing.pv")]) == 2
    finally:
        del os.environ["PROVERIF_BIN"]


GOOD_MODEL = "\n".join(
    [
        "free c: channel.",
        "free s: bitstring [private].",
        "event done.",
        "query attacker(s).",
        "query event(done).",
        "process",
        "    new n: bitstring; event done; out(c, n)",
        "",
    ]
)

LEAKY_MODEL = GOOD_MODEL.replace("out(c, n)", "out(c, s)")


@pytest.mark.skipif(shutil.which("proverif") is None, reason="ProVerif is not installed")
def test_real_proverif_verdicts(tmp_path):
    good = tmp_path / "good.pv"
    good.write_text(GOOD_MODEL)
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "verify_pv.py"), str(good)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS [reachability]" in proc.stdout and "PASS [secrecy]" in proc.stdout
    leaky = tmp_path / "leaky.pv"
    leaky.write_text(LEAKY_MODEL)
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "verify_pv.py"), str(leaky)], capture_output=True, text=True
    )
    assert proc.returncode == 1
    assert "FAIL [secrecy]" in proc.stdout
    broken = tmp_path / "broken.pv"
    broken.write_text("free c: channel" + chr(10) + "process 0." + chr(10))
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "verify_pv.py"), str(broken)], capture_output=True, text=True
    )
    assert proc.returncode == 1
