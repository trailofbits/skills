"""The guidance must read ProVerif results the way ProVerif reports them."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent
DOCS = {
    p.name: p.read_text(encoding="utf-8")
    for p in [SKILL_DIR / "SKILL.md", *sorted((SKILL_DIR / "references").glob("*.md"))]
}
SAMPLE = SKILL_DIR / "examples" / "simple-handshake" / "sample-output.pv"


def test_reachability_false_is_never_called_unreachable():
    # ProVerif checks `not event(e)`: "is false" means the event IS reachable.
    for name, text in {**DOCS, SAMPLE.name: SAMPLE.read_text()}.items():
        assert not re.search(r"`?false`?\s*\(unreachable\)", text), name
        assert "If either returns FALSE, the model has a structural bug" not in text, name


def test_forward_secrecy_leaks_keys_after_the_sessions():
    fs = DOCS["security-properties.md"].split("## 3. Forward Secrecy")[1].split("## 4.")[0]
    assert "phase 1; out(c, sk_I); out(c, sk_R)" in fs
    assert "leak long-term keys immediately" not in fs


def test_no_dangling_pointers():
    assert "unlinkability" not in DOCS["SKILL.md"]
    assert "worked example in\n`examples/simple-handshake/sample-output.pv`" not in DOCS["SKILL.md"]


def test_sample_documents_its_injective_finding():
    assert "REPORTED FALSE" in SAMPLE.read_text()


def test_sample_results_match_the_documentation():
    proverif = shutil.which("proverif")
    if proverif is None:
        pytest.skip("proverif is not installed; the text checks above still run")
    out = subprocess.run([proverif, str(SAMPLE)], capture_output=True, text=True).stdout
    results = [line for line in out.splitlines() if line.startswith("RESULT")]
    assert sum("not event(end" in r and r.endswith("is false.") for r in results) == 2
    assert any(r.startswith("RESULT inj-event(endR") and r.endswith("is false.") for r in results)
    assert sum("not attacker(private_" in r and r.endswith("is true.") for r in results) == 2
