"""The skill's commands never install Trailmark, and its snippets produce every Step 4 field."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL = (Path(__file__).resolve().parent.parent / "SKILL.md").read_text(encoding="utf-8")
BLOCKS = re.findall(r"```bash\n(.*?)```", SKILL, flags=re.S)
SNIPPETS = [b.split("<<'PY'\n", 1)[1].rsplit("PY", 1)[0] for b in BLOCKS if "<<'PY'" in b]
FIELDS = {"languages", "summary", "preanalysis", "attack_surface", "hotspots", "proxy_nodes"}


def test_no_install_route():
    assert "--with trailmark" not in SKILL
    assert not re.search(r"\binstall\b", "\n".join(BLOCKS))


def test_snippets_use_trailmarks_own_interpreter():
    runs = [b for b in BLOCKS if "<<'PY'" in b]
    assert len(runs) == 2 and all("command -v trailmark" in b for b in runs)


def test_snippets_run_and_return_every_field(tmp_path):
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv is not on PATH; the snippets are run with a Trailmark environment")
    (tmp_path / "app.py").write_text("import os\n\n\ndef main():\n    return os.getcwd()\n")

    def run(code: str):
        proc = subprocess.run(
            [uv, "run", "--quiet", "--no-project", "--with", "trailmark>=0.5,<0.6"]
            + ["python", "-", str(tmp_path)],
            input=code,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)

    detect, structural = SNIPPETS
    assert run(detect) == ["python"]
    payload = run(structural)
    assert set(payload) >= FIELDS and "subgraphs" in payload
