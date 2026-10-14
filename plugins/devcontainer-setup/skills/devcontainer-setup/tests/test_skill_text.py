"""SKILL.md recipes must agree with the shipped templates and with each other."""

import json
import re
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
SKILL = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
TEMPLATE = json.loads((SKILL_DIR / "resources" / "devcontainer.json").read_text(encoding="utf-8"))


def test_post_install_matches_the_template_command():
    base = TEMPLATE["postCreateCommand"]
    assert base == "uv run --no-project /opt/post_install.py"
    uses = re.findall(r"uv run[^`&\n]*/opt/post_install\.py", SKILL)
    assert uses and all(u == base for u in uses), uses


def test_python_setup_order_is_consistent():
    # Both the Python rule and the multi-language example clear .venv and sync first.
    chains = [
        c for c in re.findall(r"```\n(.*?)\n```", SKILL) if "post_install" in c and "uv sync" in c
    ]
    assert len(chains) == 2
    assert all(c.startswith("rm -rf .venv && uv sync && uv run --no-project") for c in chains)


def test_pnpm_and_yarn_run_through_corepack():
    # fnm's Node provides corepack but no pnpm/yarn shims.
    assert not re.search(r"&& (pnpm|yarn) install", SKILL)
    assert "corepack pnpm install --frozen-lockfile" in SKILL
    assert "corepack yarn install --frozen-lockfile" in SKILL


def test_detection_tables_agree():
    assert "| Python | `pyproject.toml`, `requirements.txt`, `setup.py`, `*.py` |" in SKILL


def test_dockerfile_first_line_cannot_become_a_parser_directive():
    first = (SKILL_DIR / "resources" / "Dockerfile").read_text(encoding="utf-8").splitlines()[0]
    assert not first.startswith("# {{")
