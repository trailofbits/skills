"""Every `{baseDir}/...` path the skill documents must name a file or directory that exists."""

from __future__ import annotations

import re
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2]
SKILL_DIR = PLUGIN / "skills" / "constant-time-analysis"
PATH_RE = re.compile(r"\{baseDir\}(/[^\s`\"')]+)")


def documented_paths() -> list[tuple[str, str]]:
    found = []
    for doc in [SKILL_DIR / "SKILL.md", *sorted((SKILL_DIR / "references").glob("*.md"))]:
        for match in PATH_RE.finditer(doc.read_text(encoding="utf-8")):
            found.append((doc.name, match.group(1)))
    return found


def test_skill_documents_baseDir_paths():
    assert documented_paths(), "no {baseDir} paths found; update PATH_RE"


def test_every_baseDir_path_exists():
    missing = sorted(
        {
            (doc, path)
            for doc, path in documented_paths()
            if not (SKILL_DIR / path.lstrip("/")).exists()
        }
    )
    assert not missing, f"{{baseDir}} is the skill directory; these paths do not exist: {missing}"
