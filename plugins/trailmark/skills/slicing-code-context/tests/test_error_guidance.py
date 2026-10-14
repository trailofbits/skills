"""Every error code the packet builder emits must be covered by SKILL.md's Error Handling."""

import re
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
SKILL = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
BUILDER = (SKILL_DIR / "scripts" / "build_slice_packet.py").read_text(encoding="utf-8")


def test_every_builder_error_code_has_guidance():
    codes = set(re.findall(r'SlicePacketError\(\s*"([a-z_]+)"', BUILDER))
    assert codes, "no error codes found; update the pattern"
    section = SKILL.split("## Error Handling")[1].split("\n## ")[0]
    listed = set(re.findall(r"`([a-z_]+)`", section))
    # Codes without their own bullet fall under the catch-all line.
    assert "Any other code" in section or codes <= listed, sorted(codes - listed)
    assert "details" in section  # ambiguous_symbol candidates are in the error details
