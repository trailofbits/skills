#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS_DIR = REPO_ROOT / "plugins"
CODEX_SKILLS_DIR = REPO_ROOT / ".codex" / "skills"


def plugin_skill_dirs() -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    for skill_md in sorted(PLUGINS_DIR.glob("*/skills/*/SKILL.md")):
        skill_dir = skill_md.parent
        name = skill_dir.name
        if name in mapping:
            raise SystemExit(
                f"Duplicate plugin skill name '{name}' found at {mapping[name]} and {skill_dir}"
            )
        mapping[name] = skill_dir
    return mapping


def codex_skill_entries() -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    if not CODEX_SKILLS_DIR.exists():
        return mapping
    for entry in sorted(CODEX_SKILLS_DIR.iterdir()):
        mapping[entry.name] = entry
    return mapping


def rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def main() -> int:
    plugin_skills = plugin_skill_dirs()
    codex_entries = codex_skill_entries()
    errors: list[str] = []

    for name, skill_dir in plugin_skills.items():
        codex_entry = codex_entries.get(name)
        if codex_entry is None:
            errors.append(
                f"Missing Codex mapping for plugin skill '{name}'. "
                f"Expected .codex/skills/{name}. Run ./.codex/scripts/install-for-codex.sh locally and update the repo view."
            )
            continue

        if codex_entry.is_symlink():
            resolved = codex_entry.resolve()
            if resolved != skill_dir.resolve():
                errors.append(
                    f"Broken Codex symlink for '{name}': {rel(codex_entry)} -> {resolved}, expected {skill_dir.resolve()}"
                )
        else:
            skill_md = codex_entry / "SKILL.md"
            if not skill_md.exists():
                errors.append(
                    f"Codex entry '{name}' is not a symlink and does not contain SKILL.md at {rel(skill_md)}"
                )

    for name, codex_entry in codex_entries.items():
        if name in plugin_skills:
            continue
        skill_md = codex_entry / "SKILL.md"
        if not skill_md.exists():
            errors.append(
                f"Codex-only entry '{name}' must contain SKILL.md at {rel(skill_md)}"
            )

    if errors:
        print("Codex skill validation failed:\n", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        print(
            "\nFix locally by running: ./.codex/scripts/install-for-codex.sh\n"
            "Then commit the resulting .codex/ changes (or add an explicit Codex wrapper skill if the plugin has no skills/ directory).",
            file=sys.stderr,
        )
        return 1

    print(
        f"Validated {len(plugin_skills)} plugin skills against {len(codex_entries)} Codex entries successfully."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
