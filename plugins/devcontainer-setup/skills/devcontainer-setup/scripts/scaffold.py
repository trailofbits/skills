#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Scaffold a Claude Code devcontainer from the shipped templates.

    scaffold.py [PROJECT_DIR] [--name NAME] [--slug SLUG] [--langs LIST|auto]
                [--python-version X.Y]

Detects the language stack (Python, Node/TypeScript, Rust, Go), infers the project name
and slug from the project's manifests, copies the five templates from ``../resources``,
merges the per-language configuration into ``devcontainer.json``, validates the result,
and prints what it wrote. It refuses to touch an existing ``.devcontainer/``.

The rules mirror the skill's documented ones exactly, so the output is what a careful
reading of SKILL.md would produce by hand — without the model retyping the templates.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path

RESOURCES = Path(__file__).resolve().parent.parent / "resources"
OUTPUT_FILES = ("Dockerfile", "devcontainer.json", "post_install.py", ".zshrc", "install.sh")
LANGUAGE_ORDER = ("python", "node", "rust", "go")
LANGUAGE_ALIASES = {"typescript": "node", "nodejs": "node", "javascript": "node", "golang": "go"}
POST_INSTALL = "uv run --no-project /opt/post_install.py"
PLACEHOLDER = re.compile(r"\{\{PROJECT_(NAME|SLUG)\}\}")
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SKIP_DIRS = {"node_modules", "venv", "target", "vendor", "dist", "build", "__pycache__"}
PYTHON_INSTALL = re.compile(r"^(RUN uv python install )(\S+)( --default)$", re.MULTILINE)

# Per-language additions, verbatim from SKILL.md's language sections.
EXTENSIONS = {
    "python": ["ms-python.python", "ms-python.vscode-pylance", "charliermarsh.ruff"],
    "node": ["dbaeumer.vscode-eslint", "esbenp.prettier-vscode"],
    "rust": ["rust-lang.rust-analyzer", "tamasfe.even-better-toml"],
    "go": ["golang.go"],
}
SETTINGS = {
    "python": {
        "python.defaultInterpreterPath": ".venv/bin/python",
        "[python]": {
            "editor.defaultFormatter": "charliermarsh.ruff",
            "editor.codeActionsOnSave": {"source.organizeImports": "explicit"},
        },
    },
    "node": {
        "editor.defaultFormatter": "esbenp.prettier-vscode",
        "editor.codeActionsOnSave": {"source.fixAll.eslint": "explicit"},
    },
    "rust": {"[rust]": {"editor.defaultFormatter": "rust-lang.rust-analyzer"}},
    "go": {"[go]": {"editor.defaultFormatter": "golang.go"}, "go.useLanguageServer": True},
}
FEATURES = {
    "rust": {"ghcr.io/devcontainers/features/rust:1": {}},
    "go": {"ghcr.io/devcontainers/features/go:1": {"version": "latest"}},
}


class ScaffoldError(Exception):
    """A user-facing failure; the message is printed without a traceback."""


# --- detection -------------------------------------------------------------------------


def has_python_files(project: Path) -> bool:
    """True if any .py file exists outside hidden, dependency, and build directories."""
    stack = [project]
    while stack:
        current = stack.pop()
        for entry in sorted(current.iterdir()):
            if entry.is_dir():
                if entry.name.startswith(".") or entry.name in SKIP_DIRS:
                    continue
                stack.append(entry)
            elif entry.suffix == ".py":
                return True
    return False


def detect_languages(project: Path) -> list[str]:
    """Apply SKILL.md's detection table, in its priority order."""
    found = []
    if any(
        (project / f).is_file() for f in ("pyproject.toml", "requirements.txt", "setup.py")
    ) or has_python_files(project):
        found.append("python")
    if any((project / f).is_file() for f in ("package.json", "tsconfig.json")):
        found.append("node")
    if (project / "Cargo.toml").is_file():
        found.append("rust")
    if any((project / f).is_file() for f in ("go.mod", "go.sum")):
        found.append("go")
    return found


def parse_languages(spec: str, project: Path) -> tuple[list[str], str]:
    """Return the languages to configure (canonical order) and where they came from."""
    if spec == "auto":
        return detect_languages(project), "auto"
    chosen = set()
    for raw in spec.split(","):
        name = LANGUAGE_ALIASES.get(raw.strip().lower(), raw.strip().lower())
        if not name:
            continue
        if name not in LANGUAGE_ORDER:
            raise ScaffoldError(
                f"unknown language {raw.strip()!r}; choose from {', '.join(LANGUAGE_ORDER)}"
            )
        chosen.add(name)
    return [lang for lang in LANGUAGE_ORDER if lang in chosen], "explicit"


# --- naming ----------------------------------------------------------------------------


def infer_raw_name(project: Path) -> tuple[str, str]:
    """SKILL.md's precedence: package.json, pyproject.toml, Cargo.toml, go.mod, directory."""
    package_json = project / "package.json"
    if package_json.is_file():
        try:
            name = json.loads(package_json.read_text(encoding="utf-8")).get("name")
        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            name = None
        if isinstance(name, str) and name.strip():
            return name.strip().rsplit("/", 1)[-1], "package.json"  # drop an npm @scope/
    for manifest, table in (("pyproject.toml", "project"), ("Cargo.toml", "package")):
        path = project / manifest
        if path.is_file():
            try:
                name = tomllib.loads(path.read_text(encoding="utf-8")).get(table, {}).get("name")
            except (tomllib.TOMLDecodeError, UnicodeDecodeError, AttributeError):
                name = None
            if isinstance(name, str) and name.strip():
                return name.strip(), manifest
    go_mod = project / "go.mod"
    if go_mod.is_file():
        for line in go_mod.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^\s*module\s+(\S+)", line)
            if match:
                return match.group(1).rstrip("/").rsplit("/", 1)[-1], "go.mod"
    return project.name, "directory name"


def slugify(text: str) -> str:
    """Lowercase; spaces and underscores become hyphens; anything else non-alphanumeric drops."""
    slug = re.sub(r"[\s_]+", "-", text.strip().lower())
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    return re.sub(r"-{2,}", "-", slug).strip("-")


def humanize(raw: str) -> str:
    """Turn a manifest identifier such as ``my-project`` into ``My Project``.

    A name that already reads as prose (spaces or capitals) is kept verbatim.
    """
    if re.fullmatch(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*", raw):
        return " ".join(part.capitalize() for part in re.split(r"[-_.]", raw))
    return raw


# --- generation ------------------------------------------------------------------------


def substitute(value, name: str, slug: str):
    """Replace the two placeholders inside every string of a parsed JSON document."""
    if isinstance(value, str):
        return value.replace("{{PROJECT_NAME}}", name).replace("{{PROJECT_SLUG}}", slug)
    if isinstance(value, list):
        return [substitute(item, name, slug) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, name, slug) for key, item in value.items()}
    return value


def post_create_command(project: Path, languages: list[str]) -> str:
    """Post-install once, then each language's setup command, joined with ``&&``."""
    commands = [POST_INSTALL]
    if "python" in languages and (project / "pyproject.toml").is_file():
        commands.append("rm -rf .venv && uv sync")
    if "node" in languages:
        # The template installs Node 22 through fnm, which ships corepack but not the pnpm or
        # yarn shims, so those two package managers need `corepack enable` first. It runs as
        # the container user, writes into fnm's Node directory, and honours a `packageManager`
        # pin in package.json. npm needs nothing extra.
        if (project / "pnpm-lock.yaml").is_file():
            commands += ["corepack enable", "pnpm install --frozen-lockfile"]
        elif (project / "yarn.lock").is_file():
            commands += ["corepack enable", "yarn install --frozen-lockfile"]
        elif (project / "package-lock.json").is_file():
            commands.append("npm ci")
        else:
            commands.append("npm install")
    if "rust" in languages:
        locked = (project / "Cargo.lock").is_file()
        commands.append("cargo build --locked" if locked else "cargo build")
    if "go" in languages:
        commands.append("go mod download")
    return " && ".join(commands)


def build_config(template: dict, project: Path, languages: list[str], name: str, slug: str) -> dict:
    config = substitute(template, name, slug)
    features = dict(config.get("features", {}))
    vscode = config.setdefault("customizations", {}).setdefault("vscode", {})
    extensions = list(vscode.get("extensions", []))
    settings = dict(vscode.get("settings", {}))
    for lang in languages:
        features.update(FEATURES.get(lang, {}))
        extensions.extend(ext for ext in EXTENSIONS[lang] if ext not in extensions)
        settings.update(SETTINGS[lang])
    config["features"] = features
    vscode["extensions"] = extensions
    vscode["settings"] = settings
    config["postCreateCommand"] = post_create_command(project, languages)
    return config


def render_dockerfile(text: str, name: str, slug: str, python_version: str | None) -> str:
    text = text.replace("{{PROJECT_NAME}}", name).replace("{{PROJECT_SLUG}}", slug)
    if python_version:
        text, count = PYTHON_INSTALL.subn(rf"\g<1>{python_version}\g<3>", text)
        if count != 1:
            raise ScaffoldError(
                "cannot set the Python version: expected exactly one "
                f"'RUN uv python install <version> --default' line, found {count}"
            )
        text = re.sub(
            r"# Install Python \S+ via uv", f"# Install Python {python_version} via uv", text
        )
    return text


def write_devcontainer(
    project: Path,
    target: Path,
    languages: list[str],
    name: str,
    slug: str,
    python_version: str | None,
) -> None:
    template = json.loads((RESOURCES / "devcontainer.json").read_text(encoding="utf-8"))
    config = build_config(template, project, languages, name, slug)
    target.mkdir()
    try:
        (target / "Dockerfile").write_text(
            render_dockerfile(
                (RESOURCES / "Dockerfile").read_text(encoding="utf-8"), name, slug, python_version
            ),
            encoding="utf-8",
        )
        (target / "devcontainer.json").write_text(
            json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        for static in ("post_install.py", ".zshrc", "install.sh"):
            shutil.copyfile(RESOURCES / static, target / static)
        (target / "install.sh").chmod(0o755)
        validate(target)
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise


def validate(target: Path) -> None:
    """Fail loudly on anything the skill's checklist would reject."""
    present = {path.name for path in target.iterdir()}
    missing = [name for name in OUTPUT_FILES if name not in present]
    if missing:
        raise ScaffoldError(f"missing generated file(s): {', '.join(missing)}")
    json.loads((target / "devcontainer.json").read_text(encoding="utf-8"))
    for name in OUTPUT_FILES:
        if PLACEHOLDER.search((target / name).read_text(encoding="utf-8", errors="replace")):
            raise ScaffoldError(f"unreplaced project placeholder in {name}")


# --- entry point -----------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("project_dir", nargs="?", default=".", help="project root (default: .)")
    parser.add_argument("--name", help="human-readable project name (default: inferred)")
    parser.add_argument("--slug", help="lowercase hyphenated slug for volumes (default: derived)")
    parser.add_argument(
        "--langs",
        default="auto",
        help="comma-separated subset of python,node,rust,go, or 'auto' to detect (default)",
    )
    parser.add_argument(
        "--python-version",
        help="pin a non-default Python in the Dockerfile's 'uv python install' line (e.g. 3.12)",
    )
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    project = Path(args.project_dir).resolve()
    if not project.is_dir():
        raise ScaffoldError(f"project directory not found: {args.project_dir}")
    target = project / ".devcontainer"
    if target.exists():
        raise ScaffoldError(
            f"refusing to overwrite existing {target}; modify that configuration directly instead"
        )
    if args.python_version and not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", args.python_version):
        raise ScaffoldError(f"invalid --python-version {args.python_version!r}; expected e.g. 3.12")

    languages, language_source = parse_languages(args.langs, project)
    raw_name, name_source = infer_raw_name(project)
    if args.name:
        name, name_source = args.name.strip(), "--name"
        if not name:
            raise ScaffoldError("--name must not be empty")
    else:
        name = humanize(raw_name)
    slug = args.slug if args.slug else slugify(args.name or raw_name)
    if not SLUG.fullmatch(slug):
        raise ScaffoldError(
            f"invalid project slug {slug!r}: use lowercase letters, digits, and single hyphens"
        )

    write_devcontainer(project, target, languages, name, slug, args.python_version)

    config = json.loads((target / "devcontainer.json").read_text(encoding="utf-8"))
    print(f"languages: {', '.join(languages) or 'none detected'} ({language_source})")
    print(f"name: {name} (from {name_source})")
    print(f"slug: {slug}")
    if args.python_version:
        print(f"python: {args.python_version} (Dockerfile)")
    print(f"postCreateCommand: {config['postCreateCommand']}")
    print(f"wrote {len(OUTPUT_FILES)} files to {target}: {', '.join(OUTPUT_FILES)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(parse_args(argv))
    except ScaffoldError as exc:
        print(f"scaffold.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
