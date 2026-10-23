# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
import tomllib
from hashlib import sha256
from pathlib import Path
from typing import Any

from calcifier import (
    Budget,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    recipe,
    resource,
    run_command,
    step,
    verify_artifact,
    write_text,
)

FILES = ("Dockerfile", "devcontainer.json", "post_install.py", ".zshrc", "install.sh")
MANIFESTS = [
    "package.json",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "go.sum",
    "tsconfig.json",
    "requirements.txt",
    "setup.py",
    "pnpm-lock.yaml",
    "yarn.lock",
    "package-lock.json",
    "Cargo.lock",
]
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


@output_type
class Decision:
    blocker: str
    python_version: str


@step
def inspect_project(root: Path, name_override: str) -> dict[str, Any]:
    present = [name for name in MANIFESTS if (root / name).is_file()]
    for name in present:
        if not (root / name).resolve().is_relative_to(root):
            fail(f"Project input escapes the project directory: {name}")
    texts = {
        name: (root / name).read_text(encoding="utf-8")
        for name in ("package.json", "pyproject.toml", "Cargo.toml", "go.mod")
        if name in present
    }
    package = json.loads(texts.get("package.json", "{}"))
    python = tomllib.loads(texts.get("pyproject.toml", ""))
    cargo = tomllib.loads(texts.get("Cargo.toml", ""))
    module = re.search(r"(?m)^\s*module\s+(\S+)", texts.get("go.mod", ""))
    names = [package.get("name"), python.get("project", {}).get("name")]
    names += [cargo.get("package", {}).get("name")]
    names += [module[1].strip('"').rsplit("/", 1)[-1] if module else None, root.name]
    name = name_override or next(x for x in names if isinstance(x, str) and x.strip())
    slug = name.lower().replace(" ", "-").replace("_", "-")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", slug):
        fail("Inferred volume slug is invalid; supply a Docker-compatible project_name.")
    detected = {
        "python": any(x in present for x in ("pyproject.toml", "requirements.txt", "setup.py"))
        or any(path.is_file() for path in root.rglob("*.py")),
        "node": any(x in present for x in ("package.json", "tsconfig.json")),
        "rust": "Cargo.toml" in present,
        "go": any(x in present for x in ("go.mod", "go.sum")),
    }
    languages = [language for language, found in detected.items() if found]
    return {"name": name, "slug": slug, "present": present, "languages": languages}


def json_object(text: str) -> dict[str, Any]:
    quoted = r'"(?:\\.|[^"\\])*"'
    comments = "(" + quoted + r")|//[^\r\n]*|/\*.*?\*/"
    text = re.sub(comments, lambda match: match[1] or "", text, flags=re.S)
    commas = "(" + quoted + r")|,\s*([}\]])"
    text = re.sub(commas, lambda match: match[1] or match[2], text)
    value = json.loads(text)
    if not isinstance(value, dict):
        fail("The devcontainer template must contain a JSON object.")
    return value


def merge(target: dict[str, Any], additions: dict[str, Any]) -> None:
    for key, value in additions.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            merge(target[key], value)
        else:
            target[key] = value


def setup_commands(facts: dict[str, Any]) -> list[str]:
    languages, present = facts["languages"], facts["present"]
    commands = []
    if "python" in languages and "pyproject.toml" in present:
        commands += ["rm -rf .venv", "uv sync"]
    commands.append("uv run /opt/post_install.py")
    if "node" in languages:
        choices = (
            ("pnpm-lock.yaml", "pnpm install --frozen-lockfile"),
            ("yarn.lock", "yarn install --frozen-lockfile"),
            ("package-lock.json", "npm ci"),
        )
        commands.append(next((cmd for lock, cmd in choices if lock in present), "npm install"))
    if "rust" in languages:
        commands.append("cargo build --locked" if "Cargo.lock" in present else "cargo build")
    if "go" in languages:
        commands.append("go mod download")
    return commands


@step
def render_files(templates: dict[str, str], facts: dict[str, Any], version: str) -> dict[str, str]:
    rendered = {}
    for name, text in templates.items():
        human, slug = facts["name"], facts["slug"]
        if name == "devcontainer.json":
            human, slug = json.dumps(human)[1:-1], json.dumps(slug)[1:-1]
        rendered[name] = text.replace("{{PROJECT_NAME}}", human).replace("{{PROJECT_SLUG}}", slug)
    config = json_object(rendered["devcontainer.json"])
    vscode = config.setdefault("customizations", {}).setdefault("vscode", {})
    extensions = vscode.setdefault("extensions", [])
    settings = vscode.setdefault("settings", {})
    for language in facts["languages"]:
        extensions.extend(x for x in EXTENSIONS[language] if x not in extensions)
        merge(settings, SETTINGS[language])
    features, mounts = config.setdefault("features", {}), config.setdefault("mounts", [])
    for language, target in (("rust", "/home/vscode/.cargo"), ("go", "/home/vscode/go")):
        if language in facts["languages"]:
            options = {"version": "latest"} if language == "go" else {}
            features.setdefault(f"ghcr.io/devcontainers/features/{language}:1", options)
            purpose = "cargo" if language == "rust" else "go"
            volume = f"source={facts['slug']}-{purpose}-$" + "{devcontainerId}"
            mount = f"{volume},target={target},type=volume"
            if mount not in mounts:
                mounts.append(mount)
    config["postCreateCommand"] = " && ".join(setup_commands(facts))
    rendered["devcontainer.json"] = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    if version:
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
            fail("The selected Python version must be a numeric major.minor or major.minor.patch.")
        rendered["Dockerfile"], count = re.subn(
            r"(\buv\s+python\s+install\s+)[^\s\\;&|]+",
            lambda match: match[1] + version,
            rendered["Dockerfile"],
        )
        if count != 1:
            fail("Cannot unambiguously locate the template's uv Python installation.")

    if not rendered or set(rendered) != set(FILES):
        fail("Validation requires all five output files; the inspection scope is incomplete.")
    for name, text in rendered.items():
        tokens = ("{{PROJECT_NAME}}", "{{PROJECT_SLUG}}")
        if not text.strip() or any(token in text for token in tokens):
            fail(f"Empty output or unresolved project placeholder in {name}.")
    config = json.loads(rendered["devcontainer.json"])
    extensions = config["customizations"]["vscode"]["extensions"]
    for language in facts["languages"]:
        if not set(EXTENSIONS[language]).issubset(extensions):
            fail(f"Required {language} extensions are missing.")
    if config.get("postCreateCommand") != " && ".join(setup_commands(facts)):
        fail("postCreateCommand does not chain all required setup commands.")
    return rendered


@recipe(output_root=".", agents=("worker",), capabilities=("Bash",), budget=Budget(2, 3600))
def devcontainer_setup(project_name: str = "", request: str = "") -> list[str]:
    root = Path.cwd().resolve()
    if (root / ".devcontainer").exists() or (root / ".devcontainer").is_symlink():
        fail("A devcontainer already exists; this skill only creates new configurations.")
    facts = inspect_project(root, project_name)
    assets = {name: resource("resources/" + name) for name in FILES}
    references = (
        resource("references/dockerfile-best-practices.md"),
        resource("references/features-vs-dockerfile.md"),
    )
    templates = {name: path.read_text(encoding="utf-8") for name, path in assets.items()}
    decision = agent(
        "worker",
        "Follow the original skill's ordered reasoning for this whole project. Understand "
        "the complete listed templates/scripts and both references; use embedded text "
        "directly and read backing files when absent. Interpret Python compatibility and "
        "ambiguities. Set blocker to an explanation if unresolved, otherwise ''. Return a "
        "numeric Python version only to change the base, otherwise ''. Python applies "
        "names, all languages, settings, volumes, and setup commands, then validates and "
        "writes files. Do not write or claim later checks. Facts: {facts}\n"
        "Request: {request}\nResources: {files}",
        facts=json.dumps(facts),
        request=request,
        files=json.dumps([str(path) for path in (*assets.values(), *references)]),
        working_directory=root,
        readable_paths=(root, *assets.values(), *references),
        output=Decision,
    )
    if decision.blocker:
        fail(decision.blocker)
    rendered = render_files(templates, facts, decision.python_version)
    destination = ensure_directory(".devcontainer", output_files=FILES)
    if destination.parent.resolve() != root:
        fail("Run with the output root set to the current project directory.")
    for name in FILES:
        write_text(destination / name, rendered[name])
    result = run_command(
        ["chmod", "u+x", str(destination / "install.sh")],
        working_directory=root,
        timeout_seconds=10,
        mutating=True,
    )
    if result.exit_code:
        fail("Could not make the CLI helper executable: " + result.stderr)
    for name in FILES:
        verify_artifact(destination / name, sha256=sha256(rendered[name].encode()).hexdigest())
    instructions = [
        "Open in VS Code and select 'Reopen in Container'",
        "Alternative: devcontainer up --workspace-folder .",
        "Run .devcontainer/install.sh self-install to add the devc command to PATH",
    ]
    emit(instructions, name="instructions")
    return emit([str(destination / name) for name in FILES], name="devcontainer-files")


if __name__ == "__main__":
    raise SystemExit(devcontainer_setup.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("ef698feec8a76cf89f283c07632a2ce92378cb34e030f6c2ca13f312a7393e39"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/dockerfile-best-practices.md",
        "sha256": ("78b9bdb7a9596f849ae69fec3042d6c3e6b65e0f3aea953e7656b89b7efedb1c"),
        "size": 3341,
        "source": None,
    },
    {
        "path": "references/features-vs-dockerfile.md",
        "sha256": ("999ac17d8f0172fce5fb00906190a97980b6a1c94d42b4046255992a9aa8c88d"),
        "size": 675,
        "source": None,
    },
    {
        "path": "resources/.zshrc",
        "sha256": ("0788e061b87afde6d0e7243e1aa2b93952c1fcdc82125278f5ac503142a5bec2"),
        "size": 1869,
        "source": None,
    },
    {
        "path": "resources/Dockerfile",
        "sha256": ("2092f264ab86c8d1b908edce6f2b475ee85d5194f4bad4b408ab9aa11fc5ab46"),
        "size": 3885,
        "source": None,
    },
    {
        "path": "resources/devcontainer.json",
        "sha256": ("0d3140742a2196b2f2eba1a756cb568c2732f9f09465dec2d9397aef7793e42f"),
        "size": 2584,
        "source": None,
    },
    {
        "path": "resources/install.sh",
        "sha256": ("022c145aef7e3890203f362460d87159b04f0835866d4610f32f1627de426822"),
        "size": 23116,
        "source": None,
    },
    {
        "path": "resources/post_install.py",
        "sha256": ("7d37aabd6a6421df6ab6448548e852e5b42d3b3d2b2aa39c9d17c4ea40543419"),
        "size": 8606,
        "source": None,
    },
]
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, target-version py311, and line-length 100. The g"
        "enerated recipe must satisfy those checks, including B007,"
        " B905, and SIM102. Keep the Python 3.13 minimum required b"
        "y Calcifier in its generated PEP 723 header. This skill is"
        " distributed independently: do not require another unmerge"
        "d skill recipe. Referenced prose and explicitly provided r"
        "esources may be packaged, while the generated recipe belon"
        "gs only to the requested skill. Repository contribution ru"
        "le: a checker that inspects zero items must fail with an e"
        "xplanation rather than return a successful clean report. T"
        "his applies to an empty inspection scope, not to a complet"
        "ed inspection that finds zero issues."
    ),
    "sha256": ("12c73b0662a6bdb615688c499f4e3e22540e4788549e5ad24bb7e01f76c25fcc"),
}
_CALCIFIER_SUBRECIPES = []
