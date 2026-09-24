"""Tests for scaffold.py: every rule in SKILL.md's language sections, plus the guard rails."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
RESOURCES = SCRIPTS.parent / "resources"
SPEC = importlib.util.spec_from_file_location("scaffold", SCRIPTS / "scaffold.py")
scaffold = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scaffold)

POST = "uv run --no-project /opt/post_install.py"
TEMPLATE = json.loads((RESOURCES / "devcontainer.json").read_text())


def project(tmp_path: Path, *files: str, **contents: str) -> Path:
    root = tmp_path / "proj"
    root.mkdir(parents=True)
    for name in files:
        (root / name).write_text("fixture\n")
    for name, text in contents.items():
        (root / name.replace("__", ".")).write_text(text)
    return root


def run(root: Path, *extra: str, capsys=None) -> dict:
    assert scaffold.main([str(root), *extra]) == 0
    return json.loads((root / ".devcontainer" / "devcontainer.json").read_text())


def test_static_files_are_byte_identical_and_install_is_executable(tmp_path):
    root = project(tmp_path, "go.mod")
    run(root, "--name", "Demo", "--slug", "demo")
    target = root / ".devcontainer"
    assert sorted(p.name for p in target.iterdir()) == sorted(scaffold.OUTPUT_FILES)
    for name in ("post_install.py", ".zshrc", "install.sh"):
        assert (target / name).read_bytes() == (RESOURCES / name).read_bytes()
    assert os.access(target / "install.sh", os.X_OK)


def test_placeholders_are_replaced_everywhere(tmp_path):
    root = project(tmp_path)
    config = run(root, "--name", "My Project", "--slug", "my-project")
    dockerfile = (root / ".devcontainer" / "Dockerfile").read_text()
    assert dockerfile.startswith("# My Project Devcontainer\n")
    assert "{{PROJECT_" not in dockerfile
    assert config["name"] == "My Project"
    assert "source=my-project-config-${devcontainerId}" in "\n".join(config["mounts"])
    assert "{{PROJECT_" not in json.dumps(config)


def test_base_template_is_preserved_apart_from_the_merged_keys(tmp_path):
    root = project(tmp_path, "package.json", "package-lock.json")
    config = run(root, "--name", "Demo", "--slug", "demo")
    expected = scaffold.substitute(TEMPLATE, "Demo", "demo")
    for key in ("$schema", "build", "runArgs", "init", "mounts", "containerEnv", "remoteEnv"):
        assert config[key] == expected[key], key
    assert config["features"] == expected["features"]  # Node adds no feature
    assert "--cap-add=NET_ADMIN" in config["runArgs"] and "SYS_ADMIN" not in json.dumps(config)
    assert any(".devcontainer,type=bind,readonly" in m for m in config["mounts"])


@pytest.mark.parametrize(
    ("files", "langs", "expected_post"),
    [
        (("pyproject.toml",), "python", f"{POST} && rm -rf .venv && uv sync"),
        (("requirements.txt",), "python", POST),  # no pyproject: no uv sync
        (
            ("package.json", "pnpm-lock.yaml"),
            "node",
            f"{POST} && corepack enable && pnpm install --frozen-lockfile",
        ),
        (
            ("package.json", "yarn.lock"),
            "node",
            f"{POST} && corepack enable && yarn install --frozen-lockfile",
        ),
        (("package.json", "package-lock.json"), "node", f"{POST} && npm ci"),
        (("package.json",), "node", f"{POST} && npm install"),
        (("Cargo.toml", "Cargo.lock"), "rust", f"{POST} && cargo build --locked"),
        (("Cargo.toml",), "rust", f"{POST} && cargo build"),
        (("go.mod",), "go", f"{POST} && go mod download"),
    ],
)
def test_post_create_command_per_language(tmp_path, files, langs, expected_post):
    root = project(tmp_path, *files)
    config = run(root, "--name", "Demo", "--slug", "demo", "--langs", langs)
    assert config["postCreateCommand"] == expected_post


def test_corepack_only_for_pnpm_and_yarn(tmp_path):
    npm = project(tmp_path / "npm", "package.json", "package-lock.json")
    assert "corepack" not in run(npm, "--name", "Demo", "--slug", "demo")["postCreateCommand"]
    pnpm = project(tmp_path / "pnpm", "package.json", "pnpm-lock.yaml")
    command = run(pnpm, "--name", "Demo", "--slug", "demo")["postCreateCommand"]
    assert command.count("corepack enable") == 1
    assert command.index("corepack enable") < command.index("pnpm install")


def test_language_additions_match_skill_sections(tmp_path):
    root = project(tmp_path, "pyproject.toml", "package.json", "Cargo.toml", "go.mod")
    config = run(root, "--name", "Demo", "--slug", "demo", "--langs", "go,rust,node,python")
    vscode = config["customizations"]["vscode"]
    assert vscode["extensions"] == [
        "anthropic.claude-code",
        "ms-python.python",
        "ms-python.vscode-pylance",
        "charliermarsh.ruff",
        "dbaeumer.vscode-eslint",
        "esbenp.prettier-vscode",
        "rust-lang.rust-analyzer",
        "tamasfe.even-better-toml",
        "golang.go",
    ]
    settings = vscode["settings"]
    assert settings["python.defaultInterpreterPath"] == ".venv/bin/python"
    assert settings["[python]"]["editor.defaultFormatter"] == "charliermarsh.ruff"
    assert settings["editor.defaultFormatter"] == "esbenp.prettier-vscode"
    assert settings["editor.codeActionsOnSave"] == {"source.fixAll.eslint": "explicit"}
    assert settings["[rust]"] == {"editor.defaultFormatter": "rust-lang.rust-analyzer"}
    assert settings["[go]"] == {"editor.defaultFormatter": "golang.go"}
    assert settings["go.useLanguageServer"] is True
    assert settings["terminal.integrated.defaultProfile.linux"] == "zsh"  # template kept
    assert config["features"] == {
        "ghcr.io/devcontainers/features/github-cli:1": {},
        "ghcr.io/devcontainers/features/rust:1": {},
        "ghcr.io/devcontainers/features/go:1": {"version": "latest"},
    }
    # Multi-language order is Python, Node, Rust, Go whatever order the caller used.
    assert config["postCreateCommand"] == (
        f"{POST} && rm -rf .venv && uv sync && npm install && cargo build && go mod download"
    )


def test_auto_detection_follows_the_detection_table(tmp_path):
    root = project(tmp_path, "tsconfig.json", "go.sum", "Cargo.toml")
    (root / "src").mkdir()
    (root / "src" / "tool.py").write_text("print()\n")
    assert scaffold.detect_languages(root) == ["python", "node", "rust", "go"]
    hidden_only = project(tmp_path / "h")
    (hidden_only / ".venv").mkdir()
    (hidden_only / ".venv" / "x.py").write_text("")
    (hidden_only / "node_modules").mkdir()
    (hidden_only / "node_modules" / "y.py").write_text("")
    assert scaffold.detect_languages(hidden_only) == []


@pytest.mark.parametrize(
    ("contents", "expected_name", "expected_slug", "source"),
    [
        (
            {"package.json": '{"name": "@acme/full-stack-example"}'},
            "Full Stack Example",
            "full-stack-example",
            "package.json",
        ),
        (
            {"pyproject.toml": '[project]\nname = "data_tool"\n'},
            "Data Tool",
            "data-tool",
            "pyproject.toml",
        ),
        (
            {"Cargo.toml": '[package]\nname = "fastcrate"\nversion = "0.1.0"\n'},
            "Fastcrate",
            "fastcrate",
            "Cargo.toml",
        ),
        (
            {"go.mod": "module github.com/acme/svc-gateway\n\ngo 1.22\n"},
            "Svc Gateway",
            "svc-gateway",
            "go.mod",
        ),
        ({}, "Proj", "proj", "directory name"),
    ],
)
def test_name_inference_precedence(
    tmp_path, contents, expected_name, expected_slug, source, capsys
):
    root = project(tmp_path)
    for name, text in contents.items():
        (root / name).write_text(text)
    assert scaffold.infer_raw_name(root)[1] == source
    run(root)
    out = capsys.readouterr().out
    assert f"name: {expected_name} (from {source})" in out
    assert f"slug: {expected_slug}" in out


def test_package_json_wins_over_pyproject(tmp_path):
    root = project(tmp_path)
    (root / "package.json").write_text('{"name": "web-app"}')
    (root / "pyproject.toml").write_text('[project]\nname = "api"\n')
    assert scaffold.infer_raw_name(root) == ("web-app", "package.json")


def test_humanize_and_slugify():
    assert scaffold.humanize("my-project") == "My Project"
    assert scaffold.humanize("My Project") == "My Project"
    assert scaffold.humanize("MyProject") == "MyProject"
    assert scaffold.slugify("My Project_v2") == "my-project-v2"
    assert scaffold.slugify("  Spaces  and__underscores ") == "spaces-and-underscores"
    assert scaffold.slugify("weird!!name") == "weirdname"


def test_explicit_name_derives_slug_and_slug_can_be_overridden(tmp_path, capsys):
    root = project(tmp_path, "go.mod")
    run(root, "--name", "Full Stack Example")
    assert "slug: full-stack-example" in capsys.readouterr().out
    other = project(tmp_path / "o", "go.mod")
    config = run(other, "--slug", "custom-slug")
    assert "source=custom-slug-config-${devcontainerId}" in "\n".join(config["mounts"])
    assert config["name"] == "Proj"


def test_python_version_pin_edits_exactly_the_install_line(tmp_path):
    root = project(tmp_path, "pyproject.toml")
    run(root, "--name", "Demo", "--slug", "demo", "--python-version", "3.12")
    dockerfile = (root / ".devcontainer" / "Dockerfile").read_text()
    assert dockerfile.count("RUN uv python install 3.12 --default") == 1
    assert "RUN uv python install 3.13" not in dockerfile
    template = (RESOURCES / "Dockerfile").read_text()
    changed = [
        (a, b)
        for a, b in zip(template.splitlines(), dockerfile.splitlines(), strict=True)
        if a != b
    ]
    assert {b for _, b in changed} == {
        "# Demo Devcontainer",
        "# Install Python 3.12 via uv (fast binary download, not source compilation)",
        "RUN uv python install 3.12 --default",
    }


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--name", "Demo", "--slug", "Bad_Slug"], "invalid project slug"),
        (["--name", "Demo", "--slug", "demo", "--langs", "cobol"], "unknown language"),
        (
            ["--name", "Demo", "--slug", "demo", "--python-version", "latest"],
            "invalid --python-version",
        ),
        (["--name", "  "], "--name must not be empty"),
    ],
)
def test_rejects_bad_arguments_without_writing(tmp_path, args, message, capsys):
    root = project(tmp_path, "go.mod")
    assert scaffold.main([str(root), *args]) == 1
    assert message in capsys.readouterr().err
    assert not (root / ".devcontainer").exists()


def test_refuses_to_overwrite_an_existing_devcontainer(tmp_path, capsys):
    root = project(tmp_path, "go.mod")
    (root / ".devcontainer").mkdir()
    (root / ".devcontainer" / "devcontainer.json").write_text("{}")
    assert scaffold.main([str(root), "--name", "Demo", "--slug", "demo"]) == 1
    assert "refusing to overwrite" in capsys.readouterr().err
    assert (root / ".devcontainer" / "devcontainer.json").read_text() == "{}"


def test_missing_project_dir_is_an_error(tmp_path, capsys):
    assert scaffold.main([str(tmp_path / "nope")]) == 1
    assert "project directory not found" in capsys.readouterr().err


def test_partial_output_is_removed_when_generation_fails(tmp_path, monkeypatch):
    root = project(tmp_path, "go.mod")

    def boom(*_args, **_kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(scaffold, "validate", boom)
    with pytest.raises(RuntimeError):
        scaffold.run(scaffold.parse_args([str(root), "--name", "Demo", "--slug", "demo"]))
    assert not (root / ".devcontainer").exists()


def test_validate_catches_a_leftover_placeholder(tmp_path):
    target = tmp_path / ".devcontainer"
    target.mkdir()
    for name in scaffold.OUTPUT_FILES:
        (target / name).write_text("{}\n" if name.endswith(".json") else "ok\n")
    scaffold.validate(target)
    (target / "Dockerfile").write_text("# {{PROJECT_NAME}} Devcontainer\n")
    with pytest.raises(scaffold.ScaffoldError, match="unreplaced project placeholder"):
        scaffold.validate(target)
    (target / "Dockerfile").unlink()
    with pytest.raises(scaffold.ScaffoldError, match="missing generated file"):
        scaffold.validate(target)


def test_inputs_are_left_untouched(tmp_path):
    root = project(tmp_path)
    (root / "package.json").write_text('{"name": "demo", "private": true}\n')
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    run(root)
    after = {p.name: p.read_bytes() for p in root.iterdir() if p.name != ".devcontainer"}
    assert after == before
