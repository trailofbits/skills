"""Behavioral regressions for untrusted metadata and safe scaffold retries."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("scaffold", Path(__file__).with_name("scaffold.py"))
scaffold = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scaffold)


@pytest.mark.parametrize(
    "source", ["package.json", "pyproject.toml", "Cargo.toml", "directory", "explicit"]
)
@pytest.mark.parametrize(
    "name", ["Demo\nRUN printf harmless", "Demo\rRUN printf harmless", "Demo\x00Name"]
)
def test_control_characters_never_reach_output(tmp_path, capsys, source, name):
    if source == "directory" and "\x00" in name:
        # NUL cannot occur in a filesystem component; direct rendering still rejects it.
        with pytest.raises(scaffold.ScaffoldError):
            scaffold.render_dockerfile("# Project: {{PROJECT_NAME}}\n", name, "demo", None)
        return
    root = tmp_path / (name if source == "directory" else "project")
    root.mkdir()
    args = [str(root), "--langs", "", "--slug", "demo"]
    if source == "package.json":
        (root / source).write_text(json.dumps({"name": name}))
    elif source in {"pyproject.toml", "Cargo.toml"}:
        section = "project" if source == "pyproject.toml" else "package"
        escaped = json.dumps(name)
        (root / source).write_text(f"[{section}]\nname = {escaped}\n")
    elif source == "explicit":
        args += ["--name", name]
    assert scaffold.main(args) == 1
    assert "control" in capsys.readouterr().err.lower()
    assert not (root / ".devcontainer").exists()


def test_name_cannot_become_a_docker_parser_directive(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="syntax=example.invalid/frontend"\n')
    assert scaffold.main([str(tmp_path), "--slug", "safe"]) == 0
    text = (tmp_path / ".devcontainer/Dockerfile").read_text()
    assert text.startswith("# Project: syntax=example.invalid/frontend Devcontainer\n")
    assert not text.startswith("# syntax=")


def test_walk_ignores_symlinks_and_terminates_cycles(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / "loop1").symlink_to(root, target_is_directory=True)
    (root / "loop2").symlink_to(root, target_is_directory=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "unrelated.py").write_text("print('not project code')\n")
    (root / "external").symlink_to(outside, target_is_directory=True)
    original = Path.iterdir
    reads = 0

    def bounded(path):
        nonlocal reads
        reads += 1
        assert reads < 20, "directory cycle was followed"
        return original(path)

    monkeypatch.setattr(Path, "iterdir", bounded)
    assert scaffold.has_python_files(root) is False
    assert reads == 1


def test_unreadable_detection_is_explicit_and_can_be_bypassed(tmp_path, monkeypatch, capsys):
    denied = tmp_path / "private"
    denied.mkdir()
    original = Path.iterdir

    def guarded(path):
        if path == denied:
            raise PermissionError("fixture unreadable directory")
        return original(path)

    monkeypatch.setattr(Path, "iterdir", guarded)
    assert scaffold.main([str(tmp_path), "--name", "Demo"]) == 1
    message = capsys.readouterr().err
    assert "incomplete" in message and "--langs" in message
    assert not (tmp_path / ".devcontainer").exists()
    assert scaffold.main([str(tmp_path), "--langs", "", "--name", "Demo"]) == 0


def test_preview_allows_correcting_options_before_writing(tmp_path, capsys):
    (tmp_path / "package.json").write_text('{"name":"demo"}')
    assert scaffold.main([str(tmp_path), "--dry-run"]) == 0
    assert not (tmp_path / ".devcontainer").exists()
    assert "preview" in capsys.readouterr().out
    assert scaffold.main([str(tmp_path), "--name", "Corrected", "--langs", "node"]) == 0
    config = json.loads((tmp_path / ".devcontainer/devcontainer.json").read_text())
    assert config["name"] == "Corrected"


def test_python_environment_does_not_delete_host_venv(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nrequires-python=">=3.10"\n')
    host = tmp_path / ".venv"
    host.mkdir()
    (host / "sentinel").write_text("host environment")
    assert scaffold.main([str(tmp_path)]) == 0
    config = json.loads((tmp_path / ".devcontainer/devcontainer.json").read_text())
    assert "rm " not in config["postCreateCommand"]
    assert config["containerEnv"]["UV_PROJECT_ENVIRONMENT"] == "/opt/project-venv"
    assert (
        config["customizations"]["vscode"]["settings"]["python.defaultInterpreterPath"]
        == "/opt/project-venv/bin/python"
    )
    assert (host / "sentinel").read_text() == "host environment"


@pytest.mark.parametrize(
    "module", ["example.com/team/tool/v2", '"example.com/team/tool/v12"', "`example.com/team/tool`"]
)
def test_go_module_version_suffix_and_quotes(tmp_path, module):
    (tmp_path / "go.mod").write_text(f"module {module}\n\ngo 1.22\n")
    assert scaffold.infer_raw_name(tmp_path) == ("tool", "go.mod")


def test_nested_manifest_is_not_installed_at_wrong_root(tmp_path, capsys):
    nested = tmp_path / "frontend"
    nested.mkdir()
    (nested / "package.json").write_text('{"name":"frontend"}')
    assert scaffold.main([str(tmp_path), "--name", "Demo"]) == 1
    assert "package root" in capsys.readouterr().err
    assert not (tmp_path / ".devcontainer").exists()


def test_configs_without_root_packages_do_not_get_package_install_commands(tmp_path):
    (tmp_path / "tsconfig.json").write_text("{}")
    (tmp_path / "go.sum").write_text("")
    assert scaffold.main([str(tmp_path), "--name", "Demo"]) == 0
    config = json.loads((tmp_path / ".devcontainer/devcontainer.json").read_text())
    assert config["postCreateCommand"] == scaffold.POST_INSTALL


def test_corepack_uses_explicit_noninteractive_invocation(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"demo"}')
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    command = scaffold.post_create_command(tmp_path, ["node"])
    assert "COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm install --frozen-lockfile" in command
    assert "corepack enable" not in command


@pytest.mark.parametrize(
    "name", ["Demo\nRUN harmless", "Demo\rRUN harmless", "Demo\x00Name", "Demo\u2028Name"]
)
def test_go_quoted_module_control_characters_are_rejected(tmp_path, capsys, name):
    (tmp_path / "go.mod").write_text("module " + json.dumps(name) + "\n")
    assert scaffold.main([str(tmp_path), "--slug", "safe"]) == 1
    assert "control" in capsys.readouterr().err
    assert not (tmp_path / ".devcontainer").exists()


def test_safe_explicit_name_bypasses_invalid_inference(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text(json.dumps({"name": "Bad\nRUN harmless"}))

    def unexpected_inference(_):
        raise AssertionError("an explicit name must not depend on inferred naming")

    monkeypatch.setattr(scaffold, "infer_raw_name", unexpected_inference)
    assert scaffold.main([str(tmp_path), "--name", "Safe Name"]) == 0
    config = json.loads((tmp_path / ".devcontainer/devcontainer.json").read_text())
    assert config["name"] == "Safe Name"
    assert "source=safe-name-config-" in "\n".join(config["mounts"])
    assert (tmp_path / ".devcontainer/Dockerfile").read_text().startswith("# Project: Safe Name ")
