"""Regression coverage for complete output and existing-installation behavior."""

import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "trailmark_summary", Path(__file__).with_name("summary.py")
)
assert SPEC and SPEC.loader
summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(summary)


def mock_commands(monkeypatch, *, languages=None, version="trailmark 0.2.0\n", text=None):
    payload = {
        "languages": ["python"] if languages is None else languages,
        "summary": {"entrypoints": 2, "dependencies": ["os"], "additional_field": {"x": 1}},
    }
    text = (
        text if text is not None else "Nodes: 3\nDependencies: os\nEntrypoints: 2\nExtra: keep me\n"
    )
    payload["summary_text"] = text
    if version:
        payload["version"] = version.strip()
    if languages == []:
        payload = {"languages": [], "error": "Trailmark found no supported languages under target"}
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        output, code = "", 0
        if "--collect" in command:
            output = json.dumps(payload)
            code = 2 if payload.get("error") else 0
        elif "--summary" in command:
            output = text
        elif "--version" in command:
            output, code = version, 0 if version else 2
        return subprocess.CompletedProcess(command, code, output, "")

    monkeypatch.setattr(summary, "run", run)
    monkeypatch.setattr(summary, "python_commands", lambda *_: [[sys.executable, "-I"]])
    return payload, text, calls


def test_complete_output_and_optional_version(monkeypatch, tmp_path):
    expected, text, calls = mock_commands(monkeypatch)
    assert summary.build_summary(str(tmp_path)) == {
        **expected,
        "summary_text": text,
        "version": "trailmark 0.2.0",
    }
    assert all("install" not in command and "--with" not in command for command in calls)


def test_old_version_without_version_command(monkeypatch, tmp_path):
    expected, text, _ = mock_commands(monkeypatch, version="")
    assert summary.build_summary(str(tmp_path)) == {**expected, "summary_text": text}


def test_empty_languages_stop_before_summary(monkeypatch, tmp_path):
    expected, _, calls = mock_commands(monkeypatch, languages=[])
    assert summary.build_summary(str(tmp_path)) == expected
    assert not any("--summary" in command for command in calls)


def test_collection_failure_keeps_cause(monkeypatch, tmp_path):
    monkeypatch.setattr(summary, "python_commands", lambda *_: [[sys.executable, "-I"]])
    monkeypatch.setattr(
        summary,
        "run",
        lambda cmd: subprocess.CompletedProcess(cmd, 1, "", "broken parser dependency"),
    )
    with pytest.raises(RuntimeError, match="broken parser dependency"):
        summary.build_summary(str(tmp_path))


def test_missing_installation_does_not_resolve_packages(monkeypatch, tmp_path):
    calls = []

    def missing(command):
        calls.append(command)
        return subprocess.CompletedProcess(command, 127, "", "not found")

    monkeypatch.setattr(summary, "run", missing)
    monkeypatch.setattr(summary, "python_commands", lambda *_: [[sys.executable, "-I"]])
    with pytest.raises(RuntimeError, match="trusted existing environments.*not found"):
        summary.build_summary(str(tmp_path))
    assert len(calls) == 1 and "--collect" in calls[0]
    assert not any("uv" in call or "--with" in call for call in calls)


@pytest.mark.parametrize("location", ["current", "legacy", "missing_export"])
def test_language_api_locations(monkeypatch, location):
    api = types.ModuleType("trailmark.query.api")
    api.detect_languages = lambda target: ["python", "rust"]
    cli = types.ModuleType("trailmark.cli")
    cli._print_summary = lambda engine: print("Nodes: 3\nDependencies: \nEntrypoints: 0")
    builds = []

    class Engine:
        @classmethod
        def from_directory(cls, target, *, language):
            assert target == "source" and language == "auto"
            builds.append(target)
            return cls()

        def summary(self):
            return {"dependencies": [], "entrypoints": 0, "extra": [1, 2, 3]}

    api.QueryEngine = Engine
    monkeypatch.setitem(sys.modules, "trailmark", types.ModuleType("trailmark"))
    monkeypatch.setitem(sys.modules, "trailmark.cli", cli)
    monkeypatch.setitem(sys.modules, "trailmark.query", types.ModuleType("trailmark.query"))
    monkeypatch.setitem(sys.modules, "trailmark.query.api", api)
    parse = None if location == "legacy" else types.ModuleType("trailmark.parse")
    if location == "current":
        parse.detect_languages = lambda target: ["python", "rust"]
        api.detect_languages = lambda target: pytest.fail("legacy fallback used on current API")
    monkeypatch.setitem(sys.modules, "trailmark.parse", parse)
    assert summary.collect("source") == {
        "languages": ["python", "rust"],
        "summary": {"dependencies": [], "entrypoints": 0, "extra": [1, 2, 3]},
        "summary_text": "Nodes: 3\nDependencies: \nEntrypoints: 0\n",
    }
    assert builds == ["source"]


def test_parse_module_dependency_failure_is_not_a_legacy_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, "trailmark", types.ModuleType("trailmark"))
    cli = types.ModuleType("trailmark.cli")
    cli._print_summary = lambda _: pytest.fail("rendered after broken import")
    monkeypatch.setitem(sys.modules, "trailmark.cli", cli)

    def broken_import(name):
        assert name == "trailmark.parse"
        raise ModuleNotFoundError("missing parser dependency", name="grammar_dependency")

    monkeypatch.setattr(summary.importlib, "import_module", broken_import)
    with pytest.raises(ModuleNotFoundError, match="missing parser dependency"):
        summary.collect("source")


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ModuleNotFoundError("missing Trailmark", name="trailmark"), 3),
        (ModuleNotFoundError("missing grammar", name="grammar_dependency"), 1),
        (ImportError("broken parser import"), 1),
    ],
)
def test_collector_exit_codes_preserve_import_cause(monkeypatch, capsys, error, expected):
    def broken_collect(_):
        raise error

    monkeypatch.setattr(summary, "collect", broken_collect)
    monkeypatch.setattr(sys, "argv", ["summary.py", "--collect", "source"])
    assert summary.main() == expected
    captured = capsys.readouterr()
    assert str(error) in captured.err and captured.out == ""


def test_missing_installation_can_use_next_candidate(monkeypatch, tmp_path):
    expected, _, _ = mock_commands(monkeypatch)
    monkeypatch.setattr(summary, "python_commands", lambda *_: [["first"], ["second"]])
    calls = []

    def run(command):
        calls.append(command[0])
        if command[0] == "first":
            return subprocess.CompletedProcess(command, 3, "", "No module named 'trailmark'")
        return subprocess.CompletedProcess(command, 0, json.dumps(expected), "")

    monkeypatch.setattr(summary, "run", run)
    assert summary.build_summary(str(tmp_path)) == expected
    assert calls == ["first", "second"]


def test_all_missing_candidates_keep_import_diagnostics(monkeypatch, tmp_path):
    monkeypatch.setattr(summary, "python_commands", lambda *_: [["first"], ["second"]])
    monkeypatch.setattr(
        summary,
        "run",
        lambda cmd: subprocess.CompletedProcess(cmd, 3, "", f"{cmd[0]}: missing trailmark"),
    )
    with pytest.raises(RuntimeError, match="first: missing trailmark; second: missing trailmark"):
        summary.build_summary(str(tmp_path))


def test_collection_stdout_notices_do_not_corrupt_json(monkeypatch, tmp_path, capsys):
    expected = {"languages": ["python"], "summary": {"extra": "retain"}, "summary_text": "all"}

    def noisy_collect(_):
        print("parser progress notice")
        return expected

    monkeypatch.setattr(summary, "collect", noisy_collect)
    monkeypatch.setattr(sys, "argv", ["summary.py", "--collect", str(tmp_path)])
    assert summary.main() == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == expected
    assert "parser progress notice" in captured.err


@pytest.mark.parametrize("contents", ["empty", "unsupported", "python"])
def test_real_cli_status_and_complete_artifact(tmp_path, contents):
    if importlib.util.find_spec("trailmark") is None:
        subprocess.run(
            [
                "uv",
                "run",
                "--no-project",
                "--with",
                "trailmark>=0.5,<0.6",
                "--with",
                "pytest",
                "python",
                "-m",
                "pytest",
                str(Path(__file__).resolve()),
                "-q",
                "-k",
                "test_real_cli_status_and_complete_artifact",
            ],
            check=True,
        )
        return
    target = tmp_path / "source with spaces"
    target.mkdir()
    if contents == "unsupported":
        (target / "README.txt").write_text("no supported source code\n")
    elif contents == "python":
        (target / "app.py").write_text("import os\ndef main():\n    return os.getcwd()\n")
    artifact = tmp_path / "output with spaces" / "summary.json"
    result = subprocess.run(
        [
            sys.executable,
            str(Path(summary.__file__)),
            str(target),
            "--python",
            sys.executable,
            "--out",
            str(artifact),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == (0 if contents == "python" else 2), result.stderr
    expected = summary.collect(str(target))
    assert json.loads(result.stdout) == expected == json.loads(artifact.read_text())
    if contents != "python":
        assert expected == {
            "languages": [],
            "error": "Trailmark found no supported languages under target",
        }
        direct = subprocess.run(
            [sys.executable, str(Path(summary.__file__)), "--collect", str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert direct.returncode == 2 and json.loads(direct.stdout) == expected
    assert not (target / ".venv").exists() and not (target / "uv.lock").exists()


def test_cli_missing_target_reports_failure(tmp_path):
    result = subprocess.run(
        [sys.executable, str(Path(summary.__file__)), str(tmp_path / "missing")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1 and "target is not a directory" in result.stderr
    assert result.stdout == ""


def test_discovery_reads_copied_cli_shebang_without_executing_it(monkeypatch, tmp_path):
    trusted = tmp_path / "tools"
    trusted.mkdir()
    interpreter = trusted / "python-real"
    interpreter.write_text("not executed by discovery")
    launcher = trusted / "trailmark"
    launcher.write_text(f"#!{interpreter}\nraise RuntimeError('must not execute')\n")
    target = tmp_path / "source"
    target.mkdir()
    monkeypatch.chdir(target)
    monkeypatch.setattr(
        summary.shutil, "which", lambda name: str(launcher) if name == "trailmark" else None
    )
    assert summary.python_commands(target)[0] == [str(interpreter), "-E", "-P"]


def test_discovery_never_selects_target_environment(monkeypatch, tmp_path):
    target = tmp_path / "source"
    target.mkdir()
    binary = target / ".venv/bin"
    binary.mkdir(parents=True)
    (binary / "python").write_text("not executed")
    (binary / "trailmark").write_text(f"#!{binary}/python\nnot executed\n")
    monkeypatch.chdir(target)
    monkeypatch.setattr(summary.shutil, "which", lambda name: str(binary / name))
    commands = summary.python_commands(target)
    assert all(not Path(c[0]).is_relative_to(target) for c in commands)
    assert all(c[-2:] == ["-E", "-P"] for c in commands)
    assert not (target / "uv.lock").exists()


def test_shell_console_wrapper_is_not_used_as_a_python_interpreter(monkeypatch, tmp_path):
    tools = tmp_path / "tools with spaces"
    tools.mkdir()
    launcher = tools / "trailmark"
    launcher.write_text("#!/bin/sh\n# pip can use a shell wrapper for paths with spaces\n")
    interpreter = tools / "python"
    interpreter.write_text("not executed during discovery")
    target = tmp_path / "source"
    target.mkdir()
    monkeypatch.chdir(target)
    monkeypatch.setattr(
        summary.shutil, "which", lambda name: str(launcher) if name == "trailmark" else None
    )
    commands = summary.python_commands(target)
    assert [str(interpreter), "-E", "-P"] in commands
    assert all(Path(command[0]).name != "sh" for command in commands)


def test_out_failure_keeps_stdout_and_returns_error(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(summary, "build_summary", lambda *_: {"languages": ["python"]})
    invalid = tmp_path / "not-directory"
    invalid.write_text("unchanged")
    monkeypatch.setattr(sys, "argv", ["summary.py", str(tmp_path), "--out", str(invalid / "out")])
    assert summary.main() == 1
    assert json.loads(capsys.readouterr().out) == {"languages": ["python"]}
    assert invalid.read_text() == "unchanged"


def test_empty_target_path_rejected_before_execution(monkeypatch, tmp_path):
    monkeypatch.setattr(summary, "run", lambda *_: pytest.fail("executed for invalid target"))
    with pytest.raises(ValueError, match="not a directory"):
        summary.build_summary(str(tmp_path / "missing"))


def test_real_installed_summary_matches_native_cli(tmp_path):
    if importlib.util.find_spec("trailmark") is None:
        subprocess.run(
            [
                "uv",
                "run",
                "--no-project",
                "--with",
                "trailmark>=0.5,<0.6",
                "--with",
                "pytest",
                "python",
                "-m",
                "pytest",
                str(Path(__file__).resolve()),
                "-q",
                "-k",
                "test_real_installed_summary_matches_native_cli",
            ],
            check=True,
        )
        return
    from trailmark.query.api import QueryEngine

    (tmp_path / "app.py").write_text("import os\ndef main():\n    return os.getcwd()\n")
    result = summary.build_summary(str(tmp_path), Path(sys.executable))
    native = subprocess.run(
        [
            str(Path(sys.executable).parent / "trailmark"),
            "analyze",
            str(tmp_path),
            "--language",
            "auto",
            "--summary",
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    assert result["summary_text"] == native.stdout
    assert result["summary"] == QueryEngine.from_directory(str(tmp_path), language="auto").summary()
    assert not (tmp_path / ".venv").exists() and not (tmp_path / "uv.lock").exists()


def test_collect_missing_required_native_fields(monkeypatch, tmp_path):
    if importlib.util.find_spec("trailmark") is None:
        subprocess.run(
            [
                "uv",
                "run",
                "--no-project",
                "--with",
                "trailmark>=0.5,<0.6",
                "--with",
                "pytest",
                "python",
                "-m",
                "pytest",
                str(Path(__file__).resolve()),
                "-q",
                "-k",
                "test_collect_missing_required_native_fields",
            ],
            check=True,
        )
        return
    import trailmark.cli

    (tmp_path / "app.py").write_text("def main():\n    return 1\n")
    monkeypatch.setattr(trailmark.cli, "_print_summary", lambda *_: print("Nodes: 1"))
    with pytest.raises(RuntimeError, match="missing Entrypoints or Dependencies"):
        summary.collect(str(tmp_path))


def test_collection_ignores_project_pythonpath_and_shadow_module(monkeypatch, tmp_path):
    if importlib.util.find_spec("trailmark") is None:
        subprocess.run(
            [
                "uv",
                "run",
                "--no-project",
                "--with",
                "trailmark>=0.5,<0.6",
                "--with",
                "pytest",
                "python",
                "-m",
                "pytest",
                str(Path(__file__).resolve()),
                "-q",
                "-k",
                "test_collection_ignores_project_pythonpath_and_shadow_module",
            ],
            check=True,
        )
        return
    (tmp_path / "trailmark.py").write_text("raise RuntimeError('PROJECT MODULE EXECUTED')\n")
    (tmp_path / "app.py").write_text("def main():\n    return 1\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    result = summary.build_summary(str(tmp_path), Path(sys.executable))
    assert "Entrypoints:" in result["summary_text"] and result["summary"]["functions"] == 1
