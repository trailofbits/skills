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
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        output, code = "", 0
        if "--collect" in command:
            output = json.dumps(payload)
        elif "--summary" in command:
            output = text
        elif "--version" in command:
            output, code = version, 0 if version else 2
        return subprocess.CompletedProcess(command, code, output, "")

    monkeypatch.setattr(summary.subprocess, "run", run)
    return payload, text, calls


def test_complete_output_and_optional_version(monkeypatch):
    expected, text, calls = mock_commands(monkeypatch)
    assert summary.build_summary("target with spaces") == {
        **expected,
        "summary_text": text,
        "version": "trailmark 0.2.0",
    }
    assert all("install" not in command and "--with" not in command for command in calls)


def test_old_version_without_version_command(monkeypatch):
    expected, text, _ = mock_commands(monkeypatch, version="")
    assert summary.build_summary("target") == {**expected, "summary_text": text}


def test_empty_languages_stop_before_summary(monkeypatch):
    expected, _, calls = mock_commands(monkeypatch, languages=[])
    assert summary.build_summary("target") == expected
    assert not any("--summary" in command for command in calls)


def test_missing_required_output_is_reported(monkeypatch):
    mock_commands(monkeypatch, text="Nodes: 3\n")
    with pytest.raises(RuntimeError, match="missing Entrypoints or Dependencies"):
        summary.build_summary("target")


def test_missing_installation_does_not_resolve_packages(monkeypatch):
    calls = []

    def missing(command):
        calls.append(command)
        return subprocess.CompletedProcess(command, 127, "", "not found")

    monkeypatch.setattr(summary, "run", missing)
    with pytest.raises(RuntimeError, match="trailmark is not installed"):
        summary.build_summary("target")
    assert calls == [
        ["trailmark", "analyze", "--help"],
        ["uv", "run", "--no-sync", "trailmark", "analyze", "--help"],
    ]


@pytest.mark.parametrize("legacy", [False, True])
def test_language_api_locations(monkeypatch, legacy):
    api = types.ModuleType("trailmark.query.api")
    api.detect_languages = lambda target: ["python", "rust"]

    class Engine:
        @classmethod
        def from_directory(cls, target, *, language):
            assert target == "source" and language == "auto"
            return cls()

        def summary(self):
            return {"dependencies": [], "entrypoints": 0, "extra": [1, 2, 3]}

    api.QueryEngine = Engine
    monkeypatch.setitem(sys.modules, "trailmark", types.ModuleType("trailmark"))
    monkeypatch.setitem(sys.modules, "trailmark.query", types.ModuleType("trailmark.query"))
    monkeypatch.setitem(sys.modules, "trailmark.query.api", api)
    parse = None if legacy else api
    monkeypatch.setitem(sys.modules, "trailmark.parse", parse)
    assert summary.collect("source") == {
        "languages": ["python", "rust"],
        "summary": {"dependencies": [], "entrypoints": 0, "extra": [1, 2, 3]},
    }
