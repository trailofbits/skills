"""Regression tests for CodeQL query-suite validation."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from verify_query_suite import SuiteResolutionFailure, main, resolve_queries


def _result(stdout: str, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_non_empty_suite_succeeds(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: _result('["one.ql", "two.ql"]'),
    )

    assert resolve_queries(tmp_path / "queries.qls") == ["one.ql", "two.ql"]


def test_empty_suite_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: _result("[]"))

    with pytest.raises(SuiteResolutionFailure, match="resolved zero queries"):
        resolve_queries(tmp_path / "queries.qls")


def test_empty_suite_cli_exits_nonzero(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: _result("[]"))

    assert main([str(tmp_path / "queries.qls")]) == 1


def test_codeql_failure_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: _result("", returncode=2, stderr="missing pack"),
    )

    with pytest.raises(SuiteResolutionFailure, match="missing pack"):
        resolve_queries(tmp_path / "queries.qls")


def test_malformed_output_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: _result("not json"))

    with pytest.raises(SuiteResolutionFailure, match="invalid JSON"):
        resolve_queries(tmp_path / "queries.qls")
