"""Invocation contracts accept official executable names and retain mode checks."""

from __future__ import annotations

import pytest

from activation import invocation


@pytest.mark.parametrize("name", ["psalm", "psalm.phar", "psalm-1.2.3.phar"])
def test_native_psalm_names_preserve_interpreter_and_args(name: str) -> None:
    argv = ["php", "-d", "memory_limit=2G", name, "--taint-analysis"]
    executable, args = invocation("psalm", argv)
    assert executable == argv[:4]
    assert args == ["--taint-analysis"]


@pytest.mark.parametrize("name", ["psalm-custom.phar", "not-psalm.phar", "psalm-6.bad.phar"])
def test_psalm_names_stay_bound_to_selected_executable(name: str) -> None:
    with pytest.raises(ValueError, match="does not match"):
        invocation("psalm", ["php", name, "--taint-analysis"])
