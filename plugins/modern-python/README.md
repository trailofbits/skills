# Modern Python

Modern Python tooling and best practices using uv, ruff, and pytest. Based on patterns from [trailofbits/cookiecutter-python](https://github.com/trailofbits/cookiecutter-python).

**Author:** William Tan

## When to Use

Use this skill when you need to:
- Set up a new Python project with modern tooling
- Migrate an existing project from legacy tools (pip, flake8, black)
- Configure `pyproject.toml` with dependency groups
- Set up `uv` for package and dependency management
- Configure `ruff` for linting and formatting
- Set up `pytest` with coverage enforcement
- Write simple scripts with PEP 723 inline metadata

## What It Does

This skill provides guidance on:
- **uv** - Fast package/dependency management (replaces pip, virtualenv, pip-tools, pipx, pyenv)
- **pyproject.toml** - Single configuration file with dependency-groups
- **ruff** - Linting AND formatting (replaces flake8, black, isort, pyupgrade)
- **ty** - Fast type checking from Astral
- **pytest** - Testing with coverage enforcement
- **PEP 723** - Inline script metadata for single-file scripts
- **src/ layout** - Standard package structure
- **Python 3.11+** - Minimum version requirement

## Installation

```
/plugin install trailofbits/skills/plugins/modern-python
```
