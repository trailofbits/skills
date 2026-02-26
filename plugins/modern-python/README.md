# Modern Python

Modern Python tooling and best practices using uv, ruff, ty, and pytest. Based on patterns from [trailofbits/cookiecutter-python](https://github.com/trailofbits/cookiecutter-python).

**Author:** William Tan

## When to Use

- Setting up a new Python project with modern, fast tooling
- Replacing pip/virtualenv with uv for faster dependency management
- Replacing flake8/black/isort with ruff for unified linting and formatting
- Replacing mypy with ty for faster type checking
- Adding pre-commit hooks and security scanning to an existing project

## What It Covers

**Core Tools:**
- **uv** - Package/dependency management (replaces pip, virtualenv, pip-tools, pipx, pyenv)
- **ruff** - Linting and formatting (replaces flake8, black, isort, pyupgrade)
- **ty** - Type checking (replaces mypy, pyright)
- **pytest** - Testing with coverage enforcement
- **prek** - Pre-commit hooks (replaces pre-commit)

**Security Tools:**
- **shellcheck** - Shell script linting
- **detect-secrets** - Secret detection in commits
- **actionlint** - GitHub Actions syntax validation
- **zizmor** - GitHub Actions security audit
- **pip-audit** - Dependency vulnerability scanning
- **Dependabot** - Automated dependency updates with supply chain protection

**Standards:**
- **pyproject.toml** - Single configuration file with dependency groups (PEP 735)
- **PEP 723** - Inline script metadata for single-file scripts
- **src/ layout** - Standard package structure
- **Python 3.11+** - Minimum version requirement

## Hook: Legacy Command Interception

This plugin includes a `SessionStart` hook that prepends PATH shims for `python`, `pip`, `pipx`, and `uv`. When Claude runs a bare `python`, `pip`, or `pipx` command, the shell resolves to the shim, which prints an error with the correct `uv` alternative and exits non-zero. `uv run` is unaffected because it prepends its managed virtualenv's `bin/` to PATH, shadowing the shims.

| Intercepted Command | Suggested Alternative |
|---------------------|----------------------|
| `python ...` | `uv run python ...` |
| `python -m module` | `uv run python -m module` |
| `python -m pip` | `uv add`/`uv remove` |
| `pip install pkg` | `uv add pkg` or `uv run --with pkg` |
| `pip uninstall pkg` | `uv remove pkg` |
| `pip freeze` | `uv export` |
| `uv pip ...` | `uv add`/`uv remove`/`uv sync` |
| `pipx install <pkg>` | `uv tool install <pkg>` |
| `pipx run <pkg>` | `uvx <pkg>` |
| `pipx uninstall <pkg>` | `uv tool uninstall <pkg>` |
| `pipx upgrade <pkg>` | `uv tool upgrade <pkg>` |
| `pipx upgrade-all` | `uv tool upgrade --all` |
| `pipx ensurepath` | `uv tool update-shell` |
| `pipx inject <pkg> <dep>` | `uv tool install --with <dep> <pkg>` |
| `pipx list` | `uv tool list` |

Commands like `grep python`, `which python`, and `cat python.txt` work normally because `python` is a shell argument, not the command being invoked.

## Installation

```
/plugin install trailofbits/skills/plugins/modern-python
```
