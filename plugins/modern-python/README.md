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

This plugin includes a `SessionStart` hook that prepends PATH shims for `python`, `pip`, `pipx`, and `uv`. When Claude runs a bare `python`, `pip`, or `pipx` command, the shell resolves to the shim, which prints an error with the correct `uv` alternative and exits non-zero. The suggested alternative always uses the exact command name `python` (never `python3`) so it also works outside a project; see the header comment in [`hooks/shims/python`](hooks/shims/python) for the full rationale.

The shims sit on PATH, so they see every subprocess a tool spawns, not only what Claude types. That is why the intercepted set is narrow: it covers the invocations `uv run` and `uv add` genuinely replace, and passes the rest through to the real binary. `python -c`, `python -m <module>` and `python -` read a program from the command line, an installed module, or stdin, so none of them resolves a script against a project's dependencies; `uv pip` carrying `--project`, `--directory` or `--target` is a tool building an environment it owns. Redirecting those broke real tooling, including `prek` hook installation and any script piping into `python3 -` ([#207](https://github.com/trailofbits/skills/issues/207)).

| Intercepted Command | Suggested Alternative |
|---------------------|----------------------|
| `python ...` | `uv run python ...` |
| `python -m pip` | `uv add`/`uv remove` |
| `pip install pkg` | `uv add pkg` or `uv run --with pkg` |
| `pip uninstall pkg` | `uv remove pkg` |
| `pip freeze` | `uv export` |
| `uv pip ...` | `uv add`/`uv remove`/`uv sync` |
| *(passed through)* | `python -c`, `python -m <module>`, `python -`, and `uv pip` with `--project`, `--directory` or `--target` |
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
