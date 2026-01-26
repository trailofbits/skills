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

## Installation

```
/plugin install trailofbits/skills/plugins/modern-python
```
