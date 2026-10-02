---
name: devcontainer-setup
description: Creates devcontainers with Claude Code, language-specific tooling (Python/Node/Rust/Go), and persistent volumes from the shipped templates. Use when adding devcontainer support to a project, setting up an isolated development environment, or configuring a sandboxed Claude Code workspace.
---

# Devcontainer Setup

Adds a new `.devcontainer/` to a project from the shipped templates. Not for modifying an
existing devcontainer (edit that configuration directly), for general Docker questions, or for
production containers.

## Procedure

1. **Preview.** Select the package root. Check `pyproject.toml`'s `requires-python` before
   choosing the default Python 3.13; pass `--python-version` for a compatible version.
   Preview the detected languages, name and setup command without writing files:

   ```bash
   uv run --no-project "{baseDir}/scripts/scaffold.py" . --dry-run
   ```

   Correct the preview with `--name "My Project"`, `--slug my-project`, or `--langs python,node`
   when needed. Automatic detection does not follow symlinks. If traversal is unreadable,
   inspect the known package manifests and pass explicit languages rather than claiming
   detection completed. The helper does not install nested monorepo packages from the root:
   choose their package root or configure their working directories explicitly.

2. **Write.** Run the same command/options without `--dry-run`. It copies and validates all
   five templates. Existing `.devcontainer/` files are never overwritten: if correction is
   needed after generation, edit that configuration deliberately rather than deleting it.
   If host `uv` is unavailable, the stdlib-only helper supports Python 3.11+:

   ```bash
   # allow-legacy-python: stdlib fallback on hosts without uv; requires Python 3.11+
   python3 "{baseDir}/scripts/scaffold.py" . --dry-run
   ```

3. **Report.** Name the five files written and tell the user how to start: "Reopen in
   Container" in VS Code, or `devcontainer up --workspace-folder .`. Running
   `.devcontainer/install.sh self-install` adds the `devc` command.

## Rules

- Keep the templates' security configuration: the read-only `.devcontainer/` mount,
  `NET_ADMIN`/`NET_RAW` for network isolation, token forwarding through `remoteEnv`, and the
  pinned images and tool versions. Never add `SYS_ADMIN`; it defeats the read-only mount.
- Multi-language projects get every detected language in the order Python, Node/TypeScript,
  Rust, Go. `postCreateCommand` runs post-install once, then chains each setup command with
  `&&`, only for package manifests at the selected root. Python dependencies use a
  container-owned environment under `/opt/project-venv`, never delete the host `.venv`.
- A non-default Python version, extra persistent volumes, or a language outside the table are
  handled as described in [languages.md](references/languages.md). For Docker changes see
  [dockerfile-best-practices.md](references/dockerfile-best-practices.md) and
  [features-vs-dockerfile.md](references/features-vs-dockerfile.md).
