---
name: devcontainer-setup
description: Creates devcontainers with Claude Code, language-specific tooling (Python/Node/Rust/Go), and persistent volumes from the shipped templates. Use when adding devcontainer support to a project, setting up an isolated development environment, or configuring a sandboxed Claude Code workspace.
---

# Devcontainer Setup

Adds a new `.devcontainer/` to a project from the shipped templates. Not for modifying an
existing devcontainer (edit that configuration directly), for general Docker questions, or for
production containers.

## Procedure

1. **Scaffold.** Run the helper from the project root. It detects the language stack, infers
   the project name and slug from the manifests, copies the five templates, merges the
   language configuration, validates the result, and prints what it chose:

   ```bash
   uv run --no-project {baseDir}/scripts/scaffold.py .
   ```

   Pass `--name "My Project"`, `--slug my-project`, or `--langs python,node` only when the
   user specified them or the printed detection is wrong. It needs `uv`; if that is missing,
   stop and tell the user to install it (`brew install uv` or
   `curl -LsSf https://astral.sh/uv/install.sh | sh`). Do not retype or hand-edit the
   generated files; the exceptions are listed under Rules.

2. **Report.** Name the five files written and tell the user how to start: "Reopen in
   Container" in VS Code, or `devcontainer up --workspace-folder .`. Running
   `.devcontainer/install.sh self-install` adds the `devc` command.

## Rules

- Keep the templates' security configuration: the read-only `.devcontainer/` mount,
  `NET_ADMIN`/`NET_RAW` for network isolation, token forwarding through `remoteEnv`, and the
  pinned images and tool versions. Never add `SYS_ADMIN`; it defeats the read-only mount.
- Multi-language projects get every detected language in the order Python, Node/TypeScript,
  Rust, Go. `postCreateCommand` runs post-install once, then chains each setup command with
  `&&`.
- A non-default Python version, extra persistent volumes, or a language outside the table are
  handled as described in [languages.md](references/languages.md). For Docker changes see
  [dockerfile-best-practices.md](references/dockerfile-best-practices.md) and
  [features-vs-dockerfile.md](references/features-vs-dockerfile.md).
