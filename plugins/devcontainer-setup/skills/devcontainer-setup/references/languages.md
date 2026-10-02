# Language configuration

`scripts/scaffold.py` applies every rule on this page. Read it when a project needs a
non-default version, an extra volume, a language the table does not cover, or when you need to
check what the helper decided.

## Detection and configuration

| Language | Detected from | Added to `devcontainer.json` | Setup command |
| --- | --- | --- | --- |
| Python | root `pyproject.toml`, `requirements.txt`, `setup.py`; or `*.py` when no root package manifest exists | extensions `ms-python.python`, `ms-python.vscode-pylance`, `charliermarsh.ruff`; Ruff formatter; `/opt/project-venv/bin/python` for pyproject projects, otherwise `python` | `uv sync` for root `pyproject.toml`, with `UV_PROJECT_ENVIRONMENT=/opt/project-venv` in the container environment; host `.venv` is untouched |
| Node/TypeScript | root `package.json` or `tsconfig.json` | extensions `dbaeumer.vscode-eslint`, `esbenp.prettier-vscode`; Prettier formatter, ESLint fix on save | with `package.json`, by lockfile: `corepack pnpm install --frozen-lockfile`, `corepack yarn install --frozen-lockfile`, `npm ci`, else `npm install`; both Corepack commands set `COREPACK_ENABLE_DOWNLOAD_PROMPT=0` |
| Rust | `Cargo.toml` | feature `ghcr.io/devcontainers/features/rust:1`; extensions `rust-lang.rust-analyzer`, `tamasfe.even-better-toml` | `cargo build --locked` when `Cargo.lock` exists, else `cargo build` |
| Go | root `go.mod` or `go.sum` | feature `ghcr.io/devcontainers/features/go:1` (`version: latest`); extension `golang.go`; `go.useLanguageServer` | `go mod download` only with root `go.mod` |

Python 3.13 and Node 22 come from the Dockerfile. Source/config-only detection enables
tooling, not a package install. Nested package roots need their own configuration; `--langs`
does not move install commands into a subdirectory. Auto-detection rejects nested-only
package layouts and unreadable traversal rather than claiming complete setup.

`postCreateCommand` always starts with `uv run --no-project /opt/post_install.py` (the
template's own command; `--no-project` keeps it independent of the project's environment), then
the setup commands in the order Python, Node/TypeScript, Rust, Go, joined with `&&`.

## Project name and slug

The helper takes the first available of: `package.json` `name` (without an npm scope),
`pyproject.toml` `project.name`, `Cargo.toml` `package.name`, the last segment of the `go.mod`
module path (without quotes or a `/v2`-style major-version suffix), then the directory name.
Names containing control characters or line separators are rejected. An identifier such as `my-project` becomes the
human-readable name `My Project`; the slug is the lowercase form with spaces and underscores
replaced by hyphens and other punctuation dropped. Override either with `--name` and `--slug`
in the preview before writing files.
An explicit `--name` bypasses name inference, so it can safely replace an invalid manifest
name. This does not validate the package manifest for building or installing dependencies.

## Exceptions

- **Different Python version.** When `pyproject.toml` requires a version other than 3.13, pass
  `--python-version 3.12` (or similar). The helper rewrites the Dockerfile's
  `RUN uv python install <version> --default` line and its version comment. Inspect the
  project's version requirement before writing; the helper does not solve version constraints.
- **Extra persistent volumes.** After scaffolding, add entries to `mounts` in
  `devcontainer.json` using the template's pattern:

  ```json
  "source=<slug>-<purpose>-${devcontainerId},target=<container-path>,type=volume"
  ```

  Common additions: `<slug>-cargo-${devcontainerId}` → `/home/vscode/.cargo` (Rust) and
  `<slug>-go-${devcontainerId}` → `/home/vscode/go` (Go).
- **Unsupported language.** Scaffold with the detected languages, then add the extra
  language's devcontainer feature, extensions, and setup command by hand, following the
  table's shape.

## Base template

Every generated devcontainer includes Claude Code with the anthropics/skills,
trailofbits/skills, and trailofbits/skills-curated marketplaces, bubblewrap and socat for
sandboxing, Python 3.13 via uv, Node 22 via fnm, ast-grep, iptables/ipset with `NET_ADMIN`
for network isolation, ripgrep, fd, fzf, tmux, and git-delta. `.devcontainer/` is mounted
read-only inside the container, and `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY` are
forwarded through `remoteEnv`.
