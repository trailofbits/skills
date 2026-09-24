# Language configuration

`scripts/scaffold.py` applies every rule on this page. Read it when a project needs a
non-default version, an extra volume, a language the table does not cover, or when you need to
check what the helper decided.

## Detection and configuration

| Language | Detected from | Added to `devcontainer.json` | Setup command |
| --- | --- | --- | --- |
| Python | `pyproject.toml`, `requirements.txt`, `setup.py`, or any `*.py` | extensions `ms-python.python`, `ms-python.vscode-pylance`, `charliermarsh.ruff`; interpreter `.venv/bin/python`; Ruff as formatter with import organizing on save | `rm -rf .venv && uv sync` when `pyproject.toml` exists; Python 3.13 comes from the base Dockerfile |
| Node/TypeScript | `package.json` or `tsconfig.json` | extensions `dbaeumer.vscode-eslint`, `esbenp.prettier-vscode`; Prettier as formatter, ESLint fix on save | by lockfile: `pnpm install --frozen-lockfile`, `yarn install --frozen-lockfile`, `npm ci`, else `npm install`; Node 22 comes from the base Dockerfile. pnpm and yarn are preceded by `corepack enable`, because fnm's Node ships corepack but not those shims |
| Rust | `Cargo.toml` | feature `ghcr.io/devcontainers/features/rust:1`; extensions `rust-lang.rust-analyzer`, `tamasfe.even-better-toml` | `cargo build --locked` when `Cargo.lock` exists, else `cargo build` |
| Go | `go.mod` or `go.sum` | feature `ghcr.io/devcontainers/features/go:1` (`version: latest`); extension `golang.go`; `go.useLanguageServer` | `go mod download` |

`postCreateCommand` always starts with `uv run --no-project /opt/post_install.py` (the
template's own command; `--no-project` keeps it independent of the project's environment), then
the setup commands in the order Python, Node/TypeScript, Rust, Go, joined with `&&`.

## Project name and slug

The helper takes the first available of: `package.json` `name` (without an npm scope),
`pyproject.toml` `project.name`, `Cargo.toml` `package.name`, the last segment of the `go.mod`
module path, then the directory name. An identifier such as `my-project` becomes the
human-readable name `My Project`; the slug is the lowercase form with spaces and underscores
replaced by hyphens. Override either with `--name` and `--slug` when the user supplies them.

## Exceptions

- **Different Python version.** When `pyproject.toml` requires a version other than 3.13, pass
  `--python-version 3.12` (or similar). The helper rewrites the Dockerfile's
  `RUN uv python install <version> --default` line and nothing else.
- **Extra persistent volumes.** After scaffolding, add entries to `mounts` in
  `devcontainer.json` using the template's pattern:

  ```json
  "source=<slug>-<purpose>-${devcontainerId},target=<container-path>,type=volume"
  ```

  Common additions: `<slug>-cargo-${devcontainerId}` → `/home/vscode/.cargo` (Rust) and
  `<slug>-go-${devcontainerId}` → `/home/vscode/go` (Go).
- **Unsupported language.** Scaffold with the detected languages, then add the extra
  language's devcontainer feature, extensions, and setup command by hand, following the
  table's shape. See `features-vs-dockerfile.md` for choosing a feature over Dockerfile steps.

## Base template

Every generated devcontainer includes Claude Code with the anthropics/skills,
trailofbits/skills, and trailofbits/skills-curated marketplaces, bubblewrap and socat for
sandboxing, Python 3.13 via uv, Node 22 via fnm, ast-grep, iptables/ipset with `NET_ADMIN`
for network isolation, ripgrep, fd, fzf, tmux, and git-delta. `.devcontainer/` is mounted
read-only inside the container, and `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY` are
forwarded through `remoteEnv`.
