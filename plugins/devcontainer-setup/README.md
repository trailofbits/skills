# Devcontainer Setup Plugin

Create pre-configured devcontainers with Claude Code and language-specific tooling.

## Features

- **Claude Code** pre-installed with `bypassPermissions` auto-configured
- **Multi-language support**: Python, Node/TypeScript, Rust, Go
- **Modern CLI tools**: ripgrep, fd, tmux, fzf, git-delta
- **Session persistence**: command history, GitHub CLI auth, Claude config survive rebuilds
- **Optional network isolation**: iptables/ipset for restricting outbound traffic

## Usage

Tell Claude to "set up a devcontainer" or "add devcontainer support" in your project.

The skill will:
1. Detect your project's language stack
2. Ask about network isolation preferences
3. Generate `.devcontainer/` configuration files
4. Provide instructions for starting the container

## Generated Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Container build instructions with Claude Code and dev tools |
| `devcontainer.json` | VS Code/devcontainer configuration |
| `post_install.py` | Post-creation setup (permissions, tmux, git config) |
| `.zshrc` | Shell configuration with history persistence |
| `install.sh` | CLI helper (`devc` command) for managing containers |

## CLI Helper Commands

After generating, run `.devcontainer/install.sh self-install` to add the `devc` command:

```
devc .              Install template + start container in current directory
devc up             Start the devcontainer
devc rebuild        Rebuild container (preserves persistent volumes)
devc down           Stop the container
devc shell          Open zsh shell in container
```

## Supported Languages

| Language | Detection | Configuration |
|----------|-----------|---------------|
| Python | `pyproject.toml`, `*.py` | uv + Python via Dockerfile |
| Node/TypeScript | `package.json`, `tsconfig.json` | Devcontainer feature |
| Rust | `Cargo.toml` | Devcontainer feature |
| Go | `go.mod` | Devcontainer feature |

Multi-language projects automatically get all detected configurations merged.

## Security Model

The devcontainer provides **filesystem isolation** with optional **network isolation**:

- Container filesystem is isolated from host
- Your `~/.gitconfig` is mounted read-only
- Persistent volumes preserve auth across rebuilds
- Optional iptables/ipset for restricting network access

## Reference Material

- `references/dockerfile-best-practices.md` - Docker optimization tips
- `references/features-vs-dockerfile.md` - When to use features vs Dockerfile
