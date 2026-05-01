# Devcontainer Setup Plugin

Create pre-configured devcontainers with Claude Code and language-specific tooling.

## Features

- **Claude Code** pre-installed with `bypassPermissions` auto-configured and marketplace plugins
- **Multi-language support**: Python 3.13, Node 22, Rust, Go
- **Modern CLI tools**: ripgrep, fd, fzf, tmux, git-delta, ast-grep
- **Session persistence**: command history, GitHub CLI auth, Claude config survive rebuilds
- **Sandboxing**: bubblewrap and socat for Claude Code sandboxing support
- **Network isolation**: iptables/ipset with NET_ADMIN capability for restricting outbound traffic
- **Token forwarding**: `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY` forwarded to container

## Usage

Tell Claude to "set up a devcontainer" or "add devcontainer support" in your project.

The skill will:
1. Detect your project's language stack
2. Generate `.devcontainer/` configuration files
3. Provide instructions for starting the container

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
devc exec <cmd>     Execute a command in the running container
devc upgrade        Upgrade Claude Code to latest version
devc mount <h> <c>  Add a bind mount to the container
devc sync           Sync sessions from devcontainers to host
devc cp <c> <h>     Copy files from container to host
devc destroy [-f]   Remove container, volumes, and image
```

## Supported Languages

| Language | Detection | Configuration |
|----------|-----------|---------------|
| Python | `pyproject.toml`, `*.py` | Python 3.13 via uv (in Dockerfile) |
| Node/TypeScript | `package.json`, `tsconfig.json` | Node 22 via fnm (in Dockerfile) |
| Rust | `Cargo.toml` | Devcontainer feature |
| Go | `go.mod` | Devcontainer feature |

Multi-language projects automatically get all detected configurations merged.

## Security Model

The devcontainer provides **filesystem isolation** with **network isolation** capabilities:

- Container filesystem is isolated from host
- `.devcontainer/` mounted read-only inside the container to prevent escape
- Your `~/.gitconfig` is mounted read-only
- SYS_ADMIN capability blocked by `devc` CLI to protect read-only mounts
- Persistent volumes preserve auth across rebuilds
- iptables/ipset with NET_ADMIN/NET_RAW capabilities for restricting network access
- NPM security settings: scripts disabled, 24-hour package release delay
- SSH commit signing supported via `gpg.ssh.program` configuration

## Reference Material

- `references/dockerfile-best-practices.md` - Docker optimization tips
- `references/features-vs-dockerfile.md` - When to use features vs Dockerfile
