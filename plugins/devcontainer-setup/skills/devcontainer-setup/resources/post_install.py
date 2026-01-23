#!/usr/bin/env python3
"""Post-install configuration for Claude Code devcontainer.

Runs on container creation to set up:
- Claude settings (bypassPermissions mode)
- Claude plugin marketplaces (anthropics/skills, trailofbits/skills)
- Tmux configuration (200k history, mouse support)
- Directory ownership fixes for mounted volumes
"""

import json
import os
import subprocess
from pathlib import Path


def setup_claude_settings():
    """Configure Claude Code with bypassPermissions enabled."""
    claude_dir = Path.home() / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)

    settings_file = claude_dir / "settings.json"

    # Load existing settings or start fresh
    settings = {}
    if settings_file.exists():
        try:
            settings = json.loads(settings_file.read_text())
        except json.JSONDecodeError:
            pass

    # Set bypassPermissions mode
    if "permissions" not in settings:
        settings["permissions"] = {}
    settings["permissions"]["defaultMode"] = "bypassPermissions"

    settings_file.write_text(json.dumps(settings, indent=2) + "\n")
    print(f"[post_install] Claude settings configured: {settings_file}")


def setup_tmux_config():
    """Configure tmux with 200k history, mouse support, and vi keys."""
    tmux_conf = Path.home() / ".tmux.conf"

    config = """\
# 200k line scrollback history
set-option -g history-limit 200000

# Enable mouse support
set -g mouse on

# Use vi keys in copy mode
setw -g mode-keys vi

# Start windows and panes at 1, not 0
set -g base-index 1
setw -g pane-base-index 1

# Renumber windows when one is closed
set -g renumber-windows on

# Faster escape time for vim
set -sg escape-time 10

# True color support
set -g default-terminal "tmux-256color"
set -ag terminal-overrides ",xterm-256color:RGB"

# Status bar
set -g status-style 'bg=#333333 fg=#ffffff'
set -g status-left '[#S] '
set -g status-right '%Y-%m-%d %H:%M'
"""
    tmux_conf.write_text(config)
    print(f"[post_install] Tmux configured: {tmux_conf}")


def fix_directory_ownership():
    """Fix ownership of mounted volumes that may have root ownership."""
    uid = os.getuid()
    gid = os.getgid()

    dirs_to_fix = [
        Path.home() / ".claude",
        Path("/commandhistory"),
        Path.home() / ".config" / "gh",
    ]

    for dir_path in dirs_to_fix:
        if dir_path.exists():
            try:
                # Use sudo to fix ownership if needed
                stat_info = dir_path.stat()
                if stat_info.st_uid != uid:
                    subprocess.run(
                        ["sudo", "chown", "-R", f"{uid}:{gid}", str(dir_path)],
                        check=True,
                        capture_output=True,
                    )
                    print(f"[post_install] Fixed ownership: {dir_path}")
            except (PermissionError, subprocess.CalledProcessError) as e:
                print(
                    f"[post_install] Warning: Could not fix ownership of {dir_path}: {e}"
                )


def setup_git_config():
    """Set up git delta as the default pager if not already configured."""
    gitconfig = Path.home() / ".gitconfig"

    # Skip if .gitconfig exists (likely mounted from host)
    if gitconfig.exists():
        print(f"[post_install] Git config exists (mounted from host): {gitconfig}")
    else:
        config = """\
[core]
    pager = delta

[interactive]
    diffFilter = delta --color-only

[delta]
    navigate = true
    light = false
    line-numbers = true

[merge]
    conflictstyle = diff3

[diff]
    colorMoved = default
"""
        gitconfig.write_text(config)
        print(f"[post_install] Git config created: {gitconfig}")


def setup_claude_plugins():
    """Install Claude Code plugin marketplaces."""
    marketplaces = [
        "anthropics/skills",
        "trailofbits/skills",
    ]

    for marketplace in marketplaces:
        try:
            subprocess.run(
                ["claude", "plugin", "marketplace", "add", marketplace],
                check=True,
                capture_output=True,
            )
            print(f"[post_install] Added plugin marketplace: {marketplace}")
        except subprocess.CalledProcessError as e:
            print(f"[post_install] Warning: Could not add marketplace {marketplace}: {e}")
        except FileNotFoundError:
            print("[post_install] Warning: claude command not found, skipping plugins")
            break


def setup_global_gitignore():
    """Set up global gitignore and local git config.

    Since ~/.gitconfig is mounted read-only from host, we create a local
    config file that includes the host config and adds container-specific
    settings like core.excludesfile.

    GIT_CONFIG_GLOBAL env var (set in devcontainer.json) points git to this
    local config as the "global" config.
    """
    home = Path.home()
    gitignore = home / ".gitignore_global"
    local_gitconfig = home / ".gitconfig.local"
    host_gitconfig = home / ".gitconfig"

    # Create global gitignore with common patterns
    patterns = """\
# Claude Code
.claude/

# macOS
.DS_Store
.AppleDouble
.LSOverride
._*

# Python
*.pyc
*.pyo
__pycache__/
*.egg-info/
.eggs/
*.egg
.venv/
venv/
.mypy_cache/
.ruff_cache/

# Node
node_modules/
.npm/

# Editors
*.swp
*.swo
*~
.idea/
.vscode/
*.sublime-*

# Misc
*.log
.env.local
.env.*.local
"""
    gitignore.write_text(patterns)
    print(f"[post_install] Global gitignore created: {gitignore}")

    # Create local git config that includes host config and sets excludesfile
    local_config = f"""\
# Container-local git config
# Includes host config (mounted read-only) and adds container settings

[include]
    path = {host_gitconfig}

[core]
    excludesfile = {gitignore}
"""
    local_gitconfig.write_text(local_config)
    print(f"[post_install] Local git config created: {local_gitconfig}")


def main():
    """Run all post-install configuration."""
    print("[post_install] Starting post-install configuration...")

    setup_claude_settings()
    setup_claude_plugins()
    setup_tmux_config()
    fix_directory_ownership()
    setup_git_config()
    setup_global_gitignore()

    print("[post_install] Configuration complete!")


if __name__ == "__main__":
    main()
