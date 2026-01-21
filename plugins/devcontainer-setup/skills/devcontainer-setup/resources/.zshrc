# Zsh configuration for Claude Code devcontainer

# Add Claude Code to PATH
export PATH="$HOME/.local/bin:$PATH"

# History settings
export HISTFILE=/commandhistory/.zsh_history
export HISTSIZE=200000
export SAVEHIST=200000
setopt SHARE_HISTORY
setopt HIST_IGNORE_DUPS

# Aliases
alias fd=fdfind
alias claude-yolo='claude --dangerously-skip-permissions'
