#!/bin/bash
set -euo pipefail

# Claude Code Devcontainer CLI Helper
# Provides the `devc` command for managing devcontainers

# Resolve symlinks to get actual script location
SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SOURCE" ]]; do
  DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_usage() {
  cat <<EOF
Usage: devc <command> [options]

Commands:
    .                   Install devcontainer template to current directory and start
    up                  Start the devcontainer in current directory
    rebuild             Rebuild the devcontainer (preserves auth volumes)
    down                Stop the devcontainer
    shell               Open a shell in the running container
    self-install        Install 'devc' command to ~/.local/bin
    update              Update devc to the latest version
    template [dir]      Copy devcontainer template to directory (default: current)
    exec <cmd>          Execute a command in the running container
    upgrade             Upgrade Claude Code to latest version
    mount <host> <cont> Add a mount to the devcontainer (recreates container)
    help                Show this help message

Examples:
    devc .                      # Install template and start container
    devc up                     # Start container in current directory
    devc rebuild                # Clean rebuild
    devc shell                  # Open interactive shell
    devc self-install           # Install devc to PATH
    devc update                 # Update to latest version
    devc exec ls -la            # Run command in container
    devc upgrade                # Upgrade Claude Code to latest
    devc mount ~/data /data     # Add mount to container
EOF
}

log_info() {
  echo -e "${BLUE}[devc]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[devc]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[devc]${NC} $1"
}

log_error() {
  echo -e "${RED}[devc]${NC} $1" >&2
}

check_devcontainer_cli() {
  if ! command -v devcontainer &>/dev/null; then
    log_error "devcontainer CLI not found."
    log_info "Install it with: npm install -g @devcontainers/cli"
    exit 1
  fi
}

check_no_sys_admin() {
  local workspace="${1:-.}"
  local dc_json="$workspace/.devcontainer/devcontainer.json"
  [[ -f "$dc_json" ]] || return 0
  if jq -e \
    '.runArgs[]? | select(test("SYS_ADMIN"))' \
    "$dc_json" >/dev/null 2>&1; then
    log_error "SYS_ADMIN capability detected in runArgs."
    log_error "This defeats the read-only .devcontainer mount."
    exit 1
  fi
}

get_workspace_folder() {
  echo "${1:-$(pwd)}"
}

# Extract custom mounts from devcontainer.json to a temp file
# Returns the temp file path, or empty string if no custom mounts
#
# Security: .devcontainer/ is mounted read-only inside the container to prevent
# a compromised process from injecting malicious mounts or commands into
# devcontainer.json that execute on the host during rebuild. This protection
# requires that SYS_ADMIN is never added to runArgs (it would allow remounting
# read-write).
extract_mounts_to_file() {
  local devcontainer_json="$1"
  local temp_file

  [[ -f "$devcontainer_json" ]] || return 0

  temp_file=$(mktemp)

  # Filter out default mounts by target path (immune to project name changes)
  local custom_mounts
  custom_mounts=$(jq -c '
    .mounts // [] | map(
      select(
        (contains("target=/commandhistory,") | not) and
        (contains("target=/home/vscode/.claude,") | not) and
        (contains("target=/home/vscode/.config/gh,") | not) and
        (contains("target=/home/vscode/.gitconfig,") | not) and
        (contains("target=/workspace/.devcontainer,") | not)
      )
    ) | if length > 0 then . else empty end
  ' "$devcontainer_json" 2>/dev/null) || true

  if [[ -n "$custom_mounts" ]]; then
    echo "$custom_mounts" >"$temp_file"
    echo "$temp_file"
  else
    rm -f "$temp_file"
  fi
}

# Merge preserved mounts back into devcontainer.json
merge_mounts_from_file() {
  local devcontainer_json="$1"
  local mounts_file="$2"

  [[ -f "$mounts_file" ]] || return 0
  [[ -s "$mounts_file" ]] || return 0

  local custom_mounts
  custom_mounts=$(cat "$mounts_file")

  local updated
  updated=$(jq --argjson custom "$custom_mounts" '
    .mounts = ((.mounts // []) + $custom | unique)
  ' "$devcontainer_json")

  echo "$updated" >"$devcontainer_json"
}

# Add or update a mount in devcontainer.json
update_devcontainer_mounts() {
  local devcontainer_json="$1"
  local host_path="$2"
  local container_path="$3"
  local readonly="${4:-false}"

  local mount_str="source=${host_path},target=${container_path},type=bind"
  [[ "$readonly" == "true" ]] && mount_str="${mount_str},readonly"

  local updated
  updated=$(jq --arg target "$container_path" --arg mount "$mount_str" '
    .mounts = (
      ((.mounts // []) | map(select(contains("target=" + $target + ",") or endswith("target=" + $target) | not)))
      + [$mount]
    )
  ' "$devcontainer_json")

  echo "$updated" >"$devcontainer_json"
}

cmd_template() {
  local target_dir="${1:-.}"
  target_dir="$(cd "$target_dir" 2>/dev/null && pwd)" || {
    log_error "Directory does not exist: $1"
    exit 1
  }

  local devcontainer_dir="$target_dir/.devcontainer"
  local devcontainer_json="$devcontainer_dir/devcontainer.json"
  local preserved_mounts=""

  if [[ -d "$devcontainer_dir" ]]; then
    log_warn "Devcontainer already exists at $devcontainer_dir"
    read -p "Overwrite? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      log_info "Aborted."
      exit 0
    fi

    # Preserve custom mounts before overwriting
    preserved_mounts=$(extract_mounts_to_file "$devcontainer_json")
    if [[ -n "$preserved_mounts" ]]; then
      log_info "Preserving custom mounts..."
    fi
  fi

  mkdir -p "$devcontainer_dir"

  # Copy template files
  cp "$SCRIPT_DIR/Dockerfile" "$devcontainer_dir/"
  cp "$SCRIPT_DIR/devcontainer.json" "$devcontainer_dir/"
  cp "$SCRIPT_DIR/post_install.py" "$devcontainer_dir/"
  cp "$SCRIPT_DIR/.zshrc" "$devcontainer_dir/"

  # Restore preserved mounts
  if [[ -n "$preserved_mounts" ]]; then
    merge_mounts_from_file "$devcontainer_json" "$preserved_mounts"
    rm -f "$preserved_mounts"
    log_info "Custom mounts restored"
  fi

  log_success "Template installed to $devcontainer_dir"
}

cmd_up() {
  local workspace_folder
  workspace_folder="$(get_workspace_folder "${1:-}")"

  check_devcontainer_cli
  check_no_sys_admin "$workspace_folder"
  log_info "Starting devcontainer in $workspace_folder..."

  devcontainer up --workspace-folder "$workspace_folder"
  log_success "Devcontainer started"
}

cmd_rebuild() {
  local workspace_folder
  workspace_folder="$(get_workspace_folder "${1:-}")"

  check_devcontainer_cli
  check_no_sys_admin "$workspace_folder"
  log_info "Rebuilding devcontainer in $workspace_folder..."

  devcontainer up \
    --workspace-folder "$workspace_folder" \
    --remove-existing-container
  log_success "Devcontainer rebuilt"
}

cmd_down() {
  local workspace_folder
  workspace_folder="$(get_workspace_folder "${1:-}")"

  check_devcontainer_cli
  log_info "Stopping devcontainer..."

  # Get container ID and stop it
  local container_id
  local label="devcontainer.local_folder=$workspace_folder"
  container_id=$(docker ps -q --filter "label=$label" 2>/dev/null || true)

  if [[ -n "$container_id" ]]; then
    docker stop "$container_id"
    log_success "Devcontainer stopped"
  else
    log_warn "No running devcontainer found for $workspace_folder"
  fi
}

cmd_shell() {
  local workspace_folder
  workspace_folder="$(get_workspace_folder)"

  check_devcontainer_cli
  log_info "Opening shell in devcontainer..."

  devcontainer exec --workspace-folder "$workspace_folder" zsh
}

cmd_exec() {
  local workspace_folder
  workspace_folder="$(get_workspace_folder)"

  check_devcontainer_cli
  devcontainer exec --workspace-folder "$workspace_folder" "$@"
}

cmd_upgrade() {
  local workspace_folder
  workspace_folder="$(get_workspace_folder)"

  check_devcontainer_cli
  log_info "Upgrading Claude Code..."

  devcontainer exec --workspace-folder "$workspace_folder" claude update

  log_success "Claude Code upgraded"
}

cmd_mount() {
  local host_path="${1:-}"
  local container_path="${2:-}"
  local readonly="false"

  if [[ -z "$host_path" ]] || [[ -z "$container_path" ]]; then
    log_error "Usage: devc mount <host_path> <container_path> [--readonly]"
    exit 1
  fi

  [[ "${3:-}" == "--readonly" ]] && readonly="true"

  # Expand and validate host path
  host_path="$(cd "$host_path" 2>/dev/null && pwd)" || {
    log_error "Host path does not exist: $1"
    exit 1
  }

  local workspace_folder
  workspace_folder="$(get_workspace_folder)"
  local devcontainer_json="$workspace_folder/.devcontainer/devcontainer.json"

  if [[ ! -f "$devcontainer_json" ]]; then
    log_error "No devcontainer.json found. Run 'devc template' first."
    exit 1
  fi

  check_devcontainer_cli

  log_info "Adding mount: $host_path → $container_path"
  update_devcontainer_mounts "$devcontainer_json" "$host_path" "$container_path" "$readonly"

  log_info "Recreating container with new mount..."
  devcontainer up \
    --workspace-folder "$workspace_folder" \
    --remove-existing-container

  log_success "Mount added: $host_path → $container_path"
}

cmd_self_install() {
  local install_dir="$HOME/.local/bin"
  local install_path="$install_dir/devc"

  mkdir -p "$install_dir"

  # Create a symlink to the original script
  ln -sf "$SCRIPT_DIR/$SCRIPT_NAME" "$install_path"

  log_success "Installed 'devc' to $install_path"

  # Check if in PATH
  if [[ ":$PATH:" != *":$install_dir:"* ]]; then
    log_warn "$install_dir is not in your PATH"
    log_info "Add this to your shell profile:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi
}

cmd_update() {
  log_info "Updating devc..."

  if ! git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree &>/dev/null; then
    log_error "Not a git repository: $SCRIPT_DIR"
    log_info "Re-clone with: rm -rf ~/.claude-devcontainer && git clone https://github.com/trailofbits/claude-code-devcontainer ~/.claude-devcontainer"
    exit 1
  fi

  local before_sha after_sha
  before_sha=$(git -C "$SCRIPT_DIR" rev-parse HEAD)

  if ! git -C "$SCRIPT_DIR" pull --ff-only; then
    log_error "Update failed. Try: cd $SCRIPT_DIR && git pull"
    exit 1
  fi

  after_sha=$(git -C "$SCRIPT_DIR" rev-parse HEAD)

  if [[ "$before_sha" == "$after_sha" ]]; then
    log_success "Already up to date"
  else
    log_success "Updated from ${before_sha:0:7} to ${after_sha:0:7}"
  fi
}

cmd_dot() {
  # Install template and start container in one command
  cmd_template "."
  cmd_up "."
}

# Main command dispatcher
main() {
  if [[ $# -eq 0 ]]; then
    print_usage
    exit 1
  fi

  local command="$1"
  shift

  case "$command" in
    .)
      cmd_dot
      ;;
    up)
      cmd_up "$@"
      ;;
    rebuild)
      cmd_rebuild "$@"
      ;;
    down)
      cmd_down "$@"
      ;;
    shell)
      cmd_shell
      ;;
    exec)
      [[ "${1:-}" == "--" ]] && shift
      cmd_exec "$@"
      ;;
    upgrade)
      cmd_upgrade
      ;;
    mount)
      cmd_mount "$@"
      ;;
    self-install)
      cmd_self_install
      ;;
    update)
      cmd_update
      ;;
    template)
      cmd_template "$@"
      ;;
    help | --help | -h)
      print_usage
      ;;
    *)
      log_error "Unknown command: $command"
      print_usage
      exit 1
      ;;
  esac
}

main "$@"
