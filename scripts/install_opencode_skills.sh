#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Install Trail of Bits plugin skills and commands for OpenCode.

Default behavior:
  - Source: remote GitHub archive (no local clone needed)
  - Action: install
  - Components: skills and commands
  - Mode: copy
  - Skills target: ~/.config/opencode/skills
  - Commands target: ~/.config/opencode/commands

Usage:
  install_opencode_skills.sh [options]

Options:
  --list                            List matching items and exit
  --bundle NAME                    Install predefined bundle (supported: smart-contracts)
  --plugin NAME                    Filter by plugin (repeatable)
  --skill NAME                     Filter by skill name (repeatable)
  --command NAME                   Filter by command name (repeatable)
  --all                            Install all items (default when no filters are provided)
  --target PATH                    Skills target directory (default: ~/.config/opencode/skills)
  --skills-target PATH             Alias for --target
  --commands-target PATH           Commands target directory (default: ~/.config/opencode/commands)
  --skills-only                    Install/uninstall only skills
  --commands-only                  Install/uninstall only commands
  --include-incompatible-commands  Include Claude-specific commands (default: false)
  --source SOURCE                  Source: remote|local (default: remote)
  --repo OWNER/REPO                GitHub repository for remote source (default: trailofbits/skills)
  --ref REF                        Git ref for remote source (default: main)
  --copy                           Copy items into target directories (default)
  --link                           Symlink items into target directories (local source only)
  --uninstall                      Remove matching items from targets
  --force                          Replace or remove existing unmanaged paths
  --dry-run                        Print planned changes without modifying files
  -h, --help                       Show this help

Examples:
  # Install smart contract bundle from GitHub (no clone required)
  install_opencode_skills.sh --bundle smart-contracts

  # Install only commands from one plugin
  install_opencode_skills.sh --commands-only --plugin entry-point-analyzer

  # Local contributor workflow with symlinks
  install_opencode_skills.sh --source local --bundle smart-contracts --link

  # Uninstall one command and its related skill
  install_opencode_skills.sh --skill entry-point-analyzer --command entry-points --uninstall
EOF
}

fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

contains_exact() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

# shellcheck disable=SC2088
expand_path() {
  local path="$1"

  if [[ "$path" == "~" ]]; then
    path="$HOME"
  elif [[ "$path" == '~/'* ]]; then
    path="$HOME/${path#\~/}"
  fi

  if [[ "$path" != /* ]]; then
    path="$(pwd)/$path"
  fi

  printf '%s' "$path"
}

extract_frontmatter_name() {
  local file="$1"
  local line
  local in_frontmatter=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"

    if [[ $in_frontmatter -eq 0 ]]; then
      if [[ "$line" == "---" ]]; then
        in_frontmatter=1
        continue
      fi
      return 1
    fi

    if [[ "$line" == "---" ]]; then
      return 1
    fi

    if [[ "$line" =~ ^[[:space:]]*name:[[:space:]]*(.*)$ ]]; then
      local value
      value="$(trim "${BASH_REMATCH[1]}")"
      if [[ -z "$value" ]]; then
        return 1
      fi

      if [[ "$value" == "\""*"\"" ]]; then
        value="${value#\"}"
        value="${value%\"}"
      elif [[ "$value" == "'"*"'" ]]; then
        value="${value#\'}"
        value="${value%\'}"
      fi

      printf '%s' "$value"
      return 0
    fi
  done <"$file"

  return 1
}

extract_skill_name_from_dir() {
  local dir="$1"
  local skill_file="$dir/SKILL.md"

  if [[ ! -f "$skill_file" ]]; then
    return 1
  fi

  extract_frontmatter_name "$skill_file"
}

extract_command_referenced_skills() {
  local file="$1"
  local line
  local token
  local normalized
  local refs_csv=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"

    if [[ "$line" != *"\`"*"\`"*" skill"* ]]; then
      continue
    fi

    token="${line#*\`}"
    token="${token%%\`*}"

    normalized="${token##*:}"
    if [[ "$normalized" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
      if ! csv_contains "$refs_csv" "$normalized"; then
        if [[ -z "$refs_csv" ]]; then
          refs_csv="$normalized"
        else
          refs_csv+=",$normalized"
        fi
      fi
    fi
  done <"$file"

  printf '%s' "$refs_csv"
}

csv_contains() {
  local csv="$1"
  local needle="$2"
  local item
  declare -a items=()
  if [[ -n "$csv" ]]; then
    IFS=',' read -r -a items <<<"$csv"
  fi
  for item in "${items[@]-}"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

matches_selected_skill_names() {
  local command_refs_csv="$1"
  local skill_name

  if [[ -z "$command_refs_csv" ]]; then
    return 1
  fi

  for skill_name in "${SELECTED_SKILL_NAMES[@]}"; do
    if csv_contains "$command_refs_csv" "$skill_name"; then
      return 0
    fi
  done

  return 1
}

is_smart_contract_plugin() {
  case "$1" in
    building-secure-contracts | entry-point-analyzer | spec-to-code-compliance | property-based-testing)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

matches_bundle() {
  local bundle="$1"
  local plugin="$2"

  case "$bundle" in
    smart-contracts)
      is_smart_contract_plugin "$plugin"
      ;;
    "")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_symlink_to() {
  local target="$1"
  local expected="$2"
  local target_real
  local expected_real

  if [[ ! -L "$target" ]]; then
    return 1
  fi

  # realpath may fail for dangling symlinks; fall through to raw readlink
  if command -v realpath >/dev/null 2>&1; then
    target_real="$(realpath "$target" 2>/dev/null || true)"
    expected_real="$(realpath "$expected" 2>/dev/null || true)"
    if [[ -n "$target_real" && -n "$expected_real" && "$target_real" == "$expected_real" ]]; then
      return 0
    fi
  fi

  local actual
  actual="$(readlink "$target")"
  [[ "$actual" == "$expected" ]]
}

files_equal() {
  local a="$1"
  local b="$2"
  cmp -s "$a" "$b"
}

is_command_compatible_with_opencode() {
  local file="$1"
  if [[ ! -r "$file" ]]; then
    return 1
  fi
  # Literal match for ${CLAUDE_PLUGIN_ROOT}, not shell expansion
  # shellcheck disable=SC2016
  if grep -q '\${CLAUDE_PLUGIN_ROOT}' "$file"; then
    return 1
  fi
  return 0
}

safe_remove_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    fail "safe_remove_path called with empty path"
  fi
  case "$path" in
    / | /bin | /boot | /dev | /etc | /home | /lib* | /opt | /proc | /root | /run | /sbin | /srv | /sys | /tmp | /usr | /var)
      fail "safe_remove_path refusing dangerous path: $path"
      ;;
  esac
  local depth
  depth="$(printf '%s' "$path" | tr -cd '/' | wc -c)"
  if [[ "$depth" -lt 3 ]]; then
    fail "safe_remove_path refusing shallow path: $path"
  fi
  # rm -rf is used instead of trash(1) because this installer runs
  # on CI and remote machines where trash may not be available.
  rm -rf "$path"
}

install_or_uninstall_skill() {
  local idx="$1"
  local name="${SKILL_NAMES[$idx]}"
  local source_dir="${SKILL_DIRS[$idx]}"
  local target_dir="$SKILLS_TARGET/$name"

  if [[ "$ACTION" == "install" ]]; then
    local exists=0
    if [[ -e "$target_dir" || -L "$target_dir" ]]; then
      exists=1
    fi

    if [[ $exists -eq 1 ]]; then
      if [[ "$MODE" == "link" ]] && is_symlink_to "$target_dir" "$source_dir"; then
        skill_unchanged=$((skill_unchanged + 1))
        log_result "unchanged" "skill" "$name" "already linked: $target_dir"
        return
      fi

      local existing_name=""
      if [[ -d "$target_dir" || -L "$target_dir" ]]; then
        existing_name="$(extract_skill_name_from_dir "$target_dir" || true)"
      fi

      if [[ "$MODE" == "copy" && -d "$target_dir" && ! -L "$target_dir" && "$existing_name" == "$name" ]]; then
        if [[ "$SOURCE" == "local" ]]; then
          skill_unchanged=$((skill_unchanged + 1))
          log_result "unchanged" "skill" "$name" "already installed: $target_dir"
          return
        fi
        # Remote source: replace with fresh content
        if [[ $DRY_RUN -eq 1 ]]; then
          printf '[dry-run] replacing %s with fresh download\n' "$target_dir"
        else
          safe_remove_path "$target_dir"
        fi
      elif [[ $FORCE -ne 1 ]]; then
        skill_error=$((skill_error + 1))
        log_result "error" "skill" "$name" "target exists ($target_dir); use --force to replace"
        return
      else
        if [[ $DRY_RUN -eq 1 ]]; then
          printf '[dry-run] rm -rf %s\n' "$target_dir"
        else
          safe_remove_path "$target_dir"
        fi
      fi
    fi

    if [[ "$MODE" == "copy" ]]; then
      if [[ $DRY_RUN -eq 1 ]]; then
        skill_installed=$((skill_installed + 1))
        log_result "installed" "skill" "$name" "[dry-run] cp -R $source_dir $target_dir"
      elif cp -R "$source_dir" "$target_dir"; then
        skill_installed=$((skill_installed + 1))
        log_result "installed" "skill" "$name" "copied: $target_dir"
      else
        skill_error=$((skill_error + 1))
        log_result "error" "skill" "$name" "failed to copy to $target_dir"
      fi
    else
      if [[ $DRY_RUN -eq 1 ]]; then
        skill_installed=$((skill_installed + 1))
        log_result "installed" "skill" "$name" "[dry-run] ln -s $source_dir $target_dir"
      elif ln -s "$source_dir" "$target_dir"; then
        skill_installed=$((skill_installed + 1))
        log_result "installed" "skill" "$name" "linked: $target_dir -> $source_dir"
      else
        skill_error=$((skill_error + 1))
        log_result "error" "skill" "$name" "failed to link $source_dir to $target_dir"
      fi
    fi
  else
    if [[ ! -e "$target_dir" && ! -L "$target_dir" ]]; then
      skill_skipped=$((skill_skipped + 1))
      log_result "skipped" "skill" "$name" "not installed: $target_dir"
      return
    fi

    local removable=0
    if [[ $FORCE -eq 1 ]]; then
      removable=1
    elif [[ -L "$target_dir" ]] && is_symlink_to "$target_dir" "$source_dir"; then
      removable=1
    else
      local target_name
      target_name="$(extract_skill_name_from_dir "$target_dir" || true)"
      if [[ "$target_name" == "$name" ]]; then
        removable=1
      fi
    fi

    if [[ $removable -ne 1 ]]; then
      skill_error=$((skill_error + 1))
      log_result "error" "skill" "$name" "refusing to remove unmanaged path ($target_dir); use --force"
      return
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
      skill_removed=$((skill_removed + 1))
      log_result "removed" "skill" "$name" "[dry-run] rm -rf $target_dir"
    else
      safe_remove_path "$target_dir"
      skill_removed=$((skill_removed + 1))
      log_result "removed" "skill" "$name" "removed: $target_dir"
    fi
  fi
}

install_or_uninstall_command() {
  local idx="$1"
  local name="${COMMAND_NAMES[$idx]}"
  local file_name="${COMMAND_FILE_NAMES[$idx]}"
  local source_file="${COMMAND_FILES[$idx]}"
  local target_file="$COMMANDS_TARGET/$file_name.md"

  if [[ "$ACTION" == "install" ]]; then
    local exists=0
    if [[ -e "$target_file" || -L "$target_file" ]]; then
      exists=1
    fi

    if [[ $exists -eq 1 ]]; then
      if [[ "$MODE" == "link" ]] && is_symlink_to "$target_file" "$source_file"; then
        command_unchanged=$((command_unchanged + 1))
        log_result "unchanged" "command" "$name" "already linked: $target_file"
        return
      fi

      if [[ "$MODE" == "copy" && -f "$target_file" && ! -L "$target_file" ]] && files_equal "$source_file" "$target_file"; then
        command_unchanged=$((command_unchanged + 1))
        log_result "unchanged" "command" "$name" "already installed: $target_file"
        return
      fi

      if [[ $FORCE -ne 1 ]]; then
        command_error=$((command_error + 1))
        log_result "error" "command" "$name" "target exists ($target_file); use --force to replace"
        return
      fi

      if [[ $DRY_RUN -eq 1 ]]; then
        printf '[dry-run] rm -rf %s\n' "$target_file"
      else
        safe_remove_path "$target_file"
      fi
    fi

    if [[ "$MODE" == "copy" ]]; then
      if [[ $DRY_RUN -eq 1 ]]; then
        command_installed=$((command_installed + 1))
        log_result "installed" "command" "$name" "[dry-run] cp $source_file $target_file"
      elif cp "$source_file" "$target_file"; then
        command_installed=$((command_installed + 1))
        log_result "installed" "command" "$name" "copied: $target_file"
      else
        command_error=$((command_error + 1))
        log_result "error" "command" "$name" "failed to copy to $target_file"
      fi
    else
      if [[ $DRY_RUN -eq 1 ]]; then
        command_installed=$((command_installed + 1))
        log_result "installed" "command" "$name" "[dry-run] ln -s $source_file $target_file"
      elif ln -s "$source_file" "$target_file"; then
        command_installed=$((command_installed + 1))
        log_result "installed" "command" "$name" "linked: $target_file -> $source_file"
      else
        command_error=$((command_error + 1))
        log_result "error" "command" "$name" "failed to link $source_file to $target_file"
      fi
    fi
  else
    if [[ ! -e "$target_file" && ! -L "$target_file" ]]; then
      command_skipped=$((command_skipped + 1))
      log_result "skipped" "command" "$name" "not installed: $target_file"
      return
    fi

    local removable=0
    if [[ $FORCE -eq 1 ]]; then
      removable=1
    elif [[ -L "$target_file" ]] && is_symlink_to "$target_file" "$source_file"; then
      removable=1
    elif [[ -f "$target_file" && ! -L "$target_file" ]]; then
      if files_equal "$source_file" "$target_file"; then
        removable=1
      else
        local target_frontmatter_name
        target_frontmatter_name="$(extract_frontmatter_name "$target_file" || true)"
        if [[ "$target_frontmatter_name" == trailofbits:* ]]; then
          removable=1
        fi
      fi
    fi

    if [[ $removable -ne 1 ]]; then
      command_error=$((command_error + 1))
      log_result "error" "command" "$name" "refusing to remove unmanaged path ($target_file); use --force"
      return
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
      command_removed=$((command_removed + 1))
      log_result "removed" "command" "$name" "[dry-run] rm -rf $target_file"
    else
      safe_remove_path "$target_file"
      command_removed=$((command_removed + 1))
      log_result "removed" "command" "$name" "removed: $target_file"
    fi
  fi
}

print_summary() {
  echo
  echo "Summary:"

  if [[ $INSTALL_SKILLS -eq 1 ]]; then
    echo "  skills:"
    printf '    installed: %d\n' "$skill_installed"
    printf '    removed: %d\n' "$skill_removed"
    printf '    unchanged: %d\n' "$skill_unchanged"
    printf '    skipped: %d\n' "$skill_skipped"
    printf '    error: %d\n' "$skill_error"
  fi

  if [[ $INSTALL_COMMANDS -eq 1 ]]; then
    echo "  commands:"
    printf '    installed: %d\n' "$command_installed"
    printf '    removed: %d\n' "$command_removed"
    printf '    unchanged: %d\n' "$command_unchanged"
    printf '    skipped: %d\n' "$command_skipped"
    printf '    error: %d\n' "$command_error"
  fi

  if [[ $INSTALL_COMMANDS -eq 1 && ${#SELECTED_COMMAND_INDEXES[@]} -eq 0 ]]; then
    echo
    echo "Note: no compatible commands matched the selected filters."
  fi
}

# --- Argument parsing ---

SOURCE="remote"
REPO="trailofbits/skills"
REF="main"
# Tilde is expanded later by expand_path()
# shellcheck disable=SC2088
SKILLS_TARGET="~/.config/opencode/skills"
# shellcheck disable=SC2088
COMMANDS_TARGET="~/.config/opencode/commands"
ACTION="install"
MODE="copy"
BUNDLE=""
DRY_RUN=0
FORCE=0
LIST_ONLY=0
ALL=0
INSTALL_SKILLS=1
INSTALL_COMMANDS=1
INCLUDE_INCOMPATIBLE_COMMANDS=0

declare -a PLUGIN_FILTERS=()
declare -a SKILL_FILTERS=()
declare -a COMMAND_FILTERS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)
      LIST_ONLY=1
      shift
      ;;
    --bundle)
      [[ $# -ge 2 ]] || fail "--bundle requires a value"
      BUNDLE="$2"
      shift 2
      ;;
    --plugin)
      [[ $# -ge 2 ]] || fail "--plugin requires a value"
      PLUGIN_FILTERS+=("$2")
      shift 2
      ;;
    --skill)
      [[ $# -ge 2 ]] || fail "--skill requires a value"
      SKILL_FILTERS+=("$2")
      shift 2
      ;;
    --command)
      [[ $# -ge 2 ]] || fail "--command requires a value"
      COMMAND_FILTERS+=("$2")
      shift 2
      ;;
    --all)
      ALL=1
      shift
      ;;
    --target | --skills-target)
      [[ $# -ge 2 ]] || fail "$1 requires a value"
      SKILLS_TARGET="$2"
      shift 2
      ;;
    --commands-target)
      [[ $# -ge 2 ]] || fail "--commands-target requires a value"
      COMMANDS_TARGET="$2"
      shift 2
      ;;
    --skills-only)
      INSTALL_SKILLS=1
      INSTALL_COMMANDS=0
      shift
      ;;
    --commands-only)
      INSTALL_SKILLS=0
      INSTALL_COMMANDS=1
      shift
      ;;
    --include-incompatible-commands)
      INCLUDE_INCOMPATIBLE_COMMANDS=1
      shift
      ;;
    --source)
      [[ $# -ge 2 ]] || fail "--source requires a value"
      SOURCE="$2"
      shift 2
      ;;
    --repo)
      [[ $# -ge 2 ]] || fail "--repo requires a value"
      REPO="$2"
      shift 2
      ;;
    --ref)
      [[ $# -ge 2 ]] || fail "--ref requires a value"
      REF="$2"
      shift 2
      ;;
    --copy)
      MODE="copy"
      shift
      ;;
    --link | --symlink)
      MODE="link"
      shift
      ;;
    --uninstall)
      ACTION="uninstall"
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

# --- Validate arguments ---

if [[ "$SOURCE" != "remote" && "$SOURCE" != "local" ]]; then
  fail "--source must be 'remote' or 'local'"
fi

if [[ "$BUNDLE" != "" && "$BUNDLE" != "smart-contracts" ]]; then
  fail "Unsupported bundle '$BUNDLE' (supported: smart-contracts)"
fi

if [[ $ALL -eq 1 && ("$BUNDLE" != "" || ${#PLUGIN_FILTERS[@]} -gt 0 || ${#SKILL_FILTERS[@]} -gt 0 || ${#COMMAND_FILTERS[@]} -gt 0) ]]; then
  fail "--all cannot be combined with --bundle, --plugin, --skill, or --command"
fi

if [[ "$MODE" == "link" && "$SOURCE" != "local" ]]; then
  fail "--link is only supported with --source local"
fi

if [[ $INSTALL_SKILLS -eq 0 && $INSTALL_COMMANDS -eq 0 ]]; then
  fail "Nothing to do: choose one of --skills-only or --commands-only"
fi

if [[ "$SOURCE" == "remote" ]]; then
  if [[ ! "$REPO" =~ ^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$ ]]; then
    fail "--repo must match owner/repo format (got '$REPO')"
  fi
  if [[ ! "$REF" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
    fail "--ref contains invalid characters (got '$REF')"
  fi
fi

SKILLS_TARGET="$(expand_path "$SKILLS_TARGET")"
COMMANDS_TARGET="$(expand_path "$COMMANDS_TARGET")"

# --- Fetch source ---

TMP_DIR=""
cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

SOURCE_ROOT=""

if [[ "$SOURCE" == "remote" ]]; then
  command -v curl >/dev/null 2>&1 || fail "curl is required for --source remote"
  command -v tar >/dev/null 2>&1 || fail "tar is required for --source remote"
  command -v find >/dev/null 2>&1 || fail "find is required"
  command -v grep >/dev/null 2>&1 || fail "grep is required"
  command -v cmp >/dev/null 2>&1 || fail "cmp is required"

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/opencode-skills.XXXXXX")"
  ARCHIVE_URL="https://codeload.github.com/${REPO}/tar.gz/${REF}"
  ARCHIVE_PATH="$TMP_DIR/source.tar.gz"

  if ! curl -fsSL "$ARCHIVE_URL" -o "$ARCHIVE_PATH"; then
    fail "Failed to download archive from $ARCHIVE_URL"
  fi

  if ! tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"; then
    fail "Failed to extract downloaded archive"
  fi

  mapfile -t _extracted_dirs < <(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d)
  SOURCE_ROOT="${_extracted_dirs[0]:-}"
  [[ -n "$SOURCE_ROOT" ]] || fail "Could not locate extracted repository root"
else
  command -v find >/dev/null 2>&1 || fail "find is required"
  command -v grep >/dev/null 2>&1 || fail "grep is required"
  command -v cmp >/dev/null 2>&1 || fail "cmp is required"

  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  SOURCE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
  if [[ ! -d "$SOURCE_ROOT/plugins" ]]; then
    fail "Local source root is invalid: $SOURCE_ROOT (expected plugins/ directory)"
  fi
fi

if [[ ! -d "$SOURCE_ROOT/plugins" ]]; then
  fail "No plugins directory found at $SOURCE_ROOT/plugins"
fi

# --- Discover skills ---

declare -a SKILL_NAMES=()
declare -a SKILL_PLUGINS=()
declare -a SKILL_DIRS=()
declare -a SKILL_FILES=()

mapfile -t _skill_files < <(find "$SOURCE_ROOT/plugins" -type f -name 'SKILL.md' | sort)
if [[ ${#_skill_files[@]} -eq 0 ]]; then
  fail "No SKILL.md files found under $SOURCE_ROOT/plugins"
fi

for skill_file in "${_skill_files[@]}"; do
  rel_path="${skill_file#"$SOURCE_ROOT/plugins/"}"
  plugin_name="${rel_path%%/*}"
  skill_dir="$(cd "$(dirname "$skill_file")" && pwd -P)"

  skill_name="$(extract_frontmatter_name "$skill_file" || true)"
  if [[ -z "$skill_name" ]]; then
    fail "Could not read frontmatter name from $skill_file"
  fi

  if [[ ! "$skill_name" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
    fail "Invalid skill name '$skill_name' in $skill_file"
  fi

  if ((${#skill_name} > 64)); then
    fail "Skill name '$skill_name' exceeds 64 characters ($skill_file)"
  fi

  # OpenCode requires skill directory name to match frontmatter name
  source_dir_name="$(basename "$skill_dir")"
  if [[ "$source_dir_name" != "$skill_name" ]]; then
    printf 'Warning: skill dir "%s" != frontmatter name "%s" (%s)\n' \
      "$source_dir_name" "$skill_name" "$skill_file" >&2
  fi

  if [[ ${#SKILL_NAMES[@]} -gt 0 ]] && contains_exact "$skill_name" "${SKILL_NAMES[@]}"; then
    fail "Duplicate skill name detected: $skill_name"
  fi

  SKILL_NAMES+=("$skill_name")
  SKILL_PLUGINS+=("$plugin_name")
  SKILL_DIRS+=("$skill_dir")
  SKILL_FILES+=("$skill_file")
done

# --- Discover commands ---

declare -a COMMAND_NAMES=()
declare -a COMMAND_FILE_NAMES=()
declare -a COMMAND_PLUGINS=()
declare -a COMMAND_FILES=()
declare -a COMMAND_REFERENCED_SKILLS=()
declare -a COMMAND_COMPATIBLE=()

mapfile -t _command_files < <(find "$SOURCE_ROOT/plugins" -type f -path '*/commands/*.md' | sort)

for command_file in "${_command_files[@]}"; do
  rel_path="${command_file#"$SOURCE_ROOT/plugins/"}"
  plugin_name="${rel_path%%/*}"
  command_file_name="$(basename "$command_file" .md)"

  command_frontmatter_name="$(extract_frontmatter_name "$command_file" || true)"
  if [[ -n "$command_frontmatter_name" ]]; then
    command_name="$command_frontmatter_name"
  else
    command_name="$command_file_name"
  fi

  command_refs="$(extract_command_referenced_skills "$command_file")"

  if is_command_compatible_with_opencode "$command_file"; then
    command_compatible="1"
  else
    command_compatible="0"
  fi

  COMMAND_NAMES+=("$command_name")
  COMMAND_FILE_NAMES+=("$command_file_name")
  COMMAND_PLUGINS+=("$plugin_name")
  COMMAND_FILES+=("$command_file")
  COMMAND_REFERENCED_SKILLS+=("$command_refs")
  COMMAND_COMPATIBLE+=("$command_compatible")
done

# --- Validate cross-references ---

for idx in "${!COMMAND_NAMES[@]}"; do
  command_name="${COMMAND_NAMES[$idx]}"
  command_plugin="${COMMAND_PLUGINS[$idx]}"
  refs_csv="${COMMAND_REFERENCED_SKILLS[$idx]}"

  if [[ -z "$refs_csv" ]]; then
    continue
  fi

  IFS=',' read -r -a refs <<<"$refs_csv"
  for ref in "${refs[@]-}"; do
    if [[ -z "$ref" ]]; then
      continue
    fi

    referenced_skill_index=""
    for skill_idx in "${!SKILL_NAMES[@]}"; do
      if [[ "${SKILL_NAMES[$skill_idx]}" == "$ref" ]]; then
        referenced_skill_index="$skill_idx"
        break
      fi
    done

    if [[ -z "$referenced_skill_index" ]]; then
      fail "Command '$command_name' references unknown skill '$ref'"
    fi

    referenced_skill_plugin="${SKILL_PLUGINS[$referenced_skill_index]}"
    if [[ "$referenced_skill_plugin" != "$command_plugin" ]]; then
      fail "Command '$command_name' in plugin '$command_plugin' references skill '$ref' in plugin '$referenced_skill_plugin'"
    fi
  done
done

# --- Build known plugins and validate filters ---

declare -a KNOWN_PLUGINS=()
for plugin_name in "${SKILL_PLUGINS[@]}"; do
  if [[ ${#KNOWN_PLUGINS[@]} -eq 0 ]] || ! contains_exact "$plugin_name" "${KNOWN_PLUGINS[@]}"; then
    KNOWN_PLUGINS+=("$plugin_name")
  fi
done
for plugin_name in "${COMMAND_PLUGINS[@]}"; do
  if [[ ${#KNOWN_PLUGINS[@]} -eq 0 ]] || ! contains_exact "$plugin_name" "${KNOWN_PLUGINS[@]}"; then
    KNOWN_PLUGINS+=("$plugin_name")
  fi
done

if [[ ${#PLUGIN_FILTERS[@]} -gt 0 ]]; then
  for plugin_filter in "${PLUGIN_FILTERS[@]}"; do
    if ! contains_exact "$plugin_filter" "${KNOWN_PLUGINS[@]}"; then
      fail "Unknown plugin filter: $plugin_filter"
    fi
  done
fi

if [[ ${#SKILL_FILTERS[@]} -gt 0 ]]; then
  for skill_filter in "${SKILL_FILTERS[@]}"; do
    if ! contains_exact "$skill_filter" "${SKILL_NAMES[@]}"; then
      fail "Unknown skill filter: $skill_filter"
    fi
  done
fi

if [[ ${#COMMAND_FILTERS[@]} -gt 0 ]]; then
  for command_filter in "${COMMAND_FILTERS[@]}"; do
    found=0
    for idx in "${!COMMAND_NAMES[@]}"; do
      if [[ "${COMMAND_NAMES[$idx]}" == "$command_filter" || "${COMMAND_FILE_NAMES[$idx]}" == "$command_filter" ]]; then
        found=1
        break
      fi
    done
    if [[ $found -eq 0 ]]; then
      fail "Unknown command filter: $command_filter"
    fi
  done
fi

# --- Select items ---

declare -a SELECTED_SKILL_INDEXES=()
for idx in "${!SKILL_NAMES[@]}"; do
  plugin_name="${SKILL_PLUGINS[$idx]}"
  skill_name="${SKILL_NAMES[$idx]}"
  include=1

  if [[ "$BUNDLE" != "" ]] && ! matches_bundle "$BUNDLE" "$plugin_name"; then
    include=0
  fi

  if [[ ${#PLUGIN_FILTERS[@]} -gt 0 ]] && ! contains_exact "$plugin_name" "${PLUGIN_FILTERS[@]}"; then
    include=0
  fi

  if [[ ${#SKILL_FILTERS[@]} -gt 0 ]] && ! contains_exact "$skill_name" "${SKILL_FILTERS[@]}"; then
    include=0
  fi

  if [[ $include -eq 1 ]]; then
    SELECTED_SKILL_INDEXES+=("$idx")
  fi
done

if [[ ${#SELECTED_SKILL_INDEXES[@]} -eq 0 && $INSTALL_SKILLS -eq 1 ]]; then
  fail "No skills matched the selected filters"
fi

declare -a SELECTED_SKILL_NAMES=()
for idx in "${SELECTED_SKILL_INDEXES[@]}"; do
  SELECTED_SKILL_NAMES+=("${SKILL_NAMES[$idx]}")
done

declare -a SELECTED_COMMAND_INDEXES=()
declare -a SKIPPED_INCOMPATIBLE_COMMANDS=()

for idx in "${!COMMAND_NAMES[@]}"; do
  plugin_name="${COMMAND_PLUGINS[$idx]}"
  command_name="${COMMAND_NAMES[$idx]}"
  referenced_skills_csv="${COMMAND_REFERENCED_SKILLS[$idx]}"
  compatible_flag="${COMMAND_COMPATIBLE[$idx]}"
  include=1

  if [[ "$BUNDLE" != "" ]] && ! matches_bundle "$BUNDLE" "$plugin_name"; then
    include=0
  fi

  if [[ ${#PLUGIN_FILTERS[@]} -gt 0 ]] && ! contains_exact "$plugin_name" "${PLUGIN_FILTERS[@]}"; then
    include=0
  fi

  if [[ ${#COMMAND_FILTERS[@]} -gt 0 ]] && ! contains_exact "$command_name" "${COMMAND_FILTERS[@]}"; then
    include=0
    for command_filter in "${COMMAND_FILTERS[@]}"; do
      if [[ "$command_name" == "$command_filter" || "${COMMAND_FILE_NAMES[$idx]}" == "$command_filter" ]]; then
        include=1
        break
      fi
    done
  fi

  if [[ ${#SKILL_FILTERS[@]} -gt 0 ]]; then
    if ! matches_selected_skill_names "$referenced_skills_csv"; then
      include=0
    fi
  fi

  if [[ $include -eq 1 && "$compatible_flag" == "0" && $INCLUDE_INCOMPATIBLE_COMMANDS -eq 0 ]]; then
    SKIPPED_INCOMPATIBLE_COMMANDS+=("$command_name (${plugin_name})")
    include=0
  fi

  if [[ $include -eq 1 ]]; then
    SELECTED_COMMAND_INDEXES+=("$idx")
  fi
done

if [[ $INSTALL_COMMANDS -eq 1 && ${#SELECTED_COMMAND_INDEXES[@]} -gt 0 ]]; then
  declare -a SEEN_COMMAND_NAMES=()
  for idx in "${SELECTED_COMMAND_INDEXES[@]}"; do
    command_name="${COMMAND_NAMES[$idx]}"
    if [[ ${#SEEN_COMMAND_NAMES[@]} -gt 0 ]] && contains_exact "$command_name" "${SEEN_COMMAND_NAMES[@]}"; then
      fail "Selected commands include duplicate command name '$command_name'; refine filters"
    fi
    SEEN_COMMAND_NAMES+=("$command_name")
  done
fi

# --- Print status ---

source_info="$SOURCE"
if [[ "$SOURCE" == "remote" ]]; then
  source_info+=" (${REPO}@${REF})"
fi

mode_info="$MODE"
if [[ "$MODE" == "link" ]]; then
  mode_info+=" (local only)"
fi

printf 'Discovered %d skills and %d commands.\n' "${#SKILL_NAMES[@]}" "${#COMMAND_NAMES[@]}"
printf 'Selected %d skills and %d commands.\n' "${#SELECTED_SKILL_INDEXES[@]}" "${#SELECTED_COMMAND_INDEXES[@]}"
printf 'Action: %s. Mode: %s. Source: %s\n' "$ACTION" "$mode_info" "$source_info"

if [[ $INSTALL_SKILLS -eq 1 ]]; then
  printf 'Skills target: %s\n' "$SKILLS_TARGET"
fi
if [[ $INSTALL_COMMANDS -eq 1 ]]; then
  printf 'Commands target: %s\n' "$COMMANDS_TARGET"
fi

if [[ ${#SKIPPED_INCOMPATIBLE_COMMANDS[@]} -gt 0 ]]; then
  echo
  echo "Skipped incompatible commands (use --include-incompatible-commands to include):"
  for item in "${SKIPPED_INCOMPATIBLE_COMMANDS[@]}"; do
    printf '  - %s\n' "$item"
  done
fi

# --- List mode ---

if [[ $LIST_ONLY -eq 1 ]]; then
  if [[ $INSTALL_SKILLS -eq 1 ]]; then
    echo
    echo "Skills:"
    printf '%-36s %s\n' "SKILL" "PLUGIN"
    printf '%-36s %s\n' "-----" "------"
    for idx in "${SELECTED_SKILL_INDEXES[@]}"; do
      printf '%-36s %s\n' "${SKILL_NAMES[$idx]}" "${SKILL_PLUGINS[$idx]}"
    done
  fi

  if [[ $INSTALL_COMMANDS -eq 1 ]]; then
    echo
    echo "Commands:"
    printf '%-28s %-28s %s\n' "COMMAND" "PLUGIN" "SKILL REFERENCES"
    printf '%-28s %-28s %s\n' "-------" "------" "----------------"
    for idx in "${SELECTED_COMMAND_INDEXES[@]}"; do
      cmd_refs="${COMMAND_REFERENCED_SKILLS[$idx]}"
      if [[ -z "$cmd_refs" ]]; then
        cmd_refs="(none detected)"
      fi
      printf '%-28s %-28s %s\n' "/${COMMAND_NAMES[$idx]}" "${COMMAND_PLUGINS[$idx]}" "$cmd_refs"
    done
  fi
  exit 0
fi

# --- Create target directories ---

if [[ "$ACTION" == "install" ]]; then
  if [[ $INSTALL_SKILLS -eq 1 && ! -d "$SKILLS_TARGET" ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      printf '[dry-run] mkdir -p %s\n' "$SKILLS_TARGET"
    else
      mkdir -p "$SKILLS_TARGET"
    fi
  fi

  if [[ $INSTALL_COMMANDS -eq 1 && ! -d "$COMMANDS_TARGET" ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      printf '[dry-run] mkdir -p %s\n' "$COMMANDS_TARGET"
    else
      mkdir -p "$COMMANDS_TARGET"
    fi
  fi
fi

# --- Install/uninstall ---

skill_installed=0
skill_removed=0
skill_unchanged=0
skill_skipped=0
skill_error=0

command_installed=0
command_removed=0
command_unchanged=0
command_skipped=0
command_error=0

log_result() {
  local status="$1"
  local component="$2"
  local name="$3"
  local message="$4"
  printf '[%s] %s %s: %s\n' "$status" "$component" "$name" "$message"
}

if [[ $INSTALL_SKILLS -eq 1 ]]; then
  for idx in "${SELECTED_SKILL_INDEXES[@]}"; do
    install_or_uninstall_skill "$idx"
  done
fi

if [[ $INSTALL_COMMANDS -eq 1 ]]; then
  for idx in "${SELECTED_COMMAND_INDEXES[@]}"; do
    install_or_uninstall_command "$idx"
  done
fi

print_summary

if [[ $skill_error -gt 0 || $command_error -gt 0 ]]; then
  exit 1
fi
