#!/usr/bin/env bash
set -euo pipefail

# Codex supplies both plugin root variables. Claude Code uses the PATH shims.
[[ -n "${PLUGIN_ROOT:-}" && "$PLUGIN_ROOT" == "${CLAUDE_PLUGIN_ROOT:-}" ]] || exit 0
command -v uv >/dev/null 2>&1 || exit 0
command -v jq >/dev/null 2>&1 || exit 0

command_text=$(jq -r '.tool_input.command | strings')
# Most shell calls need no parse.
case "$command_text" in
  *py* | *pip* | *uv*) ;;
  *) exit 0 ;;
esac
command -v shfmt >/dev/null 2>&1 || exit 0
# Commands are parsed as data. Allow syntax the parser does not recognize.
if ! syntax=$(printf '%s\n' "$command_text" | shfmt -ln=bash --tojson 2>/dev/null); then
  exit 0
fi

# shellcheck disable=SC2016 # Dollar expressions belong to jq.
reason=$(jq -r '
  def static_word:
    if any(.[]; . == null) then null else join("") end;
  def literal:
    if .Type == "Lit" or (.Type == "SglQuoted" and (.Dollar // false | not)) then .Value
    elif .Type == "DblQuoted" then [.Parts[]? | literal] | static_word
    else null end;
  def argument:
    ([.Parts[] | literal] | static_word) as $text
    | (.Parts[0] | if .Type == "DblQuoted" then .Parts[0] else . end | literal) as $prefix
    | {text: $text, assignment: ($text // $prefix // "" | test("^[A-Za-z_][A-Za-z0-9_]*="))};
  def argv:
    [.Args[]? | argument];
  def env_args:
    if .[0].text == "--" then .[1:]
    elif .[0].text == "-u" or .[0].text == "--unset" then .[2:] | env_args
    elif .[0].assignment or (.[0].text // "" | test("^(-i|--ignore-environment|--unset=.+)$"))
      then .[1:] | env_args
    else . end;
  def unwrap:
    if .[0].text == "env" or .[0].text == "/usr/bin/env" then .[1:] | env_args | unwrap
    elif .[0].text == "command" or .[0].text == "exec" then
      if .[1].text == "--" then .[2:] | unwrap
      elif (.[1].text // "" | startswith("-") | not) then .[1:] | unwrap
      else . end
    else . end;
  def python_mode:
    if .[0] == "--" then "script"
    elif .[0] == "-" then "stdin"
    elif .[0] == "--version" or .[0] == "--help" then "inspect"
    elif .[0] == "-W" or .[0] == "-X" or .[0] == "--check-hash-based-pycs" then .[2:] | python_mode
    elif (.[0] // "" | test("^-[bBdEiIOPqRsSuvx]*m")) then
      (.[0] | sub("^-[bBdEiIOPqRsSuvx]*m"; "")) as $module
      | if ($module == "" and .[1] == "pip") or $module == "pip" then "pip" else "module" end
    elif (.[0] // "" | test("^-[bBdEiIOPqRsSuvx]*c")) then "inline"
    elif (.[0] // "" | test("^-[bBdEiIOPqRsSuvx]*[hV]$")) then "inspect"
    elif (.[0] // "" | startswith("-")) then .[1:] | python_mode
    else "script" end;
  def pip_advice($action):
    if $action == "install" then "Use uv add PACKAGE, or uv run --with PACKAGE for one-off use."
    elif $action == "uninstall" then "Use uv remove PACKAGE."
    elif $action == "freeze" then "Use uv export."
    else "Use uv add, uv remove, or uv sync to manage project dependencies." end;
  def violation:
    .[0] as $exe | .[1:] as $args
    | if ($exe // "" | test("^((/usr/bin|/usr/local/bin|/opt/homebrew/bin)/)?python(3(\\.[0-9]+)?)?$")) then
        ($args | python_mode) as $mode
        | if $mode == "script" then "Use uv run python for scripts or the REPL. For scripts with inline dependencies, use uv run SCRIPT."
          elif $mode == "pip" then pip_advice(null)
          else empty end
      elif ($exe // "" | test("^((/usr/bin|/usr/local/bin|/opt/homebrew/bin)/)?pip(3(\\.[0-9]+)?)?$")) then pip_advice($args[0])
      elif ($exe // "" | test("^((/usr/local/bin|/opt/homebrew/bin)/)?pipx$")) then
        if $args[0] == "run" then "Use uvx TOOL."
        elif $args[0] == "install" then "Use uv tool install PACKAGE."
        elif $args[0] == "uninstall" then "Use uv tool uninstall PACKAGE."
        elif $args[0] == "upgrade" then "Use uv tool upgrade PACKAGE."
        elif $args[0] == "upgrade-all" then "Use uv tool upgrade --all."
        elif $args[0] == "ensurepath" then "Use uv tool update-shell."
        elif $args[0] == "inject" then "Use uv tool install --with DEPENDENCY PACKAGE."
        elif $args[0] == "list" then "Use uv tool list."
        else "Use uv tool to manage standalone Python tools." end
      elif ($exe // "" | test("^((/usr/local/bin|/opt/homebrew/bin)/)?uv$")) and $args[0] == "pip"
        and (any($args[1:][]; (. // "" | test("^(--project|--directory|--target|-t)(=|$)"))) | not)
        then pip_advice($args[1])
      else empty end;
  # Leave deferred bodies and fallback branches to the shell. Older shfmt
  # versions encode the || operator as the token number 11.
  def command_children:
    if type == "array" then .[]
    elif type != "object" or .Type == "FuncDecl" then empty
    elif .Type == "IfClause" then .Cond
    elif .Type == "CaseClause" then .Word
    elif .Type == "BinaryCmd" and (.Op == "||" or .Op == 11) then .X
    else .[] end;
  first(recurse(command_children) | objects | select(.Type? == "CallExpr") | argv | unwrap | map(.text) | violation) // empty
' <<<"$syntax")

if [[ -n "$reason" ]]; then
  # shellcheck disable=SC2016 # Dollar expressions belong to jq.
  jq -n --arg reason "$reason" '{hookSpecificOutput: {
		hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason
	}}'
fi
