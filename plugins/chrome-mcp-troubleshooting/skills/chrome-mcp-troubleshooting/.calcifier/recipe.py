# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import platform
from getpass import getuser
from pathlib import Path
from typing import Literal

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    run_command,
    step,
)

APP_CONFIG = "com.anthropic.claude_browser_extension.json"
CODE_CONFIG = "com.anthropic.claude_code_browser_extension.json"
WRAPPER = (
    "#!/bin/bash\n"
    "LATEST=$(ls -t ~/.local/share/claude/versions/ 2>/dev/null | head -1)\n"
    'exec "$HOME/.local/share/claude/versions/$LATEST" --chrome-native-host\n'
)


@output_type
class Observation:
    label: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


@output_type
class Assessment:
    explanation: str
    next_steps: list[str]
    unverified: list[str]


@output_type
class Result:
    assessment: Assessment
    before: list[Observation]
    actions: list[Observation]
    after: list[Observation]


@step
def command(label: str, argv: list[str], mutating: bool = False) -> Observation:
    outcome = run_command(argv, timeout_seconds=60, mutating=mutating)
    return Observation(label, argv, outcome.exit_code, outcome.stdout, outcome.stderr)


@step
def inspect_state(home: Path, code_socket: Path, app_socket: Path) -> list[Observation]:
    configs = home / "Library/Application Support/Google/Chrome/NativeMessagingHosts"
    scripts = [
        ("native hosts", "ps aux | grep chrome-native-host | grep -v grep"),
        ("open Unix sockets", "lsof -U 2>&1 | grep claude-mcp-browser-bridge"),
        (
            "native host open files",
            "pgrep -f chrome-native-host | xargs -I {} lsof -p {} 2>/dev/null "
            '| grep -E "(sock|claude-mcp)"',
        ),
    ]
    values = [command(label, ["/bin/bash", "-c", script]) for label, script in scripts]
    for label, argv in [
        ("CLI socket", ["ls", "-la", str(code_socket)]),
        ("Cowork sockets", ["ls", "-la", str(app_socket)]),
        ("native messaging configs", ["ls", "-la", str(configs)]),
        (
            "installed CLI versions",
            ["ls", "-lt", str(home / ".local/share/claude/versions")],
        ),
        ("TMPDIR", ["printenv", "TMPDIR"]),
    ]:
        values.append(command(label, argv))
    paths = sorted(configs.glob("com.anthropic*.json*"))
    paths.append(home / ".claude/chrome/chrome-native-host")
    for path in paths:
        try:
            if not path.resolve().is_relative_to(home):
                raise ValueError("Reference resolves outside the declared home directory")
            text = path.read_text(encoding="utf-8")
            values.append(Observation(f"file: {path}", [], 0, text, ""))
        except (OSError, ValueError) as exc:
            values.append(Observation(f"file: {path}", [], 1, "", str(exc)))
    return values


@step
def repair(
    home: Path, code_socket: Path, app_socket: Path, owner: str, operation: str
) -> list[Observation]:
    configs = home / "Library/Application Support/Google/Chrome/NativeMessagingHosts"
    selected = configs / (CODE_CONFIG if owner == "claude-code" else APP_CONFIG)
    other = configs / (APP_CONFIG if owner == "claude-code" else CODE_CONFIG)
    selected_disabled = selected.with_name(selected.name + ".disabled")
    other_disabled = other.with_name(other.name + ".disabled")
    wrapper = home / ".claude/chrome/chrome-native-host"
    issue = ""
    for path in (selected, other, selected_disabled, other_disabled, wrapper):
        if path.is_symlink() or not path.resolve().is_relative_to(home):
            issue = f"Unsafe repair destination: {path}"
    if not (selected.is_file() or selected_disabled.is_file()):
        issue = f"Selected native messaging config is missing: {selected}"
    if (selected.exists() and selected_disabled.exists()) or (
        other.exists() and other_disabled.exists()
    ):
        issue = "An active config and its disabled backup coexist; no files were overwritten."
    if operation == "reset" and not issue:
        try:
            config_source = selected if selected.is_file() else selected_disabled
            config = json.loads(config_source.read_text(encoding="utf-8"))
            if not isinstance(config, dict) or config.get("path") != str(wrapper):
                issue = "The CLI config does not point to the custom wrapper; review it first."
            if not wrapper.parent.is_dir() or not (home / ".local/share/claude/versions").is_dir():
                issue = "The wrapper directory or installed CLI versions directory is missing."
        except (OSError, ValueError) as exc:
            issue = f"Cannot validate the selected native messaging config: {exc}"
    if issue:
        return [Observation("repair not started", [], 1, "", issue)]
    jobs: list[tuple[str, list[str]]] = []
    if other.exists():
        jobs.append(("disable competing host", ["mv", str(other), str(other_disabled)]))
    if not selected.exists():
        jobs.append(("restore selected host", ["mv", str(selected_disabled), str(selected)]))
    if operation == "reset":
        jobs.extend(
            [
                (
                    "update dynamic wrapper",
                    [
                        "/bin/bash",
                        "-c",
                        'printf "%s" "$2" > "$1" && chmod +x "$1"',
                        "chrome-reset",
                        str(wrapper),
                        WRAPPER,
                    ],
                ),
                ("stop native hosts", ["pkill", "-f", "chrome-native-host"]),
                ("remove Cowork sockets", ["rm", "-rf", str(app_socket)]),
                ("remove CLI socket", ["rm", "-f", str(code_socket)]),
            ]
        )
    jobs.extend(
        [
            ("quit Chrome", ["osascript", "-e", 'quit app "Google Chrome"']),
            ("wait for Chrome", ["sleep", "2"]),
            ("launch Chrome", ["open", "-a", "Google Chrome"]),
        ]
    )
    results = []
    for label, argv in jobs:
        value = command(label, argv, mutating=True)
        results.append(value)
        allowed = (0, 1) if label == "stop native hosts" else (0,)
        if value.exit_code not in allowed:
            break
    return results


@recipe(
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def chrome_mcp_troubleshooting(
    symptom: str = "Browser extension is not connected",
    owner: Literal["claude-code", "cowork"] = "claude-code",
    operation: Literal["diagnose", "switch", "reset"] = "diagnose",
) -> Result:
    if platform.system() != "Darwin":
        fail("This skill supports macOS only; its paths and commands do not apply here.")
    if operation == "reset" and owner != "claude-code":
        fail("The supplied full reset procedure applies only to Claude Code CLI.")
    home = Path.home().resolve()
    user = getuser()
    if not user or "/" in user:
        fail("Cannot construct the account-specific bridge socket paths.")
    temporary = command("expected temporary directory", ["getconf", "DARWIN_USER_TEMP_DIR"])
    if temporary.exit_code != 0:
        fail("getconf DARWIN_USER_TEMP_DIR failed; no repairs were attempted.")
    temp_dir = Path(temporary.stdout.strip())
    if not temp_dir.is_absolute() or not temp_dir.is_dir():
        fail("getconf did not identify an existing absolute temporary directory.")
    temp_dir = temp_dir.resolve()
    code_socket = temp_dir / f"claude-mcp-browser-bridge-{user}"
    app_socket = Path("/tmp") / f"claude-mcp-browser-bridge-{user}"
    before = [temporary] + inspect_state(home, code_socket, app_socket)
    actions: list[Observation] = []
    if operation != "diagnose":
        actions = repair(home, code_socket, app_socket, owner, operation)
    after = inspect_state(home, code_socket, app_socket) if actions else []
    context = prepare_context(
        task=(
            "Assess this Claude in Chrome connectivity problem using the original skill. "
            "Python collected diagnostics and attempted only the explicitly selected operation."
        ),
        prior_results=json.dumps(
            {
                "symptom": symptom,
                "owner": owner,
                "operation": operation,
                "before": [item.model_dump() for item in before],
                "actions": [item.model_dump() for item in actions],
                "after": [item.model_dump() for item in after],
            }
        ),
    )
    answer = agent(
        "worker",
        (
            "Keep the original diagnostic reasoning and checks connected in their stated order. "
            "Interpret all supplied evidence and complete live file texts. Use embedded context "
            "directly; read task.txt when it is not embedded. Search matches are observations, "
            "not exhaustive semantic candidates. Additional read-only checks are allowed. "
            "Do not modify files or restart applications; Python owns the selected repairs. "
            "Return explanation, next_steps, and unverified. Explain failed or skipped actions, "
            "remaining causes, and applicability limits. Account for extension activation, "
            "startup timing, profiles, sessions, wrapper versions, and TMPDIR as instructed. "
            "The extension click and restarting the active CLI remain user actions. Socket or "
            "process existence alone does not verify MCP connectivity; state pending checks."
        ),
        working_directory=home,
        readable_paths=(home, Path("/Applications"), Path("/tmp"), temp_dir),
        required_capabilities=("commands",),
        output=Assessment,
        timeout=3600,
        context=context,
    )
    return emit(Result(answer, before, actions, after), name="chrome-mcp-troubleshooting")


if __name__ == "__main__":
    raise SystemExit(chrome_mcp_troubleshooting.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("1456ace18266e81691c6ba0e5f3ec11df4a51cfa3e50eb511a113f15ab080c68"),
}
_CALCIFIER_RESOURCES = []
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, target-version py311, and line-length 100. The g"
        "enerated recipe must satisfy those checks, including B007,"
        " B905, and SIM102. Keep the Python 3.13 minimum required b"
        "y Calcifier in its generated PEP 723 header. This skill is"
        " distributed independently: do not require another unmerge"
        "d skill recipe. Referenced prose and explicitly provided r"
        "esources may be packaged, while the generated recipe belon"
        "gs only to the requested skill."
    ),
    "sha256": ("46bb4ed4c424344f76192480d2444ca2e0c43d841ba604cdcf68ab9140c9162c"),
}
_CALCIFIER_SUBRECIPES = []
