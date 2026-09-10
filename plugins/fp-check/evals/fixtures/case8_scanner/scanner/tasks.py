"""Network diagnostic tasks for the operations console."""

import subprocess

TOOLS = {
    "ping": "/usr/bin/ping",
    "trace": "/usr/bin/traceroute",
}


def handle_scan(request_args: dict[str, str]) -> str:
    """Handle POST /scan. `tool` picks the binary, `host` is its argument."""
    binary = TOOLS[request_args.get("tool", "")]
    host = request_args.get("host", "")
    return _run_argv(binary, host)


def _run_argv(binary: str, argument: str) -> str:
    """Run `binary` with one argument and return what it printed."""
    done = subprocess.run([binary, argument], capture_output=True, text=True, check=False)
    return done.stdout


def refresh_tool_cache() -> None:
    """Rebuild the local tool cache using the packaged helper script."""
    subprocess.run("/opt/ops/refresh-tools.sh --quiet", shell=True, check=True)
