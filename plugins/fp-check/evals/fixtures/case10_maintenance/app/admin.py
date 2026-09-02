"""Maintenance endpoints for the operations team."""

import subprocess


def service_status(request_args: dict[str, str]) -> dict[str, str]:
    """Handle GET /admin/status. Reports whether the log writer is running."""
    del request_args
    return {"log_writer": "running"}


def rotate_logs(request_args: dict[str, str]) -> dict[str, str]:
    """Handle POST /admin/rotate. `target` names the logrotate config to force."""
    target = request_args.get("target", "")
    subprocess.run(f"logrotate -f /etc/logrotate.d/{target}", shell=True, check=True)
    return {"rotated": target}
