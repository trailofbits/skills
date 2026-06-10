#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Check that this Claude plugin marketplace loads through Codex."""

from __future__ import annotations

import argparse
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

MARKETPLACE = Path(".claude-plugin/marketplace.json")
MANIFEST = Path(".claude-plugin/plugin.json")
DEFAULT_MCP = Path(".mcp.json")


def read_rpc_message(proc: subprocess.Popen[str], log_path: Path, timeout: float) -> dict[str, Any]:
    if proc.stdout is None:
        raise RuntimeError("codex app-server stdout is unavailable")
    deadline = time.monotonic() + timeout
    while True:
        log_tail = "\n".join(
            log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-80:]
        )
        if proc.poll() is not None:
            raise RuntimeError(f"codex app-server exited with {proc.returncode}\n{log_tail}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for codex app-server\n{log_tail}")
        ready, _, _ = select.select([proc.stdout], [], [], min(remaining, 0.2))
        if not ready:
            continue
        line = proc.stdout.readline().strip()
        if not line.startswith("{"):
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict):
            return message


def expected_mcp_servers(plugin_root: Path, errors: list[str]) -> set[str]:
    manifest_path = plugin_root / MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{plugin_root.name}: cannot read {manifest_path}: {exc}")
        return set()

    mcp_path = plugin_root / DEFAULT_MCP
    if isinstance(manifest, dict) and "mcpServers" in manifest:
        configured = manifest["mcpServers"]
        if not isinstance(configured, str) or not configured:
            errors.append(
                f"{plugin_root.name}: manifest mcpServers must be a non-empty string path"
            )
            return set()
        if Path(configured).is_absolute():
            errors.append(f"{plugin_root.name}: manifest mcpServers must be relative")
            return set()
        mcp_path = plugin_root / configured
    elif not mcp_path.exists():
        return set()

    try:
        data = json.loads(mcp_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{plugin_root.name}: cannot read {mcp_path}: {exc}")
        return set()
    if not isinstance(data, dict):
        errors.append(f"{plugin_root.name}: {mcp_path} must be a JSON object")
        return set()
    servers = data.get("mcpServers", data)
    if not isinstance(servers, dict):
        errors.append(f"{plugin_root.name}: {mcp_path} mcpServers must be an object")
        return set()
    return set(servers)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--codex-bin", default=os.environ.get("CODEX_BIN", "codex"))
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    repo = args.repo.resolve()
    codex_bin = shutil.which(args.codex_bin) if os.sep not in args.codex_bin else args.codex_bin
    if codex_bin is None:
        print(f"ERROR: codex binary not found: {args.codex_bin}", file=sys.stderr)
        return 1

    marketplace_path = repo / MARKETPLACE
    marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
    marketplace_name = marketplace["name"]
    plugin_names = [plugin["name"] for plugin in marketplace["plugins"]]
    if not plugin_names:
        print(f"ERROR: no plugins listed in {MARKETPLACE}", file=sys.stderr)
        return 1

    errors: list[str] = []
    loaded_plugin_count = 0
    loaded_skill_count = 0
    loaded_mcp_count = 0
    request_id = 0
    tmp = tempfile.TemporaryDirectory(prefix="codex-load-check-")
    temp_root = Path(tmp.name)
    home = temp_root / "home"
    codex_home = temp_root / "codex-home"
    home.mkdir()
    codex_home.mkdir()
    (codex_home / "config.toml").write_text(
        "[features]\nplugins = true\nplugin_hooks = true\n",
        encoding="utf-8",
    )
    log_path = temp_root / "app-server.stderr.log"
    log_file = log_path.open("w+", encoding="utf-8")

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "CODEX_HOME": str(codex_home),
            "CODEX_APP_SERVER_DISABLE_MANAGED_CONFIG": "1",
            "RUST_LOG": env.get("RUST_LOG", "warn"),
        }
    )
    proc = subprocess.Popen(
        [
            codex_bin,
            "app-server",
            "--listen",
            "stdio://",
            "--enable",
            "plugins",
            "--enable",
            "plugin_hooks",
        ],
        cwd=str(repo),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=log_file,
        text=True,
        bufsize=1,
    )

    def write(message: dict[str, Any]) -> None:
        if proc.stdin is None:
            raise RuntimeError("codex app-server stdin is unavailable")
        proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        proc.stdin.flush()

    def request(method: str, params: dict[str, Any]) -> Any:
        nonlocal request_id
        request_id += 1
        write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        skipped_errors: list[str] = []
        while True:
            try:
                message = read_rpc_message(proc, log_path, args.timeout)
            except TimeoutError as exc:
                if skipped_errors:
                    detail = "\n".join(skipped_errors[-3:])
                    raise TimeoutError(f"{exc}\nskipped error messages:\n{detail}") from exc
                raise
            if message.get("id") != request_id:
                if "error" in message:
                    skipped_errors.append(json.dumps(message)[:500])
                continue
            if "error" in message:
                raise RuntimeError(f"{method} failed: {message['error']}")
            return message.get("result")

    try:
        request(
            "initialize",
            {
                "clientInfo": {
                    "name": "codex-load-check",
                    "title": "Codex Load Check",
                    "version": "0",
                },
                "capabilities": {
                    "experimentalApi": True,
                    "requestAttestation": False,
                    "optOutNotificationMethods": [],
                },
            },
        )
        write({"jsonrpc": "2.0", "method": "initialized"})

        listed = request("plugin/list", {"cwds": [str(repo)], "marketplaceKinds": ["local"]})
        for error in listed.get("marketplaceLoadErrors", []):
            errors.append(f"plugin/list: {error.get('marketplacePath')}: {error.get('message')}")

        matching = [
            item for item in listed.get("marketplaces", []) if item.get("name") == marketplace_name
        ]
        if not matching:
            errors.append(f"plugin/list: missing marketplace {marketplace_name!r}")
        else:
            listed_plugins = {
                plugin.get("name") for item in matching for plugin in item.get("plugins", [])
            }
            missing = sorted(set(plugin_names) - listed_plugins)
            if missing:
                errors.append("plugin/list: missing plugins: " + ", ".join(missing))

        for plugin_name in plugin_names:
            plugin_root = repo / "plugins" / plugin_name
            skill_paths = list((plugin_root / "skills").rglob("SKILL.md"))
            expected_skills = len(skill_paths)
            expected_mcp = expected_mcp_servers(plugin_root, errors)
            try:
                plugin = request(
                    "plugin/read",
                    {
                        "marketplacePath": str(marketplace_path),
                        "remoteMarketplaceName": None,
                        "pluginName": plugin_name,
                    },
                ).get("plugin", {})
            except Exception as exc:  # noqa: BLE001 - CI should show RPC failures.
                errors.append(f"{plugin_name}: {exc}")
                continue

            loaded_skills = len(plugin.get("skills", []))
            loaded_mcp_value = plugin.get("mcpServers", {})
            loaded_mcp = (
                set(loaded_mcp_value) if isinstance(loaded_mcp_value, (dict, list)) else set()
            )

            if loaded_skills != expected_skills:
                errors.append(
                    f"{plugin_name}: loaded {loaded_skills} skills, expected {expected_skills}"
                )
            if loaded_mcp != expected_mcp:
                errors.append(
                    f"{plugin_name}: loaded MCP servers {sorted(loaded_mcp)}, "
                    f"expected {sorted(expected_mcp)}"
                )
            loaded_plugin_count += 1
            loaded_skill_count += loaded_skills
            loaded_mcp_count += len(loaded_mcp)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        log_file.close()
        tmp.cleanup()

    print(
        f"loaded marketplace {marketplace_name} with {loaded_plugin_count} plugins, "
        f"{loaded_skill_count} skills, and {loaded_mcp_count} MCP servers"
    )
    if errors:
        print(f"\nFound {len(errors)} Codex loadability error(s):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("All Codex loadability checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
