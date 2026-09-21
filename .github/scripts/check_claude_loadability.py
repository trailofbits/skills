#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Check that this marketplace installs and loads through Claude Code."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

MARKETPLACE = Path(".claude-plugin/marketplace.json")
MANIFEST = Path(".claude-plugin/plugin.json")
DEFAULT_MCP = Path(".mcp.json")


def run_claude(claude_bin: str, repo: Path, env: dict[str, str], args: list[str]) -> str:
    result = subprocess.run(
        [claude_bin, *args],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise RuntimeError(f"claude {' '.join(args)} failed with {result.returncode}")
    return result.stdout


def parse_json_output(output: str, context: str) -> Any:
    text = output.strip()
    if not text:
        raise RuntimeError(f"{context}: expected JSON output, got empty response")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        starts = [index for index in (text.find("["), text.find("{")) if index != -1]
        if not starts:
            raise
        return json.loads(text[min(starts) :])


def expected_mcp_servers(plugin_root: Path, errors: list[str]) -> set[str]:
    expected: set[str] = set()
    default_mcp = plugin_root / DEFAULT_MCP
    if default_mcp.is_file():
        try:
            data = json.loads(default_mcp.read_text(encoding="utf-8"))
            servers = data.get("mcpServers", data) if isinstance(data, dict) else {}
            if isinstance(servers, dict):
                expected.update(servers)
            else:
                errors.append(f"{plugin_root.name}: {default_mcp} mcpServers must be an object")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{plugin_root.name}: cannot read {default_mcp}: {exc}")

    manifest_path = plugin_root / MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{plugin_root.name}: cannot read {manifest_path}: {exc}")
        return expected

    if not isinstance(manifest, dict) or "mcpServers" not in manifest:
        return expected

    configured = manifest["mcpServers"]
    specs = configured if isinstance(configured, list) else [configured]
    for spec in specs:
        if isinstance(spec, str):
            if Path(spec).is_absolute():
                errors.append(f"{plugin_root.name}: manifest mcpServers path must be relative")
                continue
            try:
                data = json.loads((plugin_root / spec).read_text(encoding="utf-8"))
                servers = data.get("mcpServers", data) if isinstance(data, dict) else {}
                if isinstance(servers, dict):
                    expected.update(servers)
                else:
                    errors.append(f"{plugin_root.name}: {spec} mcpServers must be an object")
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"{plugin_root.name}: cannot read manifest mcpServers {spec}: {exc}")
        elif isinstance(spec, dict):
            expected.update(spec)
        else:
            errors.append(f"{plugin_root.name}: unsupported manifest mcpServers entry for CI check")
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--claude-bin", default=os.environ.get("CLAUDE_BIN", "claude"))
    args = parser.parse_args()

    repo = args.repo.resolve()
    claude_bin = shutil.which(args.claude_bin) if os.sep not in args.claude_bin else args.claude_bin
    if claude_bin is None:
        print(f"ERROR: claude binary not found: {args.claude_bin}", file=sys.stderr)
        return 1

    marketplace = json.loads((repo / MARKETPLACE).read_text(encoding="utf-8"))
    marketplace_name = marketplace["name"]
    plugin_names = [plugin["name"] for plugin in marketplace["plugins"]]
    if not plugin_names:
        print(f"ERROR: no plugins listed in {MARKETPLACE}", file=sys.stderr)
        return 1
    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="claude-load-check-") as tmp:
        temp_root = Path(tmp)
        home = temp_root / "home"
        config_dir = temp_root / "claude"
        home.mkdir()
        config_dir.mkdir()
        env = os.environ.copy()
        env.update({"HOME": str(home), "CLAUDE_CONFIG_DIR": str(config_dir)})

        run_claude(
            claude_bin,
            repo,
            env,
            ["plugin", "validate", "--strict", str(repo / MARKETPLACE)],
        )
        run_claude(claude_bin, repo, env, ["plugin", "marketplace", "add", str(repo)])
        available = parse_json_output(
            run_claude(claude_bin, repo, env, ["plugin", "list", "--available", "--json"]),
            "claude plugin list --available --json",
        )
        available_ids = {plugin["pluginId"] for plugin in available.get("available", [])}
        expected_ids = {f"{name}@{marketplace_name}" for name in plugin_names}
        missing_available = sorted(expected_ids - available_ids)
        if missing_available:
            errors.append("missing available plugins: " + ", ".join(missing_available))

        for plugin_name in plugin_names:
            run_claude(
                claude_bin,
                repo,
                env,
                ["plugin", "validate", "--strict", str(repo / "plugins" / plugin_name / MANIFEST)],
            )
            run_claude(
                claude_bin,
                repo,
                env,
                ["plugin", "install", f"{plugin_name}@{marketplace_name}"],
            )

        installed = parse_json_output(
            run_claude(claude_bin, repo, env, ["plugin", "list", "--json"]),
            "claude plugin list --json",
        )
        installed_by_id = {plugin["id"]: plugin for plugin in installed}
        missing_installed = sorted(expected_ids - set(installed_by_id))
        if missing_installed:
            errors.append("missing installed plugins: " + ", ".join(missing_installed))

        mcp_count = 0
        for plugin_name in plugin_names:
            plugin_id = f"{plugin_name}@{marketplace_name}"
            plugin = installed_by_id.get(plugin_id, {})
            for error in plugin.get("errors", []) or []:
                errors.append(f"{plugin_id}: {error}")
            expected_mcp = expected_mcp_servers(repo / "plugins" / plugin_name, errors)
            loaded_mcp = set((plugin.get("mcpServers") or {}).keys())
            mcp_count += len(loaded_mcp)
            if loaded_mcp != expected_mcp:
                errors.append(
                    f"{plugin_id}: loaded MCP servers {sorted(loaded_mcp)}, "
                    f"expected {sorted(expected_mcp)}"
                )

    print(
        f"loaded Claude marketplace {marketplace_name} with "
        f"{len(plugin_names) - len(missing_installed)} plugins and {mcp_count} MCP servers"
    )
    if errors:
        print(f"\nFound {len(errors)} Claude loadability error(s):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("All Claude loadability checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
