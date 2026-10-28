"""Bind startup-sensitive options without claiming to sandbox native analyzers."""

from __future__ import annotations

import json
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from activation import invocation
from runner_artifacts import artifact, check_artifact, write_json
from runner_config import psalm_config, psalm_config_relative

ROOT_OPTIONS = {"--root", "-r"}
CONFIG_OPTIONS = {"--config", "-c"}
TRUST_ASSUMPTION = (
    "The analyzer installation, interpreter, environment, and explicitly configured "
    "extensions/autoloaders must be trusted. This runner does not provide a process sandbox."
)


def extract_options(args: list[str], options: set[str]) -> tuple[list[str], list[str]]:
    """Extract native options, including Psalm's attached short-option values."""
    retained, values = [], []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            retained.extend(args[index:])
            break
        option = next((name for name in options if arg == name or arg.startswith(name + "=")), None)
        attached = next(
            (name for name in options if len(name) == 2 and arg.startswith(name) and arg != name),
            None,
        )
        if option and arg == option:
            index += 1
            if index >= len(args) or args[index].startswith("-"):
                raise ValueError(f"Missing value for native startup option {option}")
            values.append(args[index])
        elif option or attached:
            values.append(arg[len(option) + 1 :] if option else arg[len(attached or "") :])
        else:
            retained.append(arg)
        index += 1
    if len(values) > 1 or any(not value for value in values):
        raise ValueError("Ambiguous or empty native startup option: " + "/".join(sorted(options)))
    return retained, values


def psalm_root_arguments(argv: list[str]) -> list[str]:
    _, args = invocation("psalm", argv)
    _, roots = extract_options(args, ROOT_OPTIONS)
    return ["--root=" + roots[0]] if roots else []


def psalm_version_root(version: list[str], root: Path) -> list[str]:
    prefix, args = invocation("psalm", version)
    args, roots = extract_options(args, ROOT_OPTIONS)
    if roots and Path(roots[0]) != root:
        raise ValueError("Psalm version command must use the same startup --root as analysis")
    return prefix + [f"--root={root}"] + args


@dataclass
class StartupPlan:
    argv: list[str]
    version_argv: list[str] | None
    policy: str = "caller-managed"
    assumptions: list[str] = field(default_factory=lambda: [TRUST_ASSUMPTION])
    errors: list[str] = field(default_factory=list)


def prepare_psalm(plan: StartupPlan, cwd: Path, root: Path) -> None:
    prefix, args = invocation("psalm", plan.argv)
    args, roots = extract_options(args, ROOT_OPTIONS)
    args, configs = extract_options(args, CONFIG_OPTIONS)
    discovery = (cwd / roots[0]).resolve() if roots else cwd
    config = (cwd / configs[0]).resolve() if configs else psalm_config(plan.argv, discovery)
    if roots:
        root = (cwd / roots[0]).resolve()
        plan.assumptions.append("The explicitly supplied Psalm startup root is caller-managed.")
    else:
        if not psalm_config_relative(ET.parse(config).getroot()):
            raise ValueError(
                "Automatic Psalm startup isolation requires resolveFromConfigFile=true; "
                "supply a reviewed explicit --root to preserve root-relative source bindings"
            )
        root.mkdir(parents=True)
        plan.policy = "psalm-private-composer-root"
        plan.assumptions.append(
            "A temporary empty root prevents automatic target Composer autoloader discovery; "
            "explicit configuration hooks and the trusted tool installation retain their behavior."
        )
    plan.argv = prefix + [f"--root={root}", f"--config={config}"] + args
    if plan.version_argv is not None:
        version_prefix, version_args = invocation("psalm", plan.version_argv)
        version_args, version_roots = extract_options(version_args, ROOT_OPTIONS)
        if version_roots:
            version_roots = [str((cwd / version_roots[0]).resolve())]
        plan.version_argv = psalm_version_root(
            version_prefix + [f"--root={value}" for value in version_roots] + version_args, root
        )


@contextmanager
def startup_plan(
    backend: str, argv: list[str], cwd: Path, *, version_argv: list[str] | None
) -> Iterator[StartupPlan]:
    plan = StartupPlan(list(argv), list(version_argv) if version_argv is not None else None)
    if backend != "psalm":
        yield plan
        return
    with tempfile.TemporaryDirectory(prefix="trailmark-psalm-") as temporary:
        try:
            # Psalm also probes dirname(root, 2)/autoload.php. Keep that ancestor private.
            prepare_psalm(plan, cwd, Path(temporary) / "empty" / "root")
        except (OSError, ValueError, ET.ParseError) as exc:
            plan.errors.append(str(exc))
        yield plan


def capture_execution(
    output: Path, plan: StartupPlan, *, requested: dict[str, Any], effective: dict[str, Any]
) -> dict[str, Any]:
    path = output.with_name(output.name + ".execution.json")
    write_json(
        path,
        {
            "requested": requested,
            "effective": effective,
            "policy": plan.policy,
            "assumptions": plan.assumptions,
        },
    )
    return {**artifact(path), "policy": plan.policy, "assumptions": list(plan.assumptions)}


def check_execution(record: dict[str, Any]) -> list[str]:
    if "execution" not in record:
        return ["Run lacks its immutable requested/effective execution snapshot"]
    errors = check_artifact(record["execution"], "execution")
    if errors:
        return errors
    saved = json.loads(Path(record["execution"]["path"]).read_text(encoding="utf-8"))
    effective = saved["effective"]
    for key in ("argv", "cwd", "config_files"):
        if effective[key] != record[key]:
            errors.append(f"Recorded {key} disagrees with the immutable execution snapshot")
    if effective["version_argv"] != record["version"]["argv"]:
        errors.append("Recorded version command disagrees with the immutable execution snapshot")
    for key in ("policy", "assumptions"):
        if saved[key] != record["execution"].get(key):
            errors.append(f"Recorded startup {key} disagrees with the execution snapshot")
    return errors


def version_identity(record: dict[str, Any]) -> dict[str, Any]:
    """Ignore only the private empty discovery directory when comparing tool identity."""
    version = dict(record["version"])
    if (
        record.get("backend") == "psalm"
        and record.get("execution", {}).get("policy") == "psalm-private-composer-root"
    ):
        prefix, args = invocation("psalm", version["argv"])
        args, _ = extract_options(args, ROOT_OPTIONS)
        version["argv"] = prefix + args
    return version
