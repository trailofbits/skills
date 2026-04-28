#!/usr/bin/env python3
"""Build a deterministic c-review run plan.

Reads ``prompts/clusters/manifest.json`` plus run-level flags, applies gate +
per-pass filtering, verifies every referenced prompt resolves on disk, and
emits two artifacts in the run's output directory:

* ``plan.json`` — machine-readable selection (cluster ids, prompt paths,
  per-pass bug classes/prefixes, sub-prompt paths). The orchestrator reads
  this to drive Phase 5 (TaskCreate metadata) and Phase 6 (worker spawn).
* ``worker-prompts/worker-N.txt`` — one ready-to-paste spawn prompt per
  selected cluster, in selection order. The orchestrator passes the file
  contents verbatim as the ``prompt`` argument to ``Agent``.

The script aborts non-zero on any malformed manifest entry, missing prompt
file, or invalid flag combination — so the orchestrator can rely on its
output without further validation.

Usage:
    python3 build_run_plan.py \\
        --plugin-root /abs/plugins/c-review \\
        --output-dir /abs/.c-review-results/<ts> \\
        --threat-model REMOTE \\
        --severity-filter medium \\
        --scope-subpath src \\
        --is-cpp false --is-posix true --is-windows false
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, NoReturn

THREAT_MODELS = {"REMOTE", "LOCAL_UNPRIVILEGED", "BOTH"}
SEVERITY_FILTERS = {"all", "medium", "high"}
GATE_VALUES = {"always", "is_cpp", "is_windows"}
KNOWN_REQUIRES = {"is_cpp", "is_posix", "is_windows"}


def parse_bool(value: str) -> bool:
    v = value.strip().lower()
    if v in ("true", "1", "yes"):
        return True
    if v in ("false", "0", "no"):
        return False
    raise argparse.ArgumentTypeError(f"expected true/false, got {value!r}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--plugin-root",
        required=True,
        type=Path,
        help="Absolute path to the c-review plugin root (contains prompts/clusters/manifest.json)",
    )
    p.add_argument(
        "--output-dir", required=True, type=Path, help="Absolute path to the run's output directory"
    )
    p.add_argument("--threat-model", required=True, choices=sorted(THREAT_MODELS))
    p.add_argument("--severity-filter", required=True, choices=sorted(SEVERITY_FILTERS))
    p.add_argument(
        "--scope-subpath", required=True, help='Repo-relative scope directory, or "." for repo root'
    )
    p.add_argument("--is-cpp", required=True, type=parse_bool)
    p.add_argument("--is-posix", required=True, type=parse_bool)
    p.add_argument("--is-windows", required=True, type=parse_bool)
    p.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Override manifest path (defaults to <plugin-root>/prompts/clusters/manifest.json)",
    )
    return p.parse_args()


def fail(msg: str) -> NoReturn:
    print(f"build_run_plan.py: {msg}", file=sys.stderr)
    sys.exit(2)


def gate_passes(cluster_gate: str, *, is_cpp: bool, is_windows: bool) -> bool:
    if cluster_gate == "always":
        return True
    if cluster_gate == "is_cpp":
        return is_cpp
    if cluster_gate == "is_windows":
        return is_windows
    fail(f"unknown cluster gate {cluster_gate!r}")


def pass_filtered_out(p: dict[str, Any], *, flags: dict[str, bool], threat_model: str) -> bool:
    """Return True if this pass should be hard-dropped from the run."""
    requires = p.get("requires", []) or []
    for req in requires:
        if req not in KNOWN_REQUIRES:
            fail(f"pass {p.get('bug_class', '?')!r}: unknown requires flag {req!r}")
        if not flags[req]:
            return True
    skip_threat_models = p.get("skip_threat_models", []) or []
    return threat_model in skip_threat_models


def build_selection(
    manifest: dict[str, Any], *, plugin_root: Path, flags: dict[str, bool], threat_model: str
) -> list[dict[str, Any]]:
    if manifest.get("version") != 1:
        fail(f"unsupported manifest version: {manifest.get('version')!r}")
    if not isinstance(manifest.get("clusters"), list):
        fail("manifest.clusters must be a list")

    selected: list[dict[str, Any]] = []
    for cluster in manifest["clusters"]:
        cid = cluster.get("cluster_id")
        if not cid:
            fail("cluster missing cluster_id")
        gate = cluster.get("gate")
        if gate not in GATE_VALUES:
            fail(f"cluster {cid!r}: invalid gate {gate!r}")
        if not gate_passes(gate, is_cpp=flags["is_cpp"], is_windows=flags["is_windows"]):
            continue

        consolidated = bool(cluster.get("consolidated", False))
        cluster_prompt_rel = cluster.get("prompt")
        if not cluster_prompt_rel:
            fail(f"cluster {cid!r}: missing prompt path")
        cluster_prompt_abs = (plugin_root / cluster_prompt_rel).resolve()
        if not cluster_prompt_abs.is_file():
            fail(f"cluster {cid!r}: prompt not found at {cluster_prompt_abs}")

        passes_in = cluster.get("passes") or []
        if not passes_in:
            fail(f"cluster {cid!r}: no passes declared")

        kept_passes: list[dict[str, Any]] = []
        for raw in passes_in:
            bug_class = raw.get("bug_class")
            prefix = raw.get("prefix")
            if not bug_class or not prefix:
                fail(f"cluster {cid!r}: pass missing bug_class/prefix: {raw!r}")
            if pass_filtered_out(raw, flags=flags, threat_model=threat_model):
                continue
            entry: dict[str, Any] = {"bug_class": bug_class, "prefix": prefix}
            if consolidated:
                # No per-pass prompt file; cluster prompt is self-sufficient.
                if "prompt" in raw:
                    fail(
                        f"cluster {cid!r} (consolidated):"
                        "pass {bug_class!r} unexpectedly has 'prompt'"
                    )
            else:
                pass_prompt_rel = raw.get("prompt")
                if not pass_prompt_rel:
                    fail(
                        f"cluster {cid!r}: non-consolidated pass {bug_class!r} missing prompt path"
                    )
                pass_prompt_abs = (plugin_root / pass_prompt_rel).resolve()
                if not pass_prompt_abs.is_file():
                    fail(
                        f"cluster {cid!r} pass {bug_class!r}: prompt not found at {pass_prompt_abs}"
                    )
                entry["prompt"] = str(pass_prompt_abs)
            kept_passes.append(entry)

        if not kept_passes:
            # Empty after filtering — drop the cluster entirely (Phase 4 rule).
            continue

        selected.append(
            {
                "cluster_id": cid,
                "consolidated": consolidated,
                "cluster_prompt": str(cluster_prompt_abs),
                "passes": kept_passes,
            }
        )

    if not selected:
        fail("no clusters selected after filtering — refusing to start an empty review")
    return selected


def render_worker_prompt(
    *,
    worker_n: int,
    cluster: dict[str, Any],
    output_dir: Path,
    scope_root: str,
    threat_model: str,
    severity_filter: str,
    flags: dict[str, bool],
) -> str:
    bug_classes = [p["bug_class"] for p in cluster["passes"]]
    prefixes = [p["prefix"] for p in cluster["passes"]]

    lines: list[str] = []
    lines.append("You are a c-review worker on a parallel C/C++ security review.")
    lines.append("Follow the protocol in your system prompt verbatim.")
    lines.append("")
    lines.append(f"Output directory: {output_dir}")
    lines.append(
        f"Scope root: {scope_root} — all Grep/Glob queries MUST be rooted here; "
        "findings outside this subtree are out-of-scope."
    )
    lines.append(f"Threat model: {threat_model}")
    lines.append(f"Severity filter: {severity_filter}")
    lines.append(
        f"Codebase: is_cpp={'true' if flags['is_cpp'] else 'false'}, "
        f"is_posix={'true' if flags['is_posix'] else 'false'}, "
        f"is_windows={'true' if flags['is_windows'] else 'false'}"
    )
    lines.append("")
    lines.append("— assignment —")
    lines.append(f"Worker id: worker-{worker_n}")
    lines.append(f"Cluster id: {cluster['cluster_id']}")
    lines.append(f"Cluster prompt: {cluster['cluster_prompt']}")

    if cluster["consolidated"]:
        # Worker.md contract: omit the section entirely for consolidated clusters.
        pass
    else:
        lines.append("Sub-prompt paths:")
        for p in cluster["passes"]:
            lines.append(f"  - {p['prompt']}")

    lines.append(f"Pass bug classes: {', '.join(bug_classes)}")
    lines.append(f"Pass prefixes: {', '.join(prefixes)}")
    # skip_subclasses is always empty: filtering is hard-drop (passes never reach
    # the worker). Field is retained because worker.md "Inputs" requires it.
    lines.append("Skip subclasses: (none)")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()

    plugin_root: Path = args.plugin_root.resolve()
    if not plugin_root.is_dir():
        fail(f"--plugin-root {plugin_root} is not a directory")

    output_dir: Path = args.output_dir.resolve()
    if not output_dir.is_dir():
        fail(f"--output-dir {output_dir} does not exist (Phase 2 must create it first)")

    manifest_path: Path = (
        args.manifest or plugin_root / "prompts/clusters/manifest.json"
    ).resolve()
    if not manifest_path.is_file():
        fail(f"manifest not found at {manifest_path}")

    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        fail(f"manifest is not valid JSON: {e}")

    flags = {"is_cpp": args.is_cpp, "is_posix": args.is_posix, "is_windows": args.is_windows}
    selected = build_selection(
        manifest, plugin_root=plugin_root, flags=flags, threat_model=args.threat_model
    )

    worker_prompts_dir = output_dir / "worker-prompts"
    worker_prompts_dir.mkdir(exist_ok=True)

    plan = {
        "version": 1,
        "run": {
            "output_dir": str(output_dir),
            "scope_root": args.scope_subpath,
            "threat_model": args.threat_model,
            "severity_filter": args.severity_filter,
            "is_cpp": args.is_cpp,
            "is_posix": args.is_posix,
            "is_windows": args.is_windows,
            "plugin_root": str(plugin_root),
            "manifest_path": str(manifest_path),
        },
        "workers": [],
    }

    for i, cluster in enumerate(selected, start=1):
        prompt_text = render_worker_prompt(
            worker_n=i,
            cluster=cluster,
            output_dir=output_dir,
            scope_root=args.scope_subpath,
            threat_model=args.threat_model,
            severity_filter=args.severity_filter,
            flags=flags,
        )
        prompt_path = worker_prompts_dir / f"worker-{i}.txt"
        prompt_path.write_text(prompt_text)
        plan["workers"].append(
            {
                "worker_n": i,
                "cluster_id": cluster["cluster_id"],
                "consolidated": cluster["consolidated"],
                "cluster_prompt": cluster["cluster_prompt"],
                "sub_prompt_paths": [p["prompt"] for p in cluster["passes"] if "prompt" in p],
                "pass_bug_classes": [p["bug_class"] for p in cluster["passes"]],
                "pass_prefixes": [p["prefix"] for p in cluster["passes"]],
                "spawn_prompt_path": str(prompt_path),
            }
        )

    plan_path = output_dir / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n")

    # Print a compact summary for the orchestrator to parse via Read.
    summary = {
        "plan_path": str(plan_path),
        "worker_prompts_dir": str(worker_prompts_dir),
        "worker_count": len(selected),
        "cluster_ids": [c["cluster_id"] for c in selected],
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
