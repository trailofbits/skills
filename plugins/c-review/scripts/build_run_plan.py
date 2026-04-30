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
        --context-roots . \\
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
    p.add_argument(
        "--context-roots",
        default=".",
        help=(
            "Comma-separated repo-relative read-only roots/files workers may inspect for "
            "reachability, build settings, wrappers, and threat-model context. Findings "
            "remain limited to --scope-subpath."
        ),
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
    p.add_argument(
        "--cache-primer",
        type=parse_bool,
        default=True,
        help=(
            "When true (default), the orchestrator spawns a small 'cache primer' worker before "
            "the parallel batch so followers can hit the prompt cache on their first turn. Pass "
            "false to skip and pay full cache-creation on every worker (useful for A/B testing)."
        ),
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
                        f"cluster {cid!r} (consolidated): "
                        f"pass {bug_class!r} unexpectedly has 'prompt'"
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


def _render_shared_prefix_lines(
    *,
    output_dir: Path,
    scope_root: str,
    context_roots: str,
    threat_model: str,
    severity_filter: str,
    flags: dict[str, bool],
    context_md_body: str,
) -> list[str]:
    """Lines that are byte-identical across all workers AND the cache primer in this run.

    Keeping this block stable is what makes the prompt cache hit cross-worker. Any change
    to its shape (formatting, ordering, blank-line placement) invalidates cache for the rest
    of the run. The primer prompt and worker prompts both call this and append divergent
    trailers afterwards.
    """
    lines: list[str] = []
    lines.append("You are a c-review worker on a parallel C/C++ security review.")
    lines.append("Follow the protocol in your system prompt verbatim.")
    lines.append("")
    lines.append(f"Output directory: {output_dir}")
    lines.append(
        f"Finding scope root: {scope_root} — finding locations MUST be inside this subtree."
    )
    lines.append(
        f"Context roots: {context_roots} — read-only context for reachability, callers, "
        "wrappers, build settings, mitigations, and threat-model details. Do not file "
        "findings outside the finding scope."
    )
    lines.append(f"Scope root: {scope_root} — legacy alias for Finding scope root.")
    lines.append(f"Threat model: {threat_model}")
    lines.append(f"Severity filter: {severity_filter}")
    lines.append(
        f"Codebase: is_cpp={'true' if flags['is_cpp'] else 'false'}, "
        f"is_posix={'true' if flags['is_posix'] else 'false'}, "
        f"is_windows={'true' if flags['is_windows'] else 'false'}"
    )
    lines.append("")
    lines.append("<context>")
    lines.append(
        "Codebase context (from output_dir/context.md — do NOT re-Read it from disk; "
        "this block IS the canonical copy):"
    )
    lines.append("")
    lines.append(context_md_body.rstrip())
    lines.append("</context>")
    lines.append("")
    return lines


def render_cache_primer_prompt(
    *,
    output_dir: Path,
    scope_root: str,
    context_roots: str,
    threat_model: str,
    severity_filter: str,
    flags: dict[str, bool],
    context_md_body: str,
) -> str:
    """Tiny single-turn prompt that warms the prompt cache for the parallel batch.

    Shares its prefix byte-for-byte with every worker prompt (via the helper above) so
    that the workers in Phase 6c read this entry from cache instead of paying full
    cache-creation. The trailer instructs the agent to abort in one text response with
    no tool calls — duration ~3 s, no findings written.
    """
    lines = _render_shared_prefix_lines(
        output_dir=output_dir,
        scope_root=scope_root,
        context_roots=context_roots,
        threat_model=threat_model,
        severity_filter=severity_filter,
        flags=flags,
        context_md_body=context_md_body,
    )
    # Trailer is primer-only — never reused by workers — so keep it short.
    # The worker system prompt treats this exact marker as a first-class mode.
    lines.append("Cache primer: true")
    lines.append("worker-PRIMER abort: cache primer (no analysis performed)")
    lines.append("")
    return "\n".join(lines)


def render_worker_prompt(
    *,
    worker_n: int,
    cluster: dict[str, Any],
    output_dir: Path,
    scope_root: str,
    context_roots: str,
    threat_model: str,
    severity_filter: str,
    flags: dict[str, bool],
    context_md_body: str,
) -> str:
    bug_classes = [p["bug_class"] for p in cluster["passes"]]
    prefixes = [p["prefix"] for p in cluster["passes"]]

    lines = _render_shared_prefix_lines(
        output_dir=output_dir,
        scope_root=scope_root,
        context_roots=context_roots,
        threat_model=threat_model,
        severity_filter=severity_filter,
        flags=flags,
        context_md_body=context_md_body,
    )
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

    context_md_path = output_dir / "context.md"
    if not context_md_path.is_file():
        fail(
            f"context.md not found at {context_md_path} — Phase 3 must write it before Phase 4 runs"
        )
    context_md_body = context_md_path.read_text()

    worker_prompts_dir = output_dir / "worker-prompts"
    worker_prompts_dir.mkdir(exist_ok=True)

    plan = {
        "version": 1,
        "run": {
            "output_dir": str(output_dir),
            "finding_scope_root": args.scope_subpath,
            "scope_root": args.scope_subpath,
            "context_roots": args.context_roots,
            "threat_model": args.threat_model,
            "severity_filter": args.severity_filter,
            "is_cpp": args.is_cpp,
            "is_posix": args.is_posix,
            "is_windows": args.is_windows,
            "plugin_root": str(plugin_root),
            "manifest_path": str(manifest_path),
            "cache_primer": args.cache_primer,
        },
        "workers": [],
    }

    for i, cluster in enumerate(selected, start=1):
        prompt_text = render_worker_prompt(
            worker_n=i,
            cluster=cluster,
            output_dir=output_dir,
            scope_root=args.scope_subpath,
            context_roots=args.context_roots,
            threat_model=args.threat_model,
            severity_filter=args.severity_filter,
            flags=flags,
            context_md_body=context_md_body,
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

    cache_primer_path: Path | None = None
    if args.cache_primer:
        cache_primer_path = worker_prompts_dir / "cache-primer.txt"
        cache_primer_path.write_text(
            render_cache_primer_prompt(
                output_dir=output_dir,
                scope_root=args.scope_subpath,
                context_roots=args.context_roots,
                threat_model=args.threat_model,
                severity_filter=args.severity_filter,
                flags=flags,
                context_md_body=context_md_body,
            )
        )
        plan["cache_primer"] = {
            "spawn_prompt_path": str(cache_primer_path),
        }

    plan_path = output_dir / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n")

    spawn_warning = (
        "Spawn workers FOREGROUND only. Each Agent call MUST have no "
        "run_in_background field (or run_in_background=false). Setting it to "
        "true defeats the Phase-6a primer cache and burns ~15K cache-creation "
        "tokens per worker. 'Parallel' = one assistant message with M Agent "
        "calls; that is already concurrent — do not add run_in_background=true."
    )

    # Stderr banner so the warning shows up in the Bash tool result the
    # orchestrator reads, not just inside the JSON summary.
    print(f"WARNING: {spawn_warning}", file=sys.stderr)

    # Print a compact summary for the orchestrator to parse via Read.
    summary = {
        "plan_path": str(plan_path),
        "worker_prompts_dir": str(worker_prompts_dir),
        "worker_count": len(selected),
        "cluster_ids": [c["cluster_id"] for c in selected],
        "cache_primer_path": str(cache_primer_path) if cache_primer_path else None,
        "spawn_instructions": spawn_warning,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
