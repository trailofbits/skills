#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "trailmark>=0.7.1,<0.8",
#   "pyyaml>=6,<7",
# ]
# ///
"""Capture graph context and native analyzer evidence without implementing taint analysis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from catalog import BACKENDS, SCOPES, catalog
from graph_context import REQUIRED_APIS as REQUIRED_APIS
from graph_context import build_context as build_context
from graph_context import context_errors as context_errors
from graph_context import neighborhoods as neighborhoods
from graph_context import rebind_anchor as rebind_anchor
from manifest_validation import _validate_models as _validate_models
from manifest_validation import validate_manifest as validate_manifest
from trace_artifacts import JsonObject
from trace_artifacts import digest as digest
from trace_artifacts import local_file as local_file
from trace_artifacts import read_json as read_json
from trace_artifacts import record_path as record_path
from trace_artifacts import relative as relative
from trace_artifacts import snapshot_sources as snapshot_sources
from trace_artifacts import write_json as write_json
from trace_report import finding_key as finding_key
from trace_report import render_report as render_report


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("catalog", help="List graph/backend candidates and scope limits")
    context = commands.add_parser("context", help="Capture structural evidence; no taint solving")
    context.add_argument("--target", type=Path, required=True)
    context.add_argument("--languages", default="auto")
    context.add_argument("--focus", action="append", default=[])
    context.add_argument("--output", type=Path, required=True)
    proof = commands.add_parser("probe", help="Run a real positive/negative native contract")
    proof.add_argument("--backend", choices=BACKENDS, required=True)
    proof.add_argument("--language", required=True)
    proof.add_argument("--contract", type=Path)
    proof.add_argument("--executable")
    proof.add_argument("--output", type=Path, required=True)
    native = commands.add_parser("run", help="Capture an existing analyzer's native findings")
    native.add_argument("--backend", choices=BACKENDS, required=True)
    native.add_argument("--language", required=True)
    native.add_argument("--phase", choices=["baseline", "enriched"], required=True)
    native.add_argument("--scope", choices=sorted(SCOPES), required=True)
    native.add_argument("--output", type=Path, required=True)
    native.add_argument("--cwd", type=Path, default=Path.cwd())
    native.add_argument("--native-output", type=Path)
    native.add_argument("--model", action="append", type=Path, default=[])
    native.add_argument("--timeout", type=int, default=300)
    native.add_argument("argv", nargs=argparse.REMAINDER)
    for name in ("validate", "report"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        if name == "validate":
            command.add_argument("--stage", choices=["baseline", "complete"], default="complete")
        else:
            command.add_argument("--output", type=Path, required=True)
    return root


def capture_context(args: argparse.Namespace) -> JsonObject:
    if args.output.exists():
        raise ValueError("Refusing to overwrite an evidence snapshot")
    result = build_context(args.target, args.languages, args.focus)
    snapshot_sources(result, args.output)
    write_json(args.output, result)
    summary = {key: result[key] for key in ("target", "summary", "trailmark_version")}
    return {**summary, "context": str(args.output.resolve())}


def capture_native(args: argparse.Namespace) -> JsonObject:
    from runner import run_native

    command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    return run_native(
        backend=args.backend,
        language=args.language,
        phase=args.phase,
        scope=args.scope,
        output=args.output,
        argv=command,
        cwd=args.cwd,
        native_output=args.native_output,
        models=args.model,
        timeout=args.timeout,
    )


def dispatch(args: argparse.Namespace) -> JsonObject:
    if args.command == "catalog":
        return catalog()
    if args.command == "context":
        return capture_context(args)
    if args.command == "probe":
        from runner import probe

        return probe(
            backend=args.backend,
            language=args.language,
            output=args.output,
            contract=args.contract,
            executable=args.executable,
        )
    if args.command == "run":
        return capture_native(args)
    if args.command == "validate":
        return dict(validate_manifest(args.manifest, args.stage))
    if args.output.exists():
        raise ValueError("Refusing to overwrite a report")
    return render_report(args.manifest, args.output)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = dispatch(args)
        print(json.dumps(result, ensure_ascii=False))
        return 2 if result.get("status") == "failed" or result.get("valid") is False else 0
    except (OSError, ValueError, TypeError, KeyError, ImportError) as exc:
        print(json.dumps({"status": "failed", "errors": [str(exc)]}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
