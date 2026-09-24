# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Validate a code-slice worker's JSON against the packet it was given.

    validate_worker_response.py RESPONSE.json --packet PACKET.json
    validate_worker_response.py RESPONSE.json -- <build_slice_packet.py arguments>

The second form rebuilds the packet deterministically with the sibling builder (same target,
anchors, mode, depth, and budget; a trailing ``--task`` is ignored), so a coordinator that never
saw the packet can still check every citation. Prints one JSON verdict and exits 0 only when the
response is exactly the worker contract, its status is valid, and every evidence and
proposed-edit range lies fully inside one packet slice.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REQUIRED = {"status", "answer", "evidence", "proposed_edits", "missing_context", "uncertainties"}
STATUSES = {"complete", "needs_context", "cannot_answer"}


def contained(slices: list[dict], item: dict) -> bool:
    return any(
        item.get("file") == source.get("file")
        and isinstance(item.get("start_line"), int)
        and isinstance(item.get("end_line"), int)
        and source.get("start_line", 0)
        <= item["start_line"]
        <= item["end_line"]
        <= source.get("end_line", -1)
        for source in slices
    )


def validate(packet: dict, response) -> list[str]:
    """Return every reason the response must be rejected; empty means valid."""
    if not isinstance(response, dict) or set(response) != REQUIRED:
        return ["response must be one JSON object with exactly the worker contract fields"]
    if response.get("status") not in STATUSES:
        return [f"invalid status {response.get('status')!r}"]
    errors = []
    if not isinstance(response.get("answer"), str):
        errors.append("answer must be a string")
    for key in ("missing_context", "uncertainties"):
        if not isinstance(response.get(key), list):
            errors.append(f"{key} must be an array")
    slices = packet.get("slices", []) if isinstance(packet, dict) else []
    for key in ("evidence", "proposed_edits"):
        values = response.get(key)
        if not isinstance(values, list):
            errors.append(f"{key} must be an array")
            continue
        for index, value in enumerate(values):
            if not isinstance(value, dict) or not contained(slices, value):
                errors.append(f"{key}[{index}] cites a range outside the packet")
    return errors


def rebuild_packet(builder_args: list[str]) -> dict:
    """Run the sibling builder in-process with the coordinator's arguments and return its packet."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "build_slice_packet", Path(__file__).resolve().parent / "build_slice_packet.py"
    )
    builder = importlib.util.module_from_spec(spec)
    # Register before executing: the builder's dataclasses resolve their annotations through
    # sys.modules[cls.__module__], which raises on Python 3.13 for an unregistered module.
    sys.modules[spec.name] = builder
    spec.loader.exec_module(builder)
    args = builder.parse_args(builder_args)
    root = Path(args.target_dir).resolve()
    if not root.is_dir():
        raise builder.SlicePacketError("invalid_target", f"Target directory does not exist: {root}")
    graph, detected = builder.load_trailmark_graph(
        root, args.language, run_preanalysis=args.mode == "entrypoint"
    )
    packet, _rendered = builder.construct_packet(
        graph,
        root,
        symbols=args.symbol,
        line_range_values=args.line_range,
        mode=args.mode,
        peer=args.peer,
        depth=args.depth,
        budget_tokens=args.budget_tokens,
        language=args.language,
        detected_languages=detected,
        output_format="json",
        task=args.task,
    )
    return packet


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    builder_args: list[str] = []
    if "--" in argv:
        split = argv.index("--")
        argv, builder_args = argv[:split], argv[split + 1 :]
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("response", type=Path)
    parser.add_argument("--packet", type=Path, help="saved packet JSON (instead of rebuilding)")
    args = parser.parse_args(argv)
    if (args.packet is None) == (not builder_args):
        parser.error("give either --packet PACKET.json or -- <builder arguments>")
    try:
        response = json.loads(args.response.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [f"response: {exc}"]}, sort_keys=True))
        return 1
    try:
        if args.packet is not None:
            packet = json.loads(args.packet.read_text(encoding="utf-8"))
        else:
            packet = rebuild_packet(builder_args)
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [f"packet: {exc}"]}, sort_keys=True))
        return 1
    except Exception as exc:  # the builder's own SlicePacketError carries code and message
        code = getattr(exc, "code", type(exc).__name__)
        message = getattr(exc, "message", str(exc))
        print(
            json.dumps({"valid": False, "errors": [f"packet: {code}: {message}"]}, sort_keys=True)
        )
        return 1
    errors = validate(packet, response)
    print(json.dumps({"valid": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
