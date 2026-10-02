# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Validate a code-slice worker's JSON against the packet it was given.

    validate_worker_response.py RESPONSE.json --packet PACKET.json
    validate_worker_response.py RESPONSE.json -- <build_slice_packet.py arguments>

For dispatches use --packet plus --receipt from dispatch_packet.py. This checks the exact
saved bytes and source snapshot without rebuilding. The legacy rebuild form preserves all
arguments, including --task, but cannot prove what a worker previously saw; its verdict says so.
Prints contract/citation validity and safety metadata, not a semantic correctness verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REQUIRED = {"status", "answer", "evidence", "proposed_edits", "missing_context", "uncertainties"}
STATUSES = {"complete", "needs_context", "cannot_answer"}


def contained(slices: list[dict], item: dict) -> bool:
    return any(
        item.get("file") == source.get("file")
        and type(item.get("start_line")) is int
        and type(item.get("end_line")) is int
        and source.get("start_line", 0)
        <= item["start_line"]
        <= item["end_line"]
        <= source.get("end_line", -1)
        for source in slices
    )


def nonempty_text(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def packet_errors(packet) -> list[str]:
    """Reject invalid/error/empty packets independently of whether citations exist."""
    if not isinstance(packet, dict) or packet.get("schema_version") != "1.0":
        return ["packet must be a schema_version 1.0 object"]
    if "error" in packet:
        return ["packet construction failed; inspect builder_error before redispatch"]
    if not nonempty_text(packet.get("notice")):
        return ["packet notice is missing"]
    selection = packet.get("selection")
    if not isinstance(selection, dict) or not nonempty_text(selection.get("target_dir")):
        return ["packet selection is missing"]
    budget = packet.get("budget")
    if not isinstance(budget, dict):
        return ["packet budget is missing"]
    used, limit = budget.get("used_estimated_tokens"), budget.get("limit_estimated_tokens")
    if type(used) is not int or type(limit) is not int or not 0 < used <= limit:
        return ["packet budget must have 0 < used_estimated_tokens <= limit_estimated_tokens"]
    for key in ("slices", "relationships", "omitted", "warnings"):
        if not isinstance(packet.get(key), list):
            return [f"packet {key} must be an array"]
    if not packet["slices"]:
        return ["packet contains no source slices"]
    count = packet.get("omitted_count")
    if type(count) is not int or count < len(packet["omitted"]):
        return ["packet omitted_count is invalid"]
    if type(packet.get("omitted_truncated")) is not bool:
        return ["packet omitted_truncated must be a boolean"]
    if packet["omitted_truncated"] != (count > len(packet["omitted"])):
        return ["packet omission summary is inconsistent"]
    if any(not nonempty_text(warning) for warning in packet["warnings"]):
        return ["packet warnings must be nonempty strings"]
    if any(not isinstance(edge, dict) for edge in packet["relationships"]):
        return ["packet relationships must be objects"]
    for source in packet["slices"]:
        if not isinstance(source, dict) or not nonempty_text(source.get("file")):
            return ["packet source needs a file"]
        path = Path(source["file"])
        if path.is_absolute() or ".." in path.parts:
            return ["packet source paths must be root-relative"]
        start, end = source.get("start_line"), source.get("end_line")
        if type(start) is not int or type(end) is not int or not 1 <= start <= end:
            return ["packet source range is invalid"]
        if not isinstance(source.get("numbered_source"), str):
            return ["packet source text is missing"]
        lines = source["numbered_source"].splitlines()
        width = len(str(end))
        if len(lines) != end - start + 1 or any(
            not line.startswith(f"L{n:0{width}d} | ") for n, line in enumerate(lines, start)
        ):
            return ["packet source text does not cover its claimed line range"]
    return []


def safety_summary(packet) -> dict:
    if not isinstance(packet, dict):
        return {}
    return {
        key: packet.get(key)
        for key in (
            "selection",
            "budget",
            "omitted",
            "omitted_count",
            "omitted_truncated",
            "warnings",
        )
    } | {
        "non_certain_relationships": [
            edge
            for edge in packet.get("relationships", [])
            if isinstance(edge, dict) and edge.get("confidence") != "certain"
        ]
        if isinstance(packet.get("relationships"), list)
        else []
    }


def validate(packet: dict, response) -> list[str]:
    """Return every reason the response must be rejected; empty means valid."""
    errors = packet_errors(packet)
    if errors:
        return errors
    if not isinstance(response, dict) or set(response) != REQUIRED:
        return ["response must be one JSON object with exactly the worker contract fields"]
    if not isinstance(response.get("status"), str) or response["status"] not in STATUSES:
        return [f"invalid status {response.get('status')!r}"]
    if not nonempty_text(response.get("answer")):
        errors.append("answer must be a nonempty string")
    for key in ("missing_context", "uncertainties"):
        if not isinstance(response.get(key), list):
            errors.append(f"{key} must be an array")
    if isinstance(response.get("uncertainties"), list) and any(
        not nonempty_text(item) for item in response["uncertainties"]
    ):
        errors.append("uncertainties must contain nonempty strings")
    if isinstance(response.get("missing_context"), list):
        for item in response["missing_context"]:
            if (
                not isinstance(item, dict)
                or set(item) != {"symbol_or_range", "reason"}
                or any(not nonempty_text(item.get(key)) for key in ("symbol_or_range", "reason"))
            ):
                errors.append("missing_context entries need symbol_or_range and reason")
    if response["status"] == "needs_context" and not response["missing_context"]:
        errors.append("needs_context must identify the missing context")
    if response["status"] == "complete" and not response["evidence"]:
        errors.append("complete requires at least one source-cited evidence item")
    if response["status"] == "complete" and response["missing_context"]:
        errors.append("complete cannot also require missing context")
    slices = packet["slices"]
    for key in ("evidence", "proposed_edits"):
        values = response.get(key)
        if not isinstance(values, list):
            errors.append(f"{key} must be an array")
            continue
        for index, value in enumerate(values):
            if not isinstance(value, dict) or not contained(slices, value):
                errors.append(f"{key}[{index}] cites a range outside the packet")
                continue
            fields = {"file", "start_line", "end_line"}
            fields |= {"claim"} if key == "evidence" else {"replacement", "rationale"}
            if set(value) != fields:
                errors.append(f"{key}[{index}] must have exactly {sorted(fields)}")
            text_key = "claim" if key == "evidence" else "rationale"
            if not nonempty_text(value.get(text_key)):
                errors.append(f"{key}[{index}].{text_key} must be nonempty text")
            if key == "proposed_edits" and not isinstance(value.get("replacement"), str):
                errors.append(f"{key}[{index}].replacement must be text (empty deletes the range)")
    return errors


def verify_receipt(raw: bytes, receipt_path: Path, packet: dict) -> list[str]:
    """Bind the exact packet to its request and detect changes in included source files."""
    errors = []
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict) or receipt.get("schema_version") != "1.0":
        return ["receipt must be a schema_version 1.0 object"]
    if receipt.get("packet_sha256") != hashlib.sha256(raw).hexdigest():
        errors.append("packet bytes differ from the dispatch receipt")
    request = (receipt_path.parent / "request.json").read_bytes()
    if receipt.get("request_sha256") != hashlib.sha256(request).hexdigest():
        errors.append("request differs from the dispatch receipt")
    if receipt.get("builder_exit_status") != 0:
        return errors + ["builder did not produce a successful packet"]
    if packet_errors(packet):
        return errors + packet_errors(packet)
    root_value = receipt.get("target_dir")
    if not isinstance(root_value, str) or not Path(root_value).is_absolute():
        return errors + ["receipt target must be absolute"]
    root = Path(root_value).resolve()
    hashes = receipt.get("source_sha256")
    if not isinstance(hashes, dict) or set(hashes) != {s["file"] for s in packet["slices"]}:
        return errors + ["receipt must identify every sliced source file"]
    for relative, expected in hashes.items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            errors.append(f"source is missing or escapes the target: {relative}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append(f"source changed after dispatch: {relative}")
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
    if args.format != "json":
        raise ValueError("rebuild validation requires the original JSON format")
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
    parser.add_argument("--receipt", type=Path, help="exact-packet dispatch receipt")
    args = parser.parse_args(argv)
    if (args.packet is None) == (not builder_args):
        parser.error("give either --packet PACKET.json or -- <builder arguments>")
    if args.receipt and not args.packet:
        parser.error("--receipt requires --packet")
    try:
        response = json.loads(args.response.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [f"response: {exc}"]}, sort_keys=True))
        return 1
    try:
        if args.packet is not None:
            raw = args.packet.read_bytes()
            packet = json.loads(raw)
        else:
            packet = rebuild_packet(builder_args)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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
    if args.receipt:
        try:
            errors.extend(verify_receipt(raw, args.receipt, packet))
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"receipt: {exc}")
    verdict = {
        "valid": not errors,
        "errors": errors,
        "safety": safety_summary(packet),
        "provenance": "saved-packet-receipt" if args.receipt else "unverified-worker-input",
        "semantic_correctness": "not_checked",
    }
    if isinstance(packet, dict) and "error" in packet:
        verdict["builder_error"] = packet["error"]
    print(json.dumps(verdict, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
