# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Transport builder arguments as data and retain the exact dispatched packet.

prepare reads {"builder_args": [...]} from a JSON file, returning artifact paths
without source. consume is called by the fork's fixed dynamic command, with only
the host's session UUID. It claims one pending request and emits the saved packet.
No request string is interpreted as shell, Python, or an executable path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
import uuid
from pathlib import Path

import build_slice_packet as builder

OPTIONS = {
    "--target-dir",
    "--symbol",
    "--line-range",
    "--mode",
    "--peer",
    "--depth",
    "--budget-tokens",
    "--language",
    "--format",
    "--task",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise ValueError(f"dispatch directory must be private and not a symlink: {path}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError(f"dispatch directory has a different owner: {path}")
    return path


def session_directory(session: str) -> Path:
    session = str(uuid.UUID(session))
    owner = str(os.getuid()) if hasattr(os, "getuid") else "local"
    root = private_directory(Path(tempfile.gettempdir()) / f"trailmark-slices-{owner}")
    return private_directory(root / session)


def save_new(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def request_args(value: object) -> tuple[list[str], argparse.Namespace]:
    if not isinstance(value, dict) or set(value) != {"builder_args"}:
        raise ValueError('request must be one object with a "builder_args" array')
    argv = value["builder_args"]
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
        raise ValueError("builder_args must be a nonempty string array")
    # Deliberately accept option/value pairs only. No help, positional arguments,
    # shell fragments, response files, duplicate singleton flags, or abbreviations.
    if len(argv) % 2:
        raise ValueError("builder_args must contain option/value pairs")
    seen = set()
    for flag, val in zip(argv[::2], argv[1::2], strict=True):
        if flag not in OPTIONS or "\x00" in val:
            raise ValueError(f"unsupported argument: {flag!r}")
        if flag in seen and flag not in {"--symbol", "--line-range"}:
            raise ValueError(f"duplicate argument: {flag}")
        seen.add(flag)
    if "--target-dir" not in seen or "--task" not in seen:
        raise ValueError("--target-dir and --task are required")
    # Equals form keeps values beginning with '-' as data, even in argparse.
    parsed = builder.parse_args([f"{flag}={val}" for flag, val in zip(argv[::2], argv[1::2])])
    if parsed.format != "json":
        raise ValueError("dispatch requires --format json; other builder modes are unchanged")
    if not parsed.task.strip():
        raise ValueError("--task must not be empty")
    root = Path(parsed.target_dir).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"target directory does not exist: {root}")
    argv = list(argv)
    argv[argv.index("--target-dir") + 1] = str(root)
    parsed.target_dir = str(root)
    return argv, parsed


def prepare(request: Path, session: str) -> dict:
    argv, _args = request_args(json.loads(request.read_text(encoding="utf-8")))
    directory = session_directory(session)
    attempt = private_directory(directory / str(uuid.uuid4()))
    payload = {"builder_args": argv}
    save_new(attempt / "request.json", json_bytes(payload))
    # Exclusive creation prevents another dispatch from silently replacing this
    # session's pending request. A failed preparation's artifacts stay available.
    save_new(directory / "pending.json", json_bytes({"attempt": attempt.name}))
    return {
        "session": directory.name,
        "request": str(attempt / "request.json"),
        "packet": str(attempt / "packet.json"),
        "receipt": str(attempt / "receipt.json"),
        "response": str(attempt / "response.json"),
    }


def source_hashes(packet: dict, root: Path) -> dict[str, str]:
    hashes = {}
    for source in packet["slices"]:
        relative, path = builder.safe_source_path(root, source["file"])
        data = path.read_bytes()
        lines = data.decode("utf-8").splitlines()
        start, end = source["start_line"], source["end_line"]
        if end > len(lines):
            raise builder.SlicePacketError(
                "stale_source", f"Source changed during slicing: {relative}"
            )
        width = len(str(end))
        numbered = "\n".join(f"L{n:0{width}d} | {lines[n - 1]}" for n in range(start, end + 1))
        if numbered != source["numbered_source"]:
            raise builder.SlicePacketError(
                "stale_source", f"Source changed during slicing: {relative}"
            )
        hashes[relative] = digest(data)
    return hashes


def consume(session: str) -> bytes:
    if os.environ.get("CLAUDE_CODE_SIMPLE", "").lower() not in {"", "0", "false"}:
        raise ValueError(
            "Bare mode does not load the restricted worker; restart without --bare "
            "instead of falling back to a general-purpose agent"
        )
    directory = session_directory(session)
    claimed = directory / f"claimed-{uuid.uuid4()}.json"
    # Atomic claim: a second consumer cannot run the same pending request twice.
    (directory / "pending.json").rename(claimed)
    request_id = str(uuid.UUID(json.loads(claimed.read_text())["attempt"]))
    attempt = private_directory(directory / request_id)
    request = (attempt / "request.json").read_bytes()
    _argv, args = request_args(json.loads(request))
    root = Path(args.target_dir)
    status = 0
    hashes = {}
    try:
        graph, detected = builder.load_trailmark_graph(
            root, args.language, run_preanalysis=args.mode == "entrypoint"
        )
        packet, rendered = builder.construct_packet(
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
        hashes = source_hashes(packet, root)
        raw = rendered.encode("utf-8")
    except (builder.SlicePacketError, OSError, UnicodeError) as exc:
        # Expected construction failures are data for the worker/coordinator. An
        # unexpected programming error still aborts invocation, never "|| true".
        status = 2
        packet = {
            "schema_version": builder.SCHEMA_VERSION,
            "error": {
                "code": getattr(exc, "code", "io_error"),
                "message": getattr(exc, "message", str(exc)),
                "details": getattr(exc, "details", None),
            },
        }
        raw = json_bytes(packet)
    save_new(attempt / "packet.json", raw)
    save_new(
        attempt / "receipt.json",
        json_bytes(
            {
                "schema_version": "1.0",
                "session": directory.name,
                "target_dir": str(root),
                "request_sha256": digest(request),
                "packet_sha256": digest(raw),
                "builder_exit_status": status,
                "source_sha256": hashes,
            }
        ),
    )
    return raw


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--request", required=True, type=Path)
    prep.add_argument("--session", default=None)
    take = commands.add_parser("consume")
    take.add_argument("--session", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            print(json.dumps(prepare(args.request, args.session or str(uuid.uuid4()))))
        else:
            sys.stdout.buffer.write(consume(args.session))
    except (OSError, ValueError, KeyError) as exc:
        print(
            json.dumps({"error": {"code": "dispatch_transport", "message": str(exc)}}),
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
