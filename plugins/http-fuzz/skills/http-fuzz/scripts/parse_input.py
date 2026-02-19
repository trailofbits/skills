#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.31"]
# ///
"""Parse an HTTP request from raw text, curl command, or HAR file into a normalized manifest.

Outputs a JSON object to stdout. Exits 1 with a JSON error object on failure.
"""

import argparse
import json
import re
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any

# Headers that carry auth/session material — skip fuzzing by default to avoid lockout
_SENSITIVE_HEADERS = frozenset(
    [
        "authorization",
        "cookie",
        "x-csrf-token",
        "x-xsrf-token",
        "x-api-key",
        "x-auth-token",
        "api-key",
        "x-access-token",
    ]
)


@dataclass
class Param:
    name: str
    value: Any
    type: str  # "string" | "integer" | "float" | "boolean" | "null" | "object" | "array"
    fuzzable: bool = True
    reason: str = ""


@dataclass
class PathSegment:
    index: int
    value: str
    fuzzable: bool


@dataclass
class Header:
    name: str
    value: str
    fuzzable: bool
    reason: str = ""


@dataclass
class Manifest:
    method: str
    url: str
    base_url: str
    path_segments: list[PathSegment] = field(default_factory=list)
    query_params: list[Param] = field(default_factory=list)
    headers: list[Header] = field(default_factory=list)
    body_format: str = ""  # "json" | "form" | "multipart" | "raw" | ""
    body_params: list[Param] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _infer_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, (dict, list)):
        return type(value).__name__
    return "string"


def _is_fuzzable_path_segment(segment: str) -> bool:
    """Path segments that look like IDs (numeric, UUID, hex) are worth fuzzing."""
    if re.fullmatch(r"\d+", segment):
        return True
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", segment):
        return True
    if re.fullmatch(r"[0-9a-f]{24,}", segment):
        return True
    return False


def _parse_path_segments(path: str) -> list[PathSegment]:
    parts = [p for p in path.split("/") if p and p not in (".", "..")]
    return [
        PathSegment(
            index=i,
            value=part,
            fuzzable=_is_fuzzable_path_segment(part),
        )
        for i, part in enumerate(parts)
    ]


def _parse_query_string(qs: str) -> list[Param]:
    params = []
    for name, value in urllib.parse.parse_qsl(qs, keep_blank_values=True):
        params.append(Param(name=name, value=value, type="string"))
    return params


def _classify_header(name: str, value: str) -> Header:
    sensitive = name.lower() in _SENSITIVE_HEADERS
    return Header(
        name=name,
        value=value,
        fuzzable=not sensitive,
        reason="auth/session material — skip fuzzing to avoid lockout" if sensitive else "",
    )


def _parse_json_body(body_text: str) -> tuple[str, list[Param], list[str]]:
    """Return (body_format, params, notes)."""
    notes: list[str] = []
    try:
        data = json.loads(body_text)
    except json.JSONDecodeError as exc:
        return "raw", [], [f"Body looks like JSON but failed to parse: {exc}"]

    if isinstance(data, dict):
        params = [
            Param(name=k, value=v, type=_infer_type(v))
            for k, v in data.items()
        ]
        # Nested objects/arrays are noted but still included as fuzz targets for their
        # top-level keys (the fuzzer replaces the entire value with a fuzz string).
        for p in params:
            if p.type in ("dict", "list"):
                notes.append(
                    f"Body param '{p.name}' is a nested {p.type}; "
                    "fuzzing will replace the entire value with scalar inputs."
                )
        return "json", params, notes
    if isinstance(data, list):
        return "json", [], ["Body is a JSON array — top-level arrays are not fuzzed individually."]
    return "json", [], notes


def _parse_form_body(body_text: str) -> tuple[str, list[Param]]:
    params = []
    for name, value in urllib.parse.parse_qsl(body_text, keep_blank_values=True):
        params.append(Param(name=name, value=value, type="string"))
    return "form", params


def _detect_body_format(content_type: str, body_text: str) -> str:
    ct = content_type.lower().split(";")[0].strip()
    if ct == "application/json" or ct.endswith("+json"):
        return "json"
    if ct == "application/x-www-form-urlencoded":
        return "form"
    if ct.startswith("multipart/"):
        return "multipart"
    # Heuristic fallback
    stripped = body_text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if "=" in body_text and "&" in body_text:
        return "form"
    return "raw"


def _build_manifest_from_parts(
    method: str,
    url: str,
    headers_raw: list[tuple[str, str]],
    body_text: str,
) -> Manifest:
    parsed = urllib.parse.urlparse(url)
    base_url = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
    path_segs = _parse_path_segments(parsed.path)
    query_params = _parse_query_string(parsed.query)
    headers = [_classify_header(k, v) for k, v in headers_raw]

    # Determine content-type for body parsing
    content_type = next(
        (v for k, v in headers_raw if k.lower() == "content-type"),
        "",
    )
    body_format = ""
    body_params: list[Param] = []
    notes: list[str] = []

    if body_text:
        body_format = _detect_body_format(content_type, body_text)
        if body_format == "json":
            body_format, body_params, notes = _parse_json_body(body_text)
        elif body_format == "form":
            body_format, body_params = _parse_form_body(body_text)
        elif body_format == "multipart":
            notes.append(
                "Multipart/form-data body detected. Binary file parts are not fuzzed; "
                "use --format raw-http and manually remove file parts to fuzz text fields."
            )
        else:
            notes.append("Body format is 'raw' — no parameters extracted for fuzzing.")

    return Manifest(
        method=method.upper(),
        url=url,
        base_url=base_url,
        path_segments=path_segs,
        query_params=query_params,
        headers=headers,
        body_format=body_format,
        body_params=body_params,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Format-specific parsers
# ---------------------------------------------------------------------------


def parse_raw_http(text: str) -> Manifest:
    """Parse a raw HTTP request (RFC 7230 format)."""
    lines = text.replace("\r\n", "\n").split("\n")

    # Request line
    if not lines:
        raise ValueError("Empty input")
    request_line = lines[0].strip()
    parts = request_line.split(None, 2)
    if len(parts) < 2:
        raise ValueError(f"Cannot parse request line: {request_line!r}")
    method = parts[0]
    target = parts[1]

    # Headers
    headers_raw: list[tuple[str, str]] = []
    body_start = len(lines)
    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            body_start = i + 1
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers_raw.append((k.strip(), v.strip()))

    body_text = "\n".join(lines[body_start:]).strip()

    # Reconstruct full URL
    host = next((v for k, v in headers_raw if k.lower() == "host"), "")
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    elif host:
        scheme = "https" if "443" in host or not host else "http"
        url = f"{scheme}://{host}{target}"
    else:
        url = f"http://localhost{target}"

    return _build_manifest_from_parts(method, url, headers_raw, body_text)


def parse_curl(cmd: str) -> Manifest:
    """Parse a curl command into a manifest."""
    # Normalize multi-line curl commands (backslash continuation)
    cmd = re.sub(r"\\\s*\n\s*", " ", cmd)
    # Strip leading 'curl' token
    cmd = re.sub(r"^\s*curl\s+", "", cmd)

    method = "GET"
    url = ""
    headers_raw: list[tuple[str, str]] = []
    body_text = ""

    # Tokenize respecting single and double quotes
    tokens: list[str] = []
    i = 0
    while i < len(cmd):
        if cmd[i] in ('"', "'"):
            quote = cmd[i]
            j = cmd.index(quote, i + 1)
            tokens.append(cmd[i + 1 : j])
            i = j + 1
        elif cmd[i].isspace():
            i += 1
        else:
            j = i
            while j < len(cmd) and not cmd[j].isspace():
                j += 1
            tokens.append(cmd[i:j])
            i = j

    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in ("-X", "--request") and idx + 1 < len(tokens):
            idx += 1
            method = tokens[idx]
        elif tok in ("-H", "--header") and idx + 1 < len(tokens):
            idx += 1
            raw = tokens[idx]
            if ":" in raw:
                k, _, v = raw.partition(":")
                headers_raw.append((k.strip(), v.strip()))
        elif tok in ("-d", "--data", "--data-raw", "--data-ascii") and idx + 1 < len(tokens):
            idx += 1
            body_text = tokens[idx]
            if method == "GET":
                method = "POST"
        elif tok in ("--data-urlencode",) and idx + 1 < len(tokens):
            idx += 1
            body_text = urllib.parse.quote(tokens[idx])
            if method == "GET":
                method = "POST"
        elif tok in ("--json",) and idx + 1 < len(tokens):
            idx += 1
            body_text = tokens[idx]
            headers_raw.append(("Content-Type", "application/json"))
            if method == "GET":
                method = "POST"
        elif tok in ("-b", "--cookie") and idx + 1 < len(tokens):
            idx += 1
            headers_raw.append(("Cookie", tokens[idx]))
        elif tok in ("-u", "--user") and idx + 1 < len(tokens):
            idx += 1
            import base64
            encoded = base64.b64encode(tokens[idx].encode()).decode()
            headers_raw.append(("Authorization", f"Basic {encoded}"))
        elif not tok.startswith("-") and not url:
            url = tok
        idx += 1

    if not url:
        raise ValueError("No URL found in curl command")

    return _build_manifest_from_parts(method, url, headers_raw, body_text)


def _list_har_entries(har: dict) -> None:
    entries = har.get("log", {}).get("entries", [])
    if not entries:
        print("No entries found in HAR file.", file=sys.stderr)
        return
    rows = []
    for i, entry in enumerate(entries):
        req = entry.get("request", {})
        resp = entry.get("response", {})
        rows.append(
            (
                str(i),
                req.get("method", "?"),
                req.get("url", "?")[:80],
                str(resp.get("status", "?")),
            )
        )
    labels = ("Index", "Method", "URL", "Status")
    col_widths = [max(len(r[c]) for r in rows + [labels]) for c in range(4)]
    header = "  ".join(h.ljust(w) for h, w in zip(labels, col_widths))
    print(header)
    print("-" * len(header))
    for row in rows:
        print("  ".join(v.ljust(w) for v, w in zip(row, col_widths)))


def parse_har(har_text: str, entry_index: int = 0) -> Manifest:
    """Parse a HAR file and extract the request at entry_index."""
    try:
        har = json.loads(har_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in HAR file: {exc}") from exc

    entries = har.get("log", {}).get("entries", [])
    if not entries:
        raise ValueError("HAR file contains no entries")
    if entry_index >= len(entries):
        raise ValueError(
            f"Entry index {entry_index} out of range — HAR has {len(entries)} entries. "
            "Use --list-entries to see available entries."
        )

    req = entries[entry_index].get("request", {})
    method = req.get("method", "GET")
    url = req.get("url", "")

    headers_raw: list[tuple[str, str]] = [
        (h["name"], h["value"]) for h in req.get("headers", []) if "name" in h and "value" in h
    ]

    body_text = ""
    post_data = req.get("postData", {})
    if post_data:
        body_text = post_data.get("text", "")
        if not body_text:
            # Some HAR exporters put form params in postData.params
            params = post_data.get("params", [])
            if params:
                pairs = [(p["name"], p.get("value", "")) for p in params]
                body_text = urllib.parse.urlencode(pairs)
                headers_raw.append(("Content-Type", "application/x-www-form-urlencoded"))

    return _build_manifest_from_parts(method, url, headers_raw, body_text)


# ---------------------------------------------------------------------------
# Auto-detect format
# ---------------------------------------------------------------------------


def detect_format(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "har"
    if re.match(r"^curl\b", stripped, re.IGNORECASE):
        return "curl"
    # Raw HTTP: first token is an HTTP method
    first_word = stripped.split()[0] if stripped.split() else ""
    http_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
    if first_word.upper() in http_methods:
        return "raw-http"
    return "raw-http"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _error_exit(msg: str) -> None:
    print(json.dumps({"error": msg}), file=sys.stdout)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse an HTTP request into a normalized fuzz manifest."
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Input file path (omit to read from stdin with --stdin)",
    )
    parser.add_argument(
        "--format",
        choices=["auto", "raw-http", "curl", "har"],
        default="auto",
        help="Input format (default: auto-detect)",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read input from stdin",
    )
    parser.add_argument(
        "--entry",
        type=int,
        default=0,
        metavar="N",
        help="HAR entry index to parse (default: 0)",
    )
    parser.add_argument(
        "--list-entries",
        action="store_true",
        help="Print HAR entry table and exit (HAR format only)",
    )
    args = parser.parse_args()

    if args.stdin:
        text = sys.stdin.read()
    elif args.file:
        try:
            with open(args.file) as f:
                text = f.read()
        except OSError as exc:
            _error_exit(f"Cannot read file '{args.file}': {exc}")
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)

    fmt = args.format if args.format != "auto" else detect_format(text)

    if args.list_entries:
        if fmt != "har":
            _error_exit("--list-entries is only valid for HAR format")
        try:
            har = json.loads(text)
        except json.JSONDecodeError as exc:
            _error_exit(f"Invalid JSON in HAR file: {exc}")
        _list_har_entries(har)
        return

    try:
        if fmt == "raw-http":
            manifest = parse_raw_http(text)
        elif fmt == "curl":
            manifest = parse_curl(text)
        elif fmt == "har":
            manifest = parse_har(text, args.entry)
        else:
            _error_exit(f"Unknown format: {fmt}")
            return
    except ValueError as exc:
        _error_exit(str(exc))
        return

    # Convert dataclasses to plain dicts for JSON serialization
    def to_dict(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            return {k: to_dict(v) for k, v in asdict(obj).items()}
        if isinstance(obj, list):
            return [to_dict(v) for v in obj]
        return obj

    print(json.dumps(to_dict(manifest), indent=2))


if __name__ == "__main__":
    main()
