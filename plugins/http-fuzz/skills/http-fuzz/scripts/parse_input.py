#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.31", "dpkt>=1.9.8"]
# ///
"""Parse an HTTP request from raw text, curl command, HAR file, or PCAP/PCAPNG into a manifest.

Outputs a JSON object to stdout. Exits 1 with a JSON error object on failure.
"""

import argparse
import io
import json
import re
import socket as _socket
import struct
import sys
import urllib.parse
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

import dpkt

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

# PCAP link-layer type constants
_DLT_NULL = 0        # BSD loopback (macOS lo0)
_DLT_EN10MB = 1      # Ethernet
_DLT_RAW = 101       # Raw IP
_DLT_LINUX_SLL = 113 # Linux cooked capture (Linux lo)

# HTTP/1.x request-line pattern used to find request boundaries in a TCP stream
_HTTP_REQUEST_LINE = re.compile(
    rb"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)"
    rb" [^\r\n]+ HTTP/1\.[01]\r?\n",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Shared dataclasses
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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
        PathSegment(index=i, value=part, fuzzable=_is_fuzzable_path_segment(part))
        for i, part in enumerate(parts)
    ]


def _parse_query_string(qs: str) -> list[Param]:
    return [
        Param(name=name, value=value, type="string")
        for name, value in urllib.parse.parse_qsl(qs, keep_blank_values=True)
    ]


def _classify_header(name: str, value: str) -> Header:
    sensitive = name.lower() in _SENSITIVE_HEADERS
    return Header(
        name=name,
        value=value,
        fuzzable=not sensitive,
        reason="auth/session material — skip fuzzing to avoid lockout" if sensitive else "",
    )


def _parse_json_body(body_text: str) -> tuple[str, list[Param], list[str]]:
    notes: list[str] = []
    try:
        data = json.loads(body_text)
    except json.JSONDecodeError as exc:
        return "raw", [], [f"Body looks like JSON but failed to parse: {exc}"]

    if isinstance(data, dict):
        params = [Param(name=k, value=v, type=_infer_type(v)) for k, v in data.items()]
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
    params = [
        Param(name=name, value=value, type="string")
        for name, value in urllib.parse.parse_qsl(body_text, keep_blank_values=True)
    ]
    return "form", params


def _detect_body_format(content_type: str, body_text: str) -> str:
    ct = content_type.lower().split(";")[0].strip()
    if ct == "application/json" or ct.endswith("+json"):
        return "json"
    if ct == "application/x-www-form-urlencoded":
        return "form"
    if ct.startswith("multipart/"):
        return "multipart"
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

    content_type = next((v for k, v in headers_raw if k.lower() == "content-type"), "")
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
# Text-based parsers: raw HTTP, curl, HAR
# ---------------------------------------------------------------------------


def parse_raw_http(text: str) -> Manifest:
    """Parse a raw HTTP request (RFC 7230 format)."""
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines:
        raise ValueError("Empty input")
    request_line = lines[0].strip()
    parts = request_line.split(None, 2)
    if len(parts) < 2:
        raise ValueError(f"Cannot parse request line: {request_line!r}")
    method, target = parts[0], parts[1]

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
    cmd = re.sub(r"\\\s*\n\s*", " ", cmd)
    cmd = re.sub(r"^\s*curl\s+", "", cmd)

    method = "GET"
    url = ""
    headers_raw: list[tuple[str, str]] = []
    body_text = ""

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
    rows = [
        (
            str(i),
            e.get("request", {}).get("method", "?"),
            e.get("request", {}).get("url", "?")[:80],
            str(e.get("response", {}).get("status", "?")),
        )
        for i, e in enumerate(entries)
    ]
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
    headers_raw = [
        (h["name"], h["value"]) for h in req.get("headers", []) if "name" in h and "value" in h
    ]

    body_text = ""
    post_data = req.get("postData", {})
    if post_data:
        body_text = post_data.get("text", "")
        if not body_text:
            params = post_data.get("params", [])
            if params:
                pairs = [(p["name"], p.get("value", "")) for p in params]
                body_text = urllib.parse.urlencode(pairs)
                headers_raw.append(("Content-Type", "application/x-www-form-urlencoded"))

    return _build_manifest_from_parts(method, url, headers_raw, body_text)


# ---------------------------------------------------------------------------
# PCAP/PCAPNG parser
# ---------------------------------------------------------------------------


def _inet_to_str(addr: bytes) -> str:
    if len(addr) == 4:
        return _socket.inet_ntoa(addr)
    return _socket.inet_ntop(_socket.AF_INET6, addr)


def _ip_from_frame(buf: bytes, datalink: int) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
    """Extract the IP layer from a link-layer frame. Returns None on any error."""
    try:
        if datalink == _DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
        elif datalink == _DLT_NULL:
            # BSD loopback: 4-byte AF_ family, native byte order
            (family,) = struct.unpack_from("=I", buf)
            payload = buf[4:]
            ip = dpkt.ip.IP(payload) if family == 2 else dpkt.ip6.IP6(payload)
        elif datalink == _DLT_RAW:
            ip = dpkt.ip.IP(buf) if (buf[0] >> 4) == 4 else dpkt.ip6.IP6(buf)
        elif datalink == _DLT_LINUX_SLL:
            # Linux cooked: 16-byte SLL header before IP
            ip = dpkt.ip.IP(buf[16:])
        else:
            return None
    except Exception:
        return None

    return ip if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) else None


def _open_pcap_reader(data: bytes) -> tuple[Any, int]:
    """Open raw bytes as a PCAP or PCAPNG reader. Returns (reader, datalink)."""
    buf = io.BytesIO(data)
    try:
        reader = dpkt.pcap.Reader(buf)
        return reader, reader.datalink()
    except Exception:
        pass

    buf.seek(0)
    try:
        reader = dpkt.pcapng.Reader(buf)
        datalink = reader.datalink() if hasattr(reader, "datalink") else _DLT_EN10MB
        return reader, datalink
    except Exception:
        pass

    raise ValueError(
        "Cannot parse as PCAP or PCAPNG. "
        "Ensure the file is an unencrypted capture (not a Wireshark session key log)."
    )


def _reassemble_tcp_streams(reader: Any, datalink: int) -> dict[tuple, bytes]:
    """Reassemble TCP payload data per flow. Returns {(src, sport, dst, dport): bytes}."""
    raw: dict[tuple, list[tuple[int, bytes]]] = defaultdict(list)

    for _ts, buf in reader:
        ip = _ip_from_frame(buf, datalink)
        if ip is None:
            continue
        tcp = getattr(ip, "data", None)
        if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data:
            continue
        src = _inet_to_str(ip.src)
        dst = _inet_to_str(ip.dst)
        raw[(src, tcp.sport, dst, tcp.dport)].append((tcp.seq, tcp.data))

    result: dict[tuple, bytes] = {}
    for key, segs in raw.items():
        segs.sort(key=lambda x: x[0])
        # Deduplicate retransmissions by sequence number
        seen: set[int] = set()
        chunks: list[bytes] = []
        for seq, data in segs:
            if seq not in seen:
                seen.add(seq)
                chunks.append(data)
        result[key] = b"".join(chunks)

    return result


def _decode(v: bytes | str) -> str:
    return v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v


def _http_requests_from_stream(
    data: bytes,
    dst_ip: str,
    dst_port: int,
) -> list[Manifest]:
    """Find and parse all HTTP/1.x requests in a reassembled TCP stream."""
    starts = [m.start() for m in _HTTP_REQUEST_LINE.finditer(data)]
    requests: list[Manifest] = []

    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(data)
        chunk = data[start:end]

        try:
            req = dpkt.http.Request(chunk)
        except Exception:
            continue

        method = _decode(req.method)
        uri = _decode(req.uri)

        headers_raw: list[tuple[str, str]] = []
        host = ""
        for k, v in req.headers.items():
            k_s, v_s = _decode(k), _decode(v)
            headers_raw.append((k_s, v_s))
            if k_s.lower() == "host":
                host = v_s

        if uri.startswith("http://") or uri.startswith("https://"):
            url = uri
        elif host:
            scheme = "https" if dst_port == 443 else "http"
            url = f"{scheme}://{host}{uri}"
        else:
            scheme = "https" if dst_port == 443 else "http"
            url = f"{scheme}://{dst_ip}:{dst_port}{uri}"

        body_bytes = getattr(req, "body", b"") or b""
        body_text = body_bytes.decode("utf-8", errors="replace")

        requests.append(_build_manifest_from_parts(method, url, headers_raw, body_text))

    return requests


def _all_pcap_requests(data: bytes) -> list[Manifest]:
    """Return every HTTP/1.x request found in a PCAP/PCAPNG file."""
    reader, datalink = _open_pcap_reader(data)
    streams = _reassemble_tcp_streams(reader, datalink)
    requests: list[Manifest] = []
    for (_, _, dst_ip, dst_port), stream_data in streams.items():
        requests.extend(_http_requests_from_stream(stream_data, dst_ip, dst_port))
    return requests


def _list_pcap_entries(data: bytes) -> None:
    """Print a table of HTTP requests found in a PCAP file."""
    try:
        requests = _all_pcap_requests(data)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return

    if not requests:
        print(
            "No HTTP/1.x requests found. "
            "TLS-encrypted (HTTPS) and HTTP/2 traffic cannot be decoded.",
            file=sys.stderr,
        )
        return

    rows = [(str(i), r.method, r.url[:80]) for i, r in enumerate(requests)]
    labels = ("Index", "Method", "URL")
    col_widths = [max(len(r[c]) for r in rows + [labels]) for c in range(3)]
    header = "  ".join(h.ljust(w) for h, w in zip(labels, col_widths))
    print(header)
    print("-" * len(header))
    for row in rows:
        print("  ".join(v.ljust(w) for v, w in zip(row, col_widths)))


def parse_pcap(data: bytes, entry_index: int = 0) -> Manifest:
    """Parse a PCAP/PCAPNG file and return the HTTP request at entry_index."""
    requests = _all_pcap_requests(data)

    if not requests:
        raise ValueError(
            "No HTTP/1.x requests found in PCAP. "
            "TLS-encrypted (HTTPS) traffic cannot be decoded without session keys. "
            "HTTP/2 binary framing is not supported — use HTTP/1.1 or export a HAR instead."
        )
    if entry_index >= len(requests):
        raise ValueError(
            f"Entry index {entry_index} out of range — "
            f"found {len(requests)} HTTP request(s). "
            "Use --list-entries to see all."
        )
    return requests[entry_index]


# ---------------------------------------------------------------------------
# Auto-detect format from raw bytes
# ---------------------------------------------------------------------------

# PCAP magic numbers (little-endian, big-endian, nanosecond variants)
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def detect_format(data: bytes) -> str:
    """Auto-detect input format from raw file bytes."""
    if len(data) >= 4:
        if data[:4] in _PCAP_MAGIC or data[:4] == _PCAPNG_MAGIC:
            return "pcap"

    # Try decoding as UTF-8 text for the remaining formats
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "pcap"  # Unknown binary — attempt pcap as last resort

    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "har"
    if re.match(r"^curl\b", stripped, re.IGNORECASE):
        return "curl"
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
        choices=["auto", "raw-http", "curl", "har", "pcap"],
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
        help="Entry index for HAR or PCAP files with multiple requests (default: 0)",
    )
    parser.add_argument(
        "--list-entries",
        action="store_true",
        help="Print request table and exit (HAR and PCAP formats)",
    )
    args = parser.parse_args()

    # Always read as binary so PCAP magic-byte detection works
    if args.stdin:
        raw = sys.stdin.buffer.read()
    elif args.file:
        try:
            with open(args.file, "rb") as f:
                raw = f.read()
        except OSError as exc:
            _error_exit(f"Cannot read file '{args.file}': {exc}")
            return
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)

    fmt = args.format if args.format != "auto" else detect_format(raw)

    if args.list_entries:
        if fmt == "pcap":
            _list_pcap_entries(raw)
        elif fmt == "har":
            try:
                har = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                _error_exit(f"Invalid HAR file: {exc}")
                return
            _list_har_entries(har)
        else:
            _error_exit("--list-entries is only valid for HAR and PCAP formats")
        return

    try:
        if fmt == "pcap":
            manifest = parse_pcap(raw, args.entry)
        else:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                _error_exit(f"Cannot decode file as UTF-8: {exc}")
                return
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

    def to_dict(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            return {k: to_dict(v) for k, v in asdict(obj).items()}
        if isinstance(obj, list):
            return [to_dict(v) for v in obj]
        return obj

    print(json.dumps(to_dict(manifest), indent=2))


if __name__ == "__main__":
    main()
