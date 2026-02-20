#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.31", "urllib3>=2.0"]
# ///
"""Send baseline requests using original parameter values and report response statistics.

Outputs a JSON summary to stdout so Claude can assess baseline consistency before fuzzing.
Progress and errors go to stderr.
"""

import argparse
import json
import statistics
import sys
import time
from typing import Any

import requests
import urllib3


def _load_manifest(path: str) -> dict[str, Any]:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"Cannot load manifest '{path}': {exc}"}))
        sys.exit(1)


def _build_request(manifest: dict[str, Any]) -> dict[str, Any]:
    """Build requests.Request kwargs from a manifest."""
    method = manifest["method"]
    url = manifest["url"]

    # Reconstruct headers from manifest (only fuzzable=True headers in the original are included,
    # but here we send all of them as-is for a representative baseline)
    headers = {h["name"]: h["value"] for h in manifest.get("headers", [])}

    # Query params are already in the URL, nothing extra needed
    # Reconstruct body
    body_format = manifest.get("body_format", "")
    body_params = manifest.get("body_params", [])

    kwargs: dict[str, Any] = {"headers": headers}

    if body_params and body_format == "json":
        payload: dict[str, Any] = {p["name"]: p["value"] for p in body_params}
        kwargs["json"] = payload
        # requests will set Content-Type automatically; remove any existing one
        kwargs["headers"] = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    elif body_params and body_format == "form":
        kwargs["data"] = {p["name"]: p["value"] for p in body_params}
        kwargs["headers"] = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    elif body_format == "raw":
        # Raw body — not fuzzable but we still send it for baseline
        kwargs["data"] = ""

    return {"method": method, "url": url, **kwargs}


_HTML_BOUNDARY_SEARCH = 80  # chars to scan when snapping to an HTML element boundary


def _extract_body(
    text: str,
    preview_length: int = 0,
    preview_offset: int = 0,
    preview_find: str | None = None,
) -> str:
    """Return the body slice for display, collapsing internal newlines.

    Modes (applied in this order of precedence):

    1. ``preview_length == 0``  — full body, no truncation.
    2. ``preview_find`` set     — find the first occurrence of the needle,
       build a window of ``preview_length`` chars centred on it, snap
       start/end to the nearest HTML element boundary (``<`` or ``>``)
       within ``_HTML_BOUNDARY_SEARCH`` characters.  Falls back to
       ``preview_offset + preview_length`` if the needle is not found.
    3. ``preview_offset + preview_length`` — fixed window.
    4. ``preview_length`` only  — first N characters.

    The result has ``\\n`` and ``\\r`` replaced with spaces so it stays on
    one line in JSON output.
    """
    if preview_length == 0:
        return text.replace("\n", " ").replace("\r", "")

    if preview_find is not None:
        needle_pos = text.find(preview_find)
        if needle_pos == -1:
            start = preview_offset
            end = start + preview_length
        else:
            half = preview_length // 2
            mid = needle_pos + len(preview_find) // 2
            start = max(0, mid - half)
            end = min(len(text), start + preview_length)
            # Snap start backwards to nearest '>' boundary.
            lo = max(0, start - _HTML_BOUNDARY_SEARCH)
            idx = text.rfind(">", lo, start)
            if idx != -1:
                start = idx + 1
            # Snap end backwards to nearest '<' boundary, never below start.
            lo = max(start, end - _HTML_BOUNDARY_SEARCH)
            idx = text.rfind("<", lo, end)
            if idx != -1:
                end = idx
    else:
        start = preview_offset
        end = start + preview_length

    return text[start:end].replace("\n", " ").replace("\r", "")


def _send_request(
    session: requests.Session,
    req_kwargs: dict[str, Any],
    timeout: float,
    index: int,
    preview_length: int = 0,
    preview_offset: int = 0,
    preview_find: str | None = None,
) -> dict[str, Any]:
    start = time.monotonic()
    try:
        resp = session.request(timeout=timeout, **req_kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        body = _extract_body(resp.text, preview_length, preview_offset, preview_find)
        return {
            "index": index,
            "status_code": resp.status_code,
            "response_time_ms": elapsed_ms,
            "content_length": len(resp.content),
            "content_type": resp.headers.get("content-type", ""),
            "body_preview": body,
            "error": None,
        }
    except requests.exceptions.Timeout:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "index": index,
            "status_code": None,
            "response_time_ms": elapsed_ms,
            "content_length": 0,
            "content_type": "",
            "body_preview": "",
            "error": "timeout",
        }
    except requests.exceptions.RequestException as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "index": index,
            "status_code": None,
            "response_time_ms": elapsed_ms,
            "content_length": 0,
            "content_type": "",
            "body_preview": "",
            "error": str(exc),
        }


def _compute_summary(responses: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [r for r in responses if r["status_code"] is not None]

    # Status code distribution
    status_counts: dict[str, int] = {}
    for r in successful:
        key = str(r["status_code"])
        status_counts[key] = status_counts.get(key, 0) + 1

    if not successful:
        return {
            "status_codes": {},
            "median_response_ms": None,
            "p95_response_ms": None,
            "median_content_length": None,
            "content_length_variance_pct": None,
        }

    times = [r["response_time_ms"] for r in successful]
    lengths = [r["content_length"] for r in successful]

    times_sorted = sorted(times)
    p95_idx = max(0, int(len(times_sorted) * 0.95) - 1)

    median_length = statistics.median(lengths)
    length_variance_pct = (
        (max(lengths) - min(lengths)) / median_length * 100 if median_length > 0 else 0.0
    )

    return {
        "status_codes": status_counts,
        "median_response_ms": int(statistics.median(times)),
        "p95_response_ms": int(times_sorted[p95_idx]),
        "median_content_length": int(median_length),
        "content_length_variance_pct": round(length_variance_pct, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send baseline requests and summarize response characteristics."
    )
    parser.add_argument(
        "--manifest",
        required=True,
        metavar="PATH",
        help="Path to parse_input.py output JSON",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        metavar="N",
        help="Number of baseline requests to send (default: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECS",
        help="Per-request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable TLS certificate verification (for self-signed certs in test environments)",
    )
    preview_group = parser.add_argument_group(
        "preview truncation",
        "Control how the response body is captured in body_preview. "
        "Default is 0 (no truncation — full body). Behaviour matches run_fuzz.py.",
    )
    preview_group.add_argument(
        "--preview-length",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Characters of response body to capture in body_preview. "
            "0 (default) = full body, no truncation. "
            "Use a positive value to limit output size."
        ),
    )
    preview_group.add_argument(
        "--preview-offset",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Skip the first N characters of the body before capturing (default: 0). "
            "Has no effect when --preview-length is 0."
        ),
    )
    preview_group.add_argument(
        "--preview-find",
        metavar="STRING",
        help=(
            "Fuzzy truncation: find the first occurrence of STRING in the body and return "
            "--preview-length characters centred on it. Start/end are snapped to the nearest "
            "HTML element boundary (< or >) within 80 characters. Falls back to "
            "--preview-offset + --preview-length if STRING is not found. "
            "Has no effect when --preview-length is 0 (full body is returned regardless)."
        ),
    )
    args = parser.parse_args()

    manifest = _load_manifest(args.manifest)
    req_kwargs = _build_request(manifest)

    if args.no_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = not args.no_verify

    print(
        f"Sending {args.count} baseline request(s) to {manifest['url']} ...",
        file=sys.stderr,
    )

    responses = []
    for i in range(args.count):
        result = _send_request(
            session, req_kwargs, args.timeout, i,
            args.preview_length, args.preview_offset, args.preview_find,
        )
        status = result["status_code"] if result["status_code"] else f"ERROR: {result['error']}"
        ms = result["response_time_ms"]
        print(f"  [{i + 1}/{args.count}] {status} ({ms}ms)", file=sys.stderr)
        responses.append(result)

    summary = _compute_summary(responses)

    output = {
        "requests_sent": args.count,
        "responses": responses,
        "summary": summary,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
