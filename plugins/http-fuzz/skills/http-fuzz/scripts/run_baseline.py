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


def _send_request(
    session: requests.Session,
    req_kwargs: dict[str, Any],
    timeout: float,
    index: int,
) -> dict[str, Any]:
    start = time.monotonic()
    try:
        resp = session.request(timeout=timeout, **req_kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        body = resp.text[:500].replace("\n", " ").replace("\r", "")
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
        result = _send_request(session, req_kwargs, args.timeout, i)
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
