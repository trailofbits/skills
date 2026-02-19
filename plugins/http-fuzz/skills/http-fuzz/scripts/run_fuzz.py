#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.31", "urllib3>=2.0"]
# ///
"""Execute a fuzz corpus against an HTTP target and stream results as NDJSON.

One parameter is varied per request; all other parameters retain original baseline values.
Results stream to stdout as requests complete. Progress and errors go to stderr.
"""

import argparse
import json
import queue
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

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

    # Path segments and headers are not fuzz targets by default in run_fuzz
    # (they can be added to corpus dir to opt in)

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

    # Determine where the param lives (query string, JSON body, form body)
    all_query = {p["name"] for p in manifest.get("query_params", [])}
    all_body = {p["name"] for p in manifest.get("body_params", [])}
    body_format = manifest.get("body_format", "")

    parsed_url = req["url"]

    if param in all_query:
        # Rebuild query string with fuzz value substituted
        import urllib.parse
        parsed = urllib.parse.urlparse(parsed_url)
        qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        qs[param] = value
        new_query = urllib.parse.urlencode(qs)
        parsed_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        req["url"] = parsed_url

    elif param in all_body and body_format == "json":
        body = dict(base.get("_body_json", {}))
        # Coerce value to the original JSON type if possible
        original_type = next(
            (p.get("type", "string") for p in manifest.get("body_params", [])
             if p["name"] == param),
            "string",
        )
        coerced = _coerce_value(value, original_type)
        body[param] = coerced
        req["json"] = body

    elif param in all_body and body_format == "form":
        body = dict(base.get("_body_form", {}))
        body[param] = value
        req["data"] = body

    return req


def _coerce_value(value: str, original_type: str) -> Any:
    """Try to coerce a string fuzz value to the original parameter type.

    If the fuzz value is 'null', 'true', 'false', or a number string, coerce it to the
    appropriate Python type. Otherwise pass as-is (string injection).
    """
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if original_type in ("integer", "float"):
        try:
            if "." in value:
                return float(value)
            return int(value)
        except (ValueError, OverflowError):
            pass
    if original_type == "boolean":
        if value in ("1", "yes", "on"):
            return True
        if value in ("0", "no", "off"):
            return False
    return value


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
            param=param,
            value=value,
            status_code=resp.status_code,
            response_time_ms=elapsed_ms,
            content_length=len(resp.content),
            content_type=resp.headers.get("content-type", ""),
            body_preview=body,
            error=None,
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


def _print_dry_run(corpus: dict[str, list[str]], manifest: dict[str, Any]) -> None:
    rows = []
    for param, values in corpus.items():
        for value in values:
            display_value = value if len(value) <= 50 else value[:47] + "..."
            rows.append((param, display_value))

    if not rows:
        print("No fuzz tasks — corpus is empty.", file=sys.stderr)
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
    args = parser.parse_args()

    manifest = _load_manifest(args.manifest)
    fuzzable = _get_fuzzable_params(manifest, args.params)

    if not fuzzable:
        print(
            json.dumps({"error": "No fuzzable parameters found in manifest. "
                        "Check that body_params or query_params are present and fuzzable=true."}),
        )
        sys.exit(1)

    corpus = _load_corpus(args.corpus_dir, fuzzable)

    if not corpus:
        msg = (
            f"No corpus files found in '{args.corpus_dir}'. "
            "Generate corpus files first (e.g. corpus/email.txt with one value per line)."
        )
        print(json.dumps({"error": msg}))
        sys.exit(1)

    if args.dry_run:
        _print_dry_run(corpus, manifest)
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

    # Enqueue all tasks
    for param, values in corpus.items():
        for value in values:
            task_q.put((param, value))

    # Poison pills
    for _ in range(args.threads):
        task_q.put(None)

    # Create session per thread for connection pooling
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
            result_dict = asdict(item)
            print(json.dumps(result_dict), flush=True)

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
