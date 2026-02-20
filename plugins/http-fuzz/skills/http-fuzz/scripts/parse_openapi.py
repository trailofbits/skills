#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml>=6.0"]
# ///
"""Parse an OpenAPI description file (Swagger 2.0, OpenAPI 3.0, 3.1) into a normalized fuzz manifest.

Accepts a local file path or a remote URL (--url). Both JSON and YAML formats are supported.
Outputs a JSON manifest to stdout. Exits 1 with a JSON error object on failure.
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

import yaml

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
    body_format: str = ""  # "json" | "form" | "raw" | ""
    body_params: list[Param] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _classify_header(name: str, value: str) -> Header:
    sensitive = name.lower() in _SENSITIVE_HEADERS
    return Header(
        name=name,
        value=value,
        fuzzable=not sensitive,
        reason="auth/session material — skip fuzzing to avoid lockout" if sensitive else "",
    )


def _is_fuzzable_path_segment(segment: str) -> bool:
    """Numeric IDs, UUIDs, and hex strings are worth fuzzing."""
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


# ---------------------------------------------------------------------------
# $ref resolution
# ---------------------------------------------------------------------------


def _resolve_ref(ref_str: str, doc: dict, visited: frozenset | None = None) -> dict:
    """Resolve an internal JSON Pointer $ref (e.g. '#/components/schemas/User').

    Returns {} on cycle, external ref, or resolution failure.
    """
    if visited is None:
        visited = frozenset()
    if not isinstance(ref_str, str) or not ref_str.startswith("#/"):
        return {}
    if ref_str in visited:
        return {}
    visited = visited | {ref_str}
    parts = ref_str[2:].split("/")
    node = doc
    for part in parts:
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    if not isinstance(node, dict):
        return {}
    if "$ref" in node:
        return _resolve_ref(node["$ref"], doc, visited)
    return node


def _resolve_obj(obj: Any, doc: dict, visited: frozenset) -> dict:
    """If obj is a dict with a $ref, resolve it. Otherwise return obj."""
    if isinstance(obj, dict) and "$ref" in obj:
        resolved = _resolve_ref(obj["$ref"], doc, visited)
        return resolved if resolved else obj
    return obj if isinstance(obj, dict) else {}


# ---------------------------------------------------------------------------
# OpenAPI version and base URL
# ---------------------------------------------------------------------------


def _detect_openapi_version(doc: dict) -> str:
    """Return '2.0', '3.0', '3.1', or 'unknown'."""
    if doc.get("swagger"):
        return "2.0"
    openapi = doc.get("openapi", "")
    if isinstance(openapi, str):
        if openapi.startswith("3.1"):
            return "3.1"
        if openapi.startswith("3."):
            return "3.0"
    return "unknown"


def _openapi_base_url(doc: dict) -> str:
    """Extract base URL from the spec."""
    version = _detect_openapi_version(doc)
    if version == "2.0":
        schemes = doc.get("schemes", ["https"])
        scheme = schemes[0] if schemes else "https"
        host = doc.get("host", "localhost")
        base_path = doc.get("basePath", "/")
        if not base_path.startswith("/"):
            base_path = "/" + base_path
        return f"{scheme}://{host}{base_path}".rstrip("/")
    # 3.0 / 3.1
    servers = doc.get("servers", [])
    if servers:
        server = servers[0]
        url = server.get("url", "/")
        for var_name, var_def in server.get("variables", {}).items():
            url = url.replace("{" + var_name + "}", str(var_def.get("default", "")))
        return url.rstrip("/")
    return ""


# ---------------------------------------------------------------------------
# Schema example synthesis
# ---------------------------------------------------------------------------


def _schema_example(schema: dict, doc: dict, visited: frozenset) -> Any:
    """Return a plausible example value for a JSON Schema object."""
    if not isinstance(schema, dict):
        return ""
    schema = _resolve_obj(schema, doc, visited)
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    schema_type = schema.get("type", "string")
    if schema_type == "string":
        return ""
    if schema_type in ("integer", "number"):
        return 0
    if schema_type == "boolean":
        return False
    if schema_type == "array":
        return []
    if schema_type == "object":
        return {}
    return ""


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------


def _openapi_params_from_operation(
    path_params: list,
    op_params: list,
    request_body: dict | None,
    doc: dict,
) -> tuple[list[Param], list[Param], list[Header], str, list[str]]:
    """Extract query params, body params, extra headers, body_format, and notes.

    Returns: (query_params, body_params, extra_headers, body_format, notes)
    """
    notes: list[str] = []
    visited: frozenset = frozenset()

    # Merge path-level and operation-level params; operation overrides by (name, in)
    merged: dict[tuple[str, str], dict] = {}
    for p in path_params:
        p = _resolve_obj(p, doc, visited)
        merged[(p.get("name", ""), p.get("in", ""))] = p
    for p in op_params:
        p = _resolve_obj(p, doc, visited)
        merged[(p.get("name", ""), p.get("in", ""))] = p

    query_params: list[Param] = []
    body_params: list[Param] = []
    extra_headers: list[Header] = []
    swagger_form_params: list[Param] = []
    body_format = ""

    for (name, location), param in merged.items():
        if not name:
            continue
        schema = _resolve_obj(param.get("schema", {}), doc, visited)
        # Swagger 2.0 puts type/default directly on param; 3.x uses schema wrapper
        param_type = (
            (schema.get("type") if schema else None) or param.get("type", "string")
        )
        # Value: check param directly first (Swagger 2.0 has no schema wrapper)
        value = param.get("example")
        if value is None:
            value = param.get("default")
        if value is None:
            value = schema.get("example") if schema else None
        if value is None:
            value = schema.get("default") if schema else None
        if value is None:
            if schema:
                value = _schema_example(schema, doc, visited)
            else:
                value = _schema_example({"type": param_type}, doc, visited)

        if location == "query":
            query_params.append(Param(name=name, value=value, type=param_type))
        elif location == "header":
            extra_headers.append(_classify_header(name, str(value)))
        elif location == "path":
            pass  # handled by path template substitution
        elif location == "cookie":
            extra_headers.append(_classify_header("Cookie", f"{name}={value}"))
        elif location == "body":
            # Swagger 2.0 body parameter
            body_schema = _resolve_obj(param.get("schema", {}), doc, visited)
            if body_schema:
                for prop_name, prop_schema in body_schema.get("properties", {}).items():
                    prop_schema = _resolve_obj(prop_schema, doc, visited)
                    body_params.append(Param(
                        name=prop_name,
                        value=_schema_example(prop_schema, doc, visited),
                        type=prop_schema.get("type", "string"),
                    ))
                body_format = "json"
        elif location == "formData":
            swagger_form_params.append(Param(name=name, value=value, type=param_type))

    if swagger_form_params:
        body_params = swagger_form_params
        body_format = "form"

    # OpenAPI 3.x requestBody
    if request_body and not body_params:
        rb = _resolve_obj(request_body, doc, visited)
        content = rb.get("content", {})
        if "application/json" in content:
            schema = _resolve_obj(content["application/json"].get("schema", {}), doc, visited)
            for prop_name, prop_schema in schema.get("properties", {}).items():
                prop_schema = _resolve_obj(prop_schema, doc, visited)
                body_params.append(Param(
                    name=prop_name,
                    value=_schema_example(prop_schema, doc, visited),
                    type=prop_schema.get("type", "string"),
                ))
            body_format = "json"
        elif "application/x-www-form-urlencoded" in content:
            schema = _resolve_obj(
                content["application/x-www-form-urlencoded"].get("schema", {}), doc, visited
            )
            for prop_name, prop_schema in schema.get("properties", {}).items():
                prop_schema = _resolve_obj(prop_schema, doc, visited)
                body_params.append(Param(
                    name=prop_name,
                    value=_schema_example(prop_schema, doc, visited),
                    type=prop_schema.get("type", "string"),
                ))
            body_format = "form"
        elif content:
            first_ct = next(iter(content))
            notes.append(
                f"requestBody content type '{first_ct}' is not application/json or "
                "application/x-www-form-urlencoded — body params not extracted."
            )
            body_format = "raw"

    return query_params, body_params, extra_headers, body_format, notes


# ---------------------------------------------------------------------------
# Operation collection and listing
# ---------------------------------------------------------------------------

_HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options", "trace"]


def _collect_operations(doc: dict) -> list[tuple[str, str, dict]]:
    """Return list of (path_template, METHOD, operation_dict) for all operations."""
    operations = []
    for path_template, path_item in doc.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method in _HTTP_METHODS:
            if method in path_item and isinstance(path_item[method], dict):
                operations.append((path_template, method.upper(), path_item[method]))
    return operations


def _list_operations(doc: dict) -> None:
    operations = _collect_operations(doc)
    if not operations:
        print("No operations found in OpenAPI spec.", file=sys.stderr)
        return
    rows = [(str(i), m, p[:60], o.get("operationId", ""))
            for i, (p, m, o) in enumerate(operations)]
    labels = ("Index", "Method", "Path", "OperationId")
    col_widths = [max(len(r[c]) for r in rows + [labels]) for c in range(4)]
    header = "  ".join(h.ljust(w) for h, w in zip(labels, col_widths))
    print(header)
    print("-" * len(header))
    for row in rows:
        print("  ".join(v.ljust(w) for v, w in zip(row, col_widths)))


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


def parse_openapi(text: str, operation_id: str | None = None, entry_index: int = 0) -> Manifest:
    """Parse an OpenAPI spec and extract a single operation as a fuzz manifest."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Failed to parse as JSON or YAML: {exc}") from exc

    if not isinstance(doc, dict):
        raise ValueError("OpenAPI spec must be a JSON/YAML object at the root level")

    version = _detect_openapi_version(doc)
    if version == "unknown":
        raise ValueError(
            "Document does not appear to be an OpenAPI spec (missing 'swagger' or 'openapi' key)"
        )

    base_url = _openapi_base_url(doc)
    operations = _collect_operations(doc)

    if not operations:
        raise ValueError("No operations found in OpenAPI spec (empty 'paths')")

    # Select operation
    if operation_id is not None:
        matching = [(p, m, o) for p, m, o in operations if o.get("operationId") == operation_id]
        if not matching:
            available = [o.get("operationId", "") for _, _, o in operations if o.get("operationId")]
            raise ValueError(
                f"operationId '{operation_id}' not found. "
                f"Available: {available}. Use --list-entries to see all operations."
            )
        path_template, method, op = matching[0]
    else:
        if entry_index >= len(operations):
            raise ValueError(
                f"Operation index {entry_index} out of range — "
                f"spec has {len(operations)} operations. "
                "Use --list-entries to see available operations."
            )
        path_template, method, op = operations[entry_index]

    # Merge path-level and operation-level parameters
    paths = doc.get("paths", {})
    path_item = paths.get(path_template, {})
    path_level_params = path_item.get("parameters", [])
    op_params = op.get("parameters", [])

    query_params, body_params, extra_headers, body_format, notes = _openapi_params_from_operation(
        path_level_params, op_params, op.get("requestBody"), doc
    )

    # Build concrete path by substituting path params that have explicit example/default values
    concrete_path = path_template
    visited: frozenset = frozenset()
    for p in list(path_level_params) + list(op_params):
        p = _resolve_obj(p, doc, visited)
        if p.get("in") != "path":
            continue
        name = p.get("name", "")
        schema = _resolve_obj(p.get("schema", {}), doc, visited)
        val = p.get("example") or p.get("default")
        if val is None:
            val = (schema.get("example") or schema.get("default")) if schema else None
        # Only substitute if we have a real concrete value; otherwise keep {name} as fuzzable
        if val is not None and str(val) != "":
            concrete_path = concrete_path.replace("{" + name + "}", str(val))

    # Build path segments; unsubstituted {var} placeholders are fuzzable
    def _is_fuzzable_seg(seg: str) -> bool:
        return bool(re.fullmatch(r"\{[^}]+\}", seg)) or _is_fuzzable_path_segment(seg)

    path_segments = [
        PathSegment(index=i, value=part, fuzzable=_is_fuzzable_seg(part))
        for i, part in enumerate(p for p in concrete_path.split("/") if p not in ("", ".", ".."))
    ]

    full_url = (base_url + concrete_path) if base_url else concrete_path

    if op.get("summary") or op.get("description"):
        notes.insert(0, f"Operation: {op.get('summary') or op.get('description')}")

    return Manifest(
        method=method,
        url=full_url,
        base_url=base_url + concrete_path if base_url else concrete_path,
        path_segments=path_segments,
        query_params=query_params,
        headers=extra_headers,
        body_format=body_format,
        body_params=body_params,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# URL fetching
# ---------------------------------------------------------------------------


def _fetch_url(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read().decode("utf-8")
    except Exception as exc:
        raise ValueError(f"Failed to fetch URL '{url}': {exc}") from exc


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _error_exit(msg: str) -> None:
    print(json.dumps({"error": msg}), file=sys.stdout)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse an OpenAPI spec into a normalized fuzz manifest."
    )
    parser.add_argument("file", nargs="?", help="Local OpenAPI file (JSON or YAML)")
    parser.add_argument("--url", metavar="URL", help="Fetch OpenAPI spec from a URL")
    parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    parser.add_argument(
        "--entry", type=int, default=0, metavar="N",
        help="Operation index to parse (default: 0)",
    )
    parser.add_argument(
        "--list-entries", action="store_true",
        help="Print operation table and exit",
    )
    parser.add_argument(
        "--operation", metavar="OPERATION_ID",
        help="Select operation by operationId (overrides --entry)",
    )
    args = parser.parse_args()

    if args.url:
        try:
            text = _fetch_url(args.url)
        except ValueError as exc:
            _error_exit(str(exc))
            return
    elif args.stdin:
        text = sys.stdin.read()
    elif args.file:
        try:
            with open(args.file) as f:
                text = f.read()
        except OSError as exc:
            _error_exit(f"Cannot read file '{args.file}': {exc}")
            return
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.list_entries:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            try:
                doc = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                _error_exit(f"Failed to parse spec: {exc}")
                return
        _list_operations(doc)
        return

    try:
        manifest = parse_openapi(text, operation_id=args.operation, entry_index=args.entry)
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
