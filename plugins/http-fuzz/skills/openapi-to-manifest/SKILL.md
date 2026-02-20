---
name: openapi-to-manifest
description: >
  Converts an OpenAPI description file (Swagger 2.0, OpenAPI 3.0, or 3.1) into a normalized
  fuzz manifest for use with the http-fuzz skill. Accepts a local file path or a remote URL.
  Extracts all operations as fuzz targets: path params, query params, request body fields, and
  headers. Triggers on: "fuzz this API spec", "test this OpenAPI file", "parse this swagger",
  user provides a .yaml or .json spec file or a Swagger/OpenAPI URL for security testing.
allowed-tools:
  - Bash
  - Read
  - Write
---

# OpenAPI to Fuzz Manifest

Converts an OpenAPI description file into a normalized fuzz manifest so the http-fuzz workflow
can proceed directly from API documentation — no need to manually craft curl commands or HAR files.

## When to Use

- User provides an OpenAPI/Swagger spec file (local path or URL)
- User pastes OpenAPI YAML or JSON content
- User wants to fuzz one or more endpoints from an API spec

## When NOT to Use

- User has a live captured request (curl, raw HTTP, HAR) — use http-fuzz directly instead
- The document has no `paths` key (metadata-only, not a usable spec)
- The file is not an OpenAPI or Swagger spec — verify before proceeding; if unclear, ask the user
- Non-HTTP target

## Rationalizations to Reject

- "The spec looks incomplete, I'll just pick the first endpoint" — always show the operation list
  and let the user choose; picking silently hides options
- "The placeholder values look fine for fuzzing" — `{id}` in a URL will produce 404s on every
  request; always resolve placeholders before handing off to the fuzzer

---

## Workflow

### Step 1: List Available Operations

Show the user what operations are in the spec:

```bash
# From a local file
uv run {baseDir}/scripts/parse_openapi.py --list-entries api.yaml

# From a remote URL
uv run {baseDir}/scripts/parse_openapi.py --url https://example.com/openapi.json --list-entries
```

Present the table and ask which operation to fuzz. If the spec has only one operation, proceed
directly without asking.

### Step 2: Parse the Selected Operation

```bash
# By index
uv run {baseDir}/scripts/parse_openapi.py --entry 3 api.yaml > manifest.json

# By operationId (more stable than index for large specs)
uv run {baseDir}/scripts/parse_openapi.py --operation createUser api.yaml > manifest.json

# From URL
uv run {baseDir}/scripts/parse_openapi.py --url https://example.com/openapi.json --operation getUser > manifest.json
```

Read `manifest.json` and present the extracted parameters as a table:

| Parameter | Location | Type | Value | Fuzz? |
|---|---|---|---|---|
| id | path | string | `{id}` | **Yes** (path variable) |
| verbose | query | boolean | false | Yes |
| name | body (JSON) | string | "" | Yes |

Show any manifest notes (e.g. unresolved `$ref`, unsupported content types) to the user.

**Before proceeding**: check for `{placeholder}` values in the URL or parameter list. These mean
the spec had no example or default for that parameter. Ask the user to supply real values —
fuzzing with a literal `{id}` in the URL will produce 404s on every request and yield no signal.

### Step 3: Hand Off to http-fuzz

Once all placeholders are resolved and the user has confirmed the parameter list, continue with
the http-fuzz workflow starting from **Step 2 (Generate Corpus)**. The manifest format is
identical — no conversion needed.

See `references/openapi-notes.md` for known limitations and edge cases.

---

## Reference Files

- `references/openapi-notes.md` — supported versions, $ref handling, OData paths, synthetic values, operation ordering
