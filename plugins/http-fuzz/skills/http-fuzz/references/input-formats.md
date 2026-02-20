# Input Format Reference

`parse_input.py` accepts three formats. Pass `--format auto` (the default) to auto-detect,
or specify `--format raw-http`, `--format curl`, or `--format har` explicitly.

**OpenAPI/Swagger specs** are handled by a separate script (`parse_openapi.py`) invoked via
the `openapi-to-manifest` skill — see that skill for usage details.

---

## Raw HTTP Text

The raw HTTP request format used in tools like Burp Suite, Wireshark exports, and RFC 7230.

**Required fields**: request line (method + path + HTTP version), `Host` header.
**Optional**: any headers, body content.

**Example input** (`request.txt`):
```
POST /api/v1/users HTTP/1.1
Host: example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc

{"email": "user@example.com", "role": "member", "age": 25}
```

**Parse command**:
```bash
uv run {baseDir}/scripts/parse_input.py --format raw-http request.txt > manifest.json
```

**Notes**:
- The `Authorization` header is automatically marked `fuzzable: false`. Claude can override this.
- The URL is reconstructed as `https://<Host><path>` unless the path already contains a full URL.
- Both `\r\n` and `\n` line endings are accepted.
- Body is everything after the first blank line.

---

## curl Command

Paste a `curl` command directly. Multi-line commands with `\` continuation are supported.

**Supported flags**:

| Flag | Meaning |
|------|---------|
| `-X`, `--request METHOD` | HTTP method |
| `-H`, `--header 'Name: Value'` | Request header |
| `-d`, `--data`, `--data-raw` | Request body (string) |
| `--json` | Request body (sets Content-Type: application/json) |
| `-b`, `--cookie` | Cookie header value |
| `-u`, `--user user:pass` | Basic auth (encoded as Authorization header) |

**Example input** (`curl.txt`):
```
curl -X POST https://example.com/api/v1/users \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "role": "member", "age": 25}'
```

**Parse command**:
```bash
uv run {baseDir}/scripts/parse_input.py --format curl curl.txt > manifest.json
# or from stdin:
pbpaste | uv run {baseDir}/scripts/parse_input.py --format curl --stdin > manifest.json
```

**Notes**:
- Flags not listed above (e.g., `--compressed`, `-k`, `-v`) are silently ignored — they don't
  affect the request structure.
- Quote handling: single and double quotes around flag values are stripped.
- The curl command is parsed without invoking a shell, so shell variables (`$VAR`) are not expanded.

---

## HAR File

HAR (HTTP Archive) is a JSON format that browsers use to export recorded network traffic.

**How to export from Chrome**:
1. Open DevTools → Network tab
2. Reproduce the request you want to fuzz
3. Right-click the request → "Copy" → "Copy as HAR" (copies all entries to clipboard)
4. Paste into a file: `pbpaste > export.har`

Or to export all traffic: Right-click anywhere in the request list → "Save all as HAR with content"

**How to export from Firefox**:
1. Open DevTools → Network tab
2. Right-click → "Save all as HAR"

**Single-entry HAR files**: if you right-click a single request and "Copy as cURL", you can use
`--format curl`. For HAR, the format contains multiple entries.

**Parse a specific entry**:
```bash
# List all entries in the file
uv run {baseDir}/scripts/parse_input.py --format har --list-entries export.har

# Parse entry at index 3
uv run {baseDir}/scripts/parse_input.py --format har --entry 3 export.har > manifest.json
```

**Example `--list-entries` output**:
```
Index  Method  URL                                               Status
----------------------------------------------------------------------
0      GET     https://example.com/                             200
1      POST    https://example.com/api/v1/login                 200
2      GET     https://example.com/api/v1/users?page=1&limit=10 200
3      POST    https://example.com/api/v1/users                 201
```

**Notes**:
- HAR files can be very large (browser exports everything including images, fonts, analytics).
  Use `--list-entries` to identify the target request before parsing.
- `postData.text` is used for the request body. If absent but `postData.params` is present
  (form submissions), the params are encoded as a form body.
- HAR headers often include browser-added headers (`sec-ch-ua`, `sec-fetch-*`). These are included
  in the manifest but not marked sensitive — they're safe to fuzz.

---

## Parsed Manifest Format

All formats — including OpenAPI via `parse_openapi.py` — produce the same normalized manifest JSON:

```json
{
  "method": "POST",
  "url": "https://example.com/api/v1/users",
  "base_url": "https://example.com/api/v1/users",
  "path_segments": [
    {"index": 0, "value": "api", "fuzzable": false},
    {"index": 1, "value": "v1", "fuzzable": false},
    {"index": 2, "value": "users", "fuzzable": false}
  ],
  "query_params": [],
  "headers": [
    {"name": "Authorization", "value": "Bearer eyJ...", "fuzzable": false,
     "reason": "auth/session material — skip fuzzing to avoid lockout"},
    {"name": "Content-Type", "value": "application/json", "fuzzable": true, "reason": ""}
  ],
  "body_format": "json",
  "body_params": [
    {"name": "email", "value": "user@example.com", "type": "string", "fuzzable": true, "reason": ""},
    {"name": "role", "value": "member", "type": "string", "fuzzable": true, "reason": ""},
    {"name": "age", "value": 25, "type": "integer", "fuzzable": true, "reason": ""}
  ],
  "notes": []
}
```

**`fuzzable` flag**: Claude presents this table and users can exclude specific parameters before
corpus generation begins. The fuzzer (`run_fuzz.py`) only reads corpus files for parameters in
the manifest — if you don't generate a corpus file for a parameter, it won't be fuzzed.

---

## Known Limitations

**Binary/multipart bodies**: `multipart/form-data` requests with file upload parts are detected
but the binary parts are not fuzzable. The manifest will include a note, and only text fields
are extracted. If you need to fuzz a file upload endpoint, manually edit the request to use a
JSON or form body before parsing.

**Chunked transfer encoding**: Chunked bodies in raw HTTP are not reassembled. If the body appears
malformed, convert to a normal Content-Length body before using `--format raw-http`.

**Compressed responses**: The scripts use `requests` with default decompression. If the response
body appears as binary/garbled text, the server may not be respecting the `Accept-Encoding` header.
Add `-H "Accept-Encoding: identity"` to the original curl command to disable compression.
