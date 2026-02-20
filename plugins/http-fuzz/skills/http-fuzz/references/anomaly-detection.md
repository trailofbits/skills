# Anomaly Detection: Signal vs Noise

The goal is to flag responses that reveal something meaningful — a security issue, a crash, an
unintended code path — while ignoring the normal variation that any API produces. Getting this
balance right is what separates a useful fuzz run from a wall of false positives.

---

## Always Report (Signal)

These are strong indicators of a real finding:

**Status code change from baseline**
The server handled the original request with status X. A fuzz value caused status Y. Even "benign"
status changes (200 → 400) are worth noting — a well-designed API returns 400 for invalid input,
so a 400 may confirm the input reaches validation, but a 500 confirms it reached a crash.
- Exception: if the baseline itself included mixed status codes, only report changes that are not
  in the baseline distribution.

**Error internals visible in the response body**
These strings in the response body (case-insensitive) indicate the server leaked internal state:
- `stack trace`, `stacktrace`, `stack_trace`
- `exception`, `unhandled exception`, `NullPointerException`, `RuntimeError`
- `syntax error`, `parse error`
- `SQL`, `mysql_`, `ORA-`, `pg_`, `sqlite`, `SQLSTATE`, `syntax error near`
- `at line`, `undefined method`, `undefined variable`, `uninitialized constant`
- `Internal Server Error` (when paired with a body that has details, not just the HTTP status)
- `Warning:`, `Notice:`, `Fatal error:` (PHP error prefixes)
- `Traceback (most recent call last)` (Python tracebacks)
- `jsonpickle`, `cannot restore`, `py/object` (Python unsafe deserialization)
- `unserialize(): Error`, `Class '` (PHP unsafe deserialization)
- `Could not load type`, `JsonSerializationException`, `was not resolved` (ASP.NET Json.NET `TypeNameHandling`)

**Content-type change**
The server sent JSON in the baseline but HTML in the fuzz response — or vice versa. This often
means the fuzz value triggered a different code path (an error page, a redirect, a raw exception).

**Response time anomaly**
A response time more than 10× the baseline median may indicate:
- ReDoS (regex denial of service) — a crafted string causes catastrophic backtracking
- Expensive database query triggered by a particular value
- Sleep injection (`sleep(5)`, `WAITFOR DELAY`) landed in a SQL query
Flag it. Note the timing value in the report.

**Structural JSON schema change**
If the baseline returned `{"id": 1, "status": "ok"}` and the fuzz response returned
`{"error": "...", "debug": {...}}`, that's a structural change. Parse both as JSON and compare
top-level key sets. If the key sets differ and the status code changed, report it.

---

## Ignore (Noise)

These changes are expected and should not be reported:

**Dynamic fields in the response body**
These fields rotate by design — comparing them against baseline will always show a "change":
- `created_at`, `updated_at`, `timestamp`, `date`, `time`, `expires_at`, `modified_at`
- `session_id`, `session`, `sid`, `nonce`, `csrf_token`, `_token`, `request_id`, `trace_id`
- `X-Request-Id`, `X-Trace-Id` headers in the response

When evaluating JSON bodies, strip these keys before comparing structure.

**Normal response time jitter**
Response time variation within 3× the baseline median is network/server jitter. Only flag when
the ratio exceeds 10×.

**Minor content-length variation with same status code**
A response that's 5% larger or smaller than the baseline with the same status code is not
interesting. Only flag length changes when they are also accompanied by a status code or
content-type change. The threshold for "significant" length change alone (same status) is >5×
or <1/5 of baseline median length.

**Expected validation errors**
A 400 or 422 response with a body like `{"error": "invalid email format"}` is the correct
behavior — the server validated the input. Only flag these if:
1. The baseline never returned a 400/422 (meaning the endpoint doesn't normally validate)
2. The 400/422 body contains internal state (stack traces, SQL errors — see Signal above)

**Connection failures when fuzzing aggressively**
With high thread counts and short delays, some requests will fail with timeouts or connection
resets. These indicate rate limiting, not vulnerabilities. Log them separately as "connection
failures" in the report summary, don't classify them as anomalies.

**Concurrency queuing noise (timing false positives)**
When threads > 1 and the server has limited concurrency (PHP built-in dev server, simple Node
`http.createServer`, SQLite-backed apps with write locks), multiple in-flight requests queue
behind each other. The measured `response_time_ms` includes time spent waiting in the server's
accept queue, not just processing time. A 1ms computation can appear as 1000ms+ if 9 other
requests are ahead of it.

**Do not report a timing anomaly found during a multi-threaded run without first verifying it
in isolation.** See the "Timing Anomaly Verification" guidance in the Ambiguous Cases section.

---

## Ambiguous Cases (Use Judgment)

**Timing anomaly verification (mandatory for multi-threaded runs)**
Any `response_time_ms > 10× baseline median` result from a run with `--threads > 1` must be
re-verified in isolation before it can be reported as an anomaly. Re-run the specific parameter
with a single thread and no delay:

```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest manifest.json \
  --corpus-dir ./corpus \
  --threads 1 \
  --delay-ms 0 \
  --param <param-name>
```

Filter the output to the specific value that triggered the timing hit. If the isolation run
shows normal timing (within 3× baseline), discard the original result — it was concurrency
queuing noise, not a server-side anomaly. Only report timing anomalies that reproduce in
isolation.

Exception: if the entire isolation run shows elevated timing across all values for that parameter,
the server may have entered a degraded state. Re-run the baseline to confirm.

**404 Not Found**
Report if the baseline never returned 404. A parameter value that causes a 404 when the baseline
always returned 200 may indicate path traversal or resource enumeration succeeded/failed in an
unexpected direction.

**301/302 Redirect**
Report if the baseline never redirected. Pay attention to the `Location` header — a redirect to
an external domain is more interesting than a redirect to `/login`.

**Empty response body**
Report if the baseline always returned a body. An empty 200 response to a fuzz input may indicate
the server hit a code path that silently short-circuits.

**403 Forbidden on a role/permission field**
A 403 response to `role=admin` is expected behavior (the server correctly rejected privilege
escalation). Still worth noting in the report — it confirms the field is security-relevant and
the server does enforce access control. Mark it as "access control enforced (expected)" rather
than an anomaly requiring remediation.

---

## Explaining Anomalies

For each anomaly in the report, write one sentence explaining what you observe:

- **Be specific about the mechanism**: "SQL syntax error" is better than "server error"
- **Note what it suggests, not what it proves**: "indicates the input may reach a SQL query" not
  "confirms SQL injection vulnerability"
- **Reference both the input and the observable effect**: "The value `../../../etc/passwd` in
  the `path` field returned a 200 with body content that differed structurally from baseline,
  suggesting the path is being passed to a file-reading function."

One sentence per anomaly. Save longer analysis for notes or a separate security report.

---

## When Baseline Is Inherently Inconsistent

Some APIs rotate response structure by design (A/B tests, feature flags, geolocation). If you
cannot establish a stable baseline (mixed status codes, high timing variance, inconsistent response
schema), stop and explain the situation to the user.

Options to offer:
1. **Proceed with reduced confidence**: Flag any status code that was not in the baseline
   distribution, but accept that noise will be higher.
2. **Target a more stable endpoint**: Ask the user to identify a specific endpoint that returns
   consistent responses.
3. **Manual review**: Skip automated anomaly detection and provide the full response corpus for
   manual inspection.

Do not silently continue with a bad baseline — that produces useless results and wastes the
user's time.
