---
name: http-fuzz
description: Fuzzes HTTP endpoints to find security vulnerabilities. Use when the user wants to security-test, penetration-test, or fuzz an HTTP API or web application endpoint. Accepts raw HTTP, curl, HAR, or PCAP input; generates semantic payloads per parameter; reports anomalies (SQLi, LFI, XXE, path traversal, error disclosure). Requires explicit authorization to test the target.
allowed-tools:
  - Bash
  - Read
  - Write
---

# HTTP Fuzzing

Probes an HTTP endpoint by generating contextually meaningful fuzz inputs for each parameter,
using parameter names and types to create targeted test cases rather than random noise.
A Python script handles HTTP requests; Claude handles the reasoning.

## When to Use

- Authorized penetration testing of an HTTP API or web application
- Bug bounty research on an in-scope target
- Pre-deployment security review of your own API
- Investigating how an endpoint handles malformed, boundary, or injection inputs
- Generating a reusable fuzz corpus for integration with other tools (ffuf, nuclei, etc.)

## When NOT to Use

- No explicit authorization to test the target
- A consistent baseline cannot be established (see Step 3) — fuzzing relies on detecting anomalies against a stable baseline
- Non-HTTP target — use a different skill for TCP fuzzing, smart contract fuzzing, etc.
- Testing that requires protocol-level mutation — use a network fuzzing tool instead
- User provides an OpenAPI/Swagger spec — use the `openapi-to-manifest` skill first, then return to Step 2 here

## Rationalizations to Reject

- "It's just a staging/dev server" — staging servers often contain real data and credentials
- "I'll only send a few requests" — fuzzing requires enough volume to be meaningful; obtain authorization regardless of volume
- "The endpoint looks safe, skipping the baseline" — inconsistent baselines produce noise; always establish a baseline before fuzzing
- "I'll skip the auth headers in the corpus to be safe" — that's correct behavior, not a shortcut
- "I'll add INSERT/UPDATE/DELETE payloads to test for SQL injection more thoroughly" — write-operation SQL in an automated fuzz run can cause irreversible data loss; read-only probes (`SELECT`, `OR 1=1`) are sufficient to confirm a SQL injection sink exists

## Prerequisites

- `uv` installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Network access to the target
- Explicit authorization to test the target — confirm this with the user before starting

---

## Workflow

### Step 0: Preflight — Verify Dependencies, Capture Working Directory, and Plan Operation Order

**Check that `uv` is installed** — all fuzzer scripts require it:

```bash
uv --version
```

If this fails, stop immediately and tell the user:
> "`uv` is required but not found. Install it with:
> `curl -LsSf https://astral.sh/uv/install.sh | sh`
> Then restart your shell and try again."

Do not proceed to any other step without a working `uv`. Python package dependencies
(`requests`, `dpkt`, `urllib3`) are declared inline in each script via PEP 723 and are
resolved automatically by `uv run` — no separate install step is needed for them.

**Capture the working directory** — before writing any file, run:

```bash
pwd
```

If the user specified a working directory, use that as `WORK_DIR`. Otherwise, store the result
with `/http-fuzz-report/` appended as `WORK_DIR`. Use `$WORK_DIR/<filename>` as the absolute
path for every subsequent write — the Write tool requires absolute paths, and `./` is
ambiguous. All paths below that start with `$WORK_DIR` refer to this captured value.

**Plan operation order before fuzzing multiple endpoints.** When the scope includes more than
one operation and the session is authenticated, classify each operation by its effect on the
session before starting any fuzz run:

| Class | Examples | When to fuzz |
|---|---|---|
| **Session-neutral** | GET pages, search, booking details, profile view | First — these are safe to run with any valid session |
| **Session-mutating** | Profile update, password change, role change | After session-neutral operations; re-verify session after each |
| **Session-terminating** | Logout (`/logout`, `/signout`, session destroy) | Last — a single hit destroys the session for all concurrent operations |
| **Session-creating** | Login, signup, OAuth callback | Last — test after all authenticated operations are complete; a successful auth-bypass payload may also create a new session that masks subsequent results |

**Why this matters:** The fuzzer sends many requests concurrently. If a logout endpoint is
fuzzed at the same time as an authenticated page, a successful (or even partially successful)
logout request will invalidate the session mid-run — every subsequent result returns the login
page regardless of payload, producing zero signal and no findings for those operations.

**Concrete rule:** When any logout or login endpoint is in scope alongside authenticated
endpoints, always complete all authenticated fuzz operations first, then fuzz login/logout
last — in separate runs with freshly obtained sessions. Security-sensitive flows (login, logout,
password change, role assignment) must still be thoroughly tested; the constraint is on *when*,
not *whether*.

### Step 1: Parse the Input Request

Save the input to a file, then run:

```bash
# Auto-detect format (raw HTTP, curl, HAR, or PCAP/PCAPNG)
uv run {baseDir}/scripts/parse_input.py --format auto request.txt > "$WORK_DIR/manifest.json"

# Or specify format explicitly
uv run {baseDir}/scripts/parse_input.py --format curl curl.txt > "$WORK_DIR/manifest.json"

# HAR: list entries first, then parse a specific one
uv run {baseDir}/scripts/parse_input.py --format har --list-entries export.har
uv run {baseDir}/scripts/parse_input.py --format har --entry 3 export.har > "$WORK_DIR/manifest.json"

# PCAP/PCAPNG: list captured requests first, then parse a specific one
uv run {baseDir}/scripts/parse_input.py --format pcap --list-entries capture.pcap
uv run {baseDir}/scripts/parse_input.py --format pcap --entry 0 capture.pcap > "$WORK_DIR/manifest.json"
```

Read the manifest and present the extracted parameters as a table:

| Parameter | Location | Type | Value (truncated) | Fuzz? |
|---|---|---|---|---|
| email | body (JSON) | string | user@example.com | Yes |
| role | body (JSON) | string | member | Yes |
| Authorization | header | string | Bearer eyJ... | **No** (auth token) |

Ask the user to confirm or remove parameters before proceeding. Generally, fuzzing CSRF tokens or session
cookies produces noise, not findings. 

**Important:** If multiple requests are present (e.g. HAR file), ensure the user selects the correct one for fuzzing. The manifest should only contain one request.

See `references/input-formats.md` for format-specific details and known limitations.

### Step 2: Generate Corpus

For each fuzz target, generate a curated set of inputs using the semantic strategy table in
`references/fuzz-strategies.md`. Match the parameter name to a category, generate the
corresponding values, and write them to corpus files using the absolute path from Step 0:

```
$WORK_DIR/corpus/<param-name>.txt   (one value per line, UTF-8, blank lines ignored)
```

Use the Write tool with the full absolute path (e.g. `/home/user/project/corpus/email.txt`).
Never use `./` or `/tmp/` — the corpus files should live alongside the user's project.

**Before generating anything**, ask the user which parameters to exclude.

**One parameter per response turn.** For each parameter:
1. Write the corpus file using the Write tool (full absolute path).
2. Output exactly one confirmation line: `✓ corpus/<name>.txt — N values`
3. Stop. Do not preview values, explain choices, or narrate next steps.

Additional rules:
- Cap at 50 values per parameter; prioritize distinct vulnerability classes over repetition
- When a parameter matches multiple categories, include values from each (still under 50)
- For unmatched parameter names, use the "Unmatched" fallback set from `references/fuzz-strategies.md`

### Step 3: Establish Baseline

Run 5 baseline requests with the original parameter values. Always use `--preview-length 0`
(full body, no truncation). Five full responses fit easily within Claude's context window,
and reading them in full lets you: confirm the session is active; locate where errors appear
in the body so you can set `--preview-find` or `--preview-offset` for the fuzz run; and
establish true content-length for anomaly comparison.

```bash
uv run {baseDir}/scripts/run_baseline.py \
  --manifest "$WORK_DIR/manifest.json" \
  --count 5 \
  --preview-length 0 \
  [--timeout 10] \
  [--no-verify] \
  > "$WORK_DIR/baseline.json"
```

**Always redirect to a file** — `uv run` does not reliably forward stdout through a shell pipe on all platforms. Read the file after the command completes:

```bash
cat "$WORK_DIR/baseline.json"
```

Read the summary JSON and evaluate consistency:

**Stop and warn the user if ANY of these are true:**
- `status_codes` has more than 1 distinct value (mixed responses)
- `p95_response_ms / median_response_ms > 3.0` (high timing variance)
- `content_length_variance_pct > 50` (high size variance)

**If the manifest includes auth credentials (Cookie, Authorization header), also verify the session is active:**
Inspect the baseline response bodies. If they show a login page, redirect to `/login`, or lack the authenticated UI elements you expect (e.g. navigation links only visible when logged in), the session has expired. Stop and ask the user to provide a fresh session token. Re-login, update the Cookie/Authorization header in the manifest, and re-run the baseline before proceeding. **A fuzz run against an expired session produces zero signal — every probe returns the same login page regardless of payload.**

**If the baseline is consistent**, confirm to the user:
> "Baseline established: 200 OK, median 145ms, p95 201ms. Consistent across 5 requests. Ready to fuzz."

If the user asks to proceed despite an inconsistent baseline, note this in the report and explain
that anomaly detection reliability will be reduced. See `references/anomaly-detection.md` for
guidance on this case.

### Step 4: Encoding Variation Probes

**This step runs on every fuzz session, no exceptions.** Do not skip it. Do not move on to
Step 5 until the probes have been sent and their responses evaluated.

Format-level variation reaches attack surfaces that parameter value fuzzing cannot — an
endpoint that silently accepts XML when it expects JSON may have external entity resolution
enabled; one that accepts form-encoded data when expecting JSON may expose nested objects
that flat fields can't represent. These vulnerability classes only appear when you change
the encoding, not the values.

Preview what probes will be sent, then run them:

```bash
# Preview (no requests sent)
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --probe-encodings \
  --dry-run

# Send probes (redirect to file — uv run stdout pipe is unreliable)
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --probe-encodings \
  [--timeout 10] \
  [--no-verify] \
  > "$WORK_DIR/encoding-probes.ndjson"
cat "$WORK_DIR/encoding-probes.ndjson"
```

The script automatically constructs and sends the appropriate probes for the manifest's
`body_format`: XML with a DOCTYPE XXE entity injection, form-encoded, and JSON (when the
original is not already that format). Results are written as NDJSON with `probe_encoding` set.

For each result: compare `status_code` and `body_preview` against the baseline. Apply the
anomaly rules from `references/anomaly-detection.md`.

**Any 2xx for an alternative encoding is a finding** even before looking for deeper
vulnerabilities — unexpected content negotiation is worth documenting on its own. A response
body containing `root:x:0:0` or a file path is a confirmed XXE. See
`references/fuzz-strategies.md` (Encoding Variation section) for full signal guidance.

Include all encoding probe results in the final report under their own section.

### Step 5: Choose Aggression Level

Ask the user how aggressive the fuzz should be, then select `--threads` and `--delay-ms`
values accordingly. There is **no `--aggression` flag** — set thread count and delay directly
in Step 6.

| Level | `--threads` | `--delay-ms` | Use when |
|---|---|---|---|
| **Gentle** | 1–5 | 3000 | Rate-limited APIs, WAFs, shared/staging environments |
| **Moderate** | 10–20 | 500 | Dedicated test environments, most common choice |
| **Aggressive** | 50+ | 0 | Isolated test environments, high-throughput APIs |

Note: high thread counts against rate-limited APIs produce connection failures that look like
anomalies. Reduce `--threads` if many `"error": "timeout"` results appear.

### Step 6: Run the Fuzzer

**If fuzzing multiple operations in an authenticated session, follow the order established in
Step 0:** session-neutral first, session-mutating next, session-terminating (logout) and
session-creating (login) last. Do not run logout or login operations concurrently with any
other authenticated operation. Obtain a fresh session immediately before fuzzing each
session-creating or session-terminating operation.

```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --threads <N> \
  --delay-ms <MS> \
  [--timeout 10] \
  [--no-verify] \
  [--param email] \   # optional: limit to specific parameters
  > "$WORK_DIR/fuzz-results.ndjson"
```

**Always redirect to a file** — `uv run` does not reliably forward stdout through a shell pipe on all platforms. Read the file after the command completes:

```bash
cat "$WORK_DIR/fuzz-results.ndjson"
```

Use `--dry-run` first to preview the full request plan without sending:
```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --dry-run
```

The fuzzer writes NDJSON to stdout — one result per line:
```json
{"param": "email", "value": "a@b.c'--", "status_code": 500, "response_time_ms": 89,
 "content_length": 1203, "content_type": "text/html", "body_preview": "...SQL syntax...", "error": null}
```

Read the results file and classify each line using the rules in Step 7.
For large runs (>500 requests), batch in groups of 50 to manage context.

#### Choosing preview settings

The default is `--preview-length 0` (full body, no truncation). Only set a positive value
when result volume would overflow Claude's context window. **Always err towards larger
previews — a missed signal costs far more than extra tokens.**

Use the baseline bodies from Step 3 to decide:
- **Known error keyword** (e.g. `SQLSTATE`, `Traceback`): use `--preview-find` — it centres
  the window on the signal regardless of where it appears in the body. This is the preferred
  option when truncation is needed.
- **Large fixed header before dynamic content**: use `--preview-offset` to skip it.
- **Large run (>200 results) with big response bodies**: set `--preview-length 2000–5000`.

See `references/preview-settings.md` for the full decision procedure and context budget
guidance.

### Step 7: Classify Anomalies

**Before classifying, verify the session did not expire mid-run.** Check a sample of results across the run (first 10%, last 10%): if the majority share an identical small content_length that matches a login page size, or if `body_preview` shows navigation links like "Login / Sign Up" rather than authenticated UI, the session expired. In this case:
1. Note the approximate point where content_length collapsed to the login-page size.
2. Discard all results from that point onward — they are unauthenticated and produce no signal.
3. Warn the user that a fresh session is needed and the affected operations must be re-run.

Apply the rules from `references/anomaly-detection.md` to each result. That file covers:
signal vs noise rules, timing anomaly verification (mandatory isolation re-run when
threads > 1), and how to write anomaly explanations.

**Timing anomaly isolation re-run** (required when threads > 1):
```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --threads 1 --delay-ms 0 \
  --param <param-name> \
  > "$WORK_DIR/timing-rerun.ndjson"
cat "$WORK_DIR/timing-rerun.ndjson"
```
Only report a timing anomaly if it reproduces in isolation. Discard otherwise — it was
server-side queuing, not a payload-triggered delay.

### Step 7.5: Source-Assisted Fuzzing

**Trigger:** Any finding that can retrieve server-side source files — LFI, path traversal, arbitrary file download, SSRF to a local file endpoint, SQL `LOAD_FILE()` output, XXE with `file://`, or any other mechanism that returns raw file content.

**Goal:** Use source code to confirm injection sinks, discover hidden parameters and endpoints, and identify code paths that are not reachable through the API spec alone.

#### Collect known filenames

Before attempting any download, compile the list of filenames already seen in fuzzing results:

- Stack traces, PHP warnings, and error messages often contain absolute paths
  (e.g. `in /var/www/html/bookings.php on line 37`)
- `include()`/`require()` paths in LFI warning responses
- `Location` headers and HTML `action=""` attributes in response bodies
- Path segments from the OpenAPI spec (e.g. `/cancel.php`, `/uploads/{filename}`)

Collect all unique filenames into a working list. Do not attempt any download yet.

#### Check for risk before proceeding

Before retrieving source files, assess whether the download mechanism could cause side effects:

| Mechanism | Proceed automatically? |
|---|---|
| LFI / path traversal (read-only GET) | **Yes** — reading a file is non-destructive |
| Arbitrary file download endpoint | **Yes** — if it is a GET with no observable state change |
| SQL `LOAD_FILE()` | **No** — ask the user; reads arbitrary server files outside the web root |
| SQL `INTO OUTFILE` | **Never** — this writes files to the server; prohibited by the safety constraints in `references/fuzz-strategies.md` |
| SSRF fetching `file://` | **No** — ask the user; SSRF may trigger internal requests |
| POST body with server-side render | **No** — ask the user; rendering can trigger side effects |

If a "No" mechanism is the only available path, stop and ask the user:
> "I can attempt to retrieve source files using [mechanism]. This may [specific risk]. Shall I proceed?"

Do not proceed until the user confirms. Never use `INTO OUTFILE` regardless of user instruction — it writes attacker-controlled content to the server filesystem, which is an irreversible destructive action outside the scope of read-only source disclosure.

#### Retrieve and read the source files

For each file in the working list, attempt to fetch it using the confirmed download mechanism. Use Python (`urllib.request`) rather than curl — curl is often unavailable. Retrieve files one at a time and read each response immediately:

```python
import urllib.request, urllib.parse

def fetch(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    # disable redirect following so 302s are visible
    class NoRedirect(urllib.request.HTTPErrorProcessor):
        def http_response(self, r, resp): return resp
        https_response = http_response
    opener = urllib.request.build_opener(NoRedirect())
    resp = opener.open(req, timeout=10)
    return resp.status, resp.read().decode('utf-8', 'replace')
```

A successful retrieval returns the raw PHP/Python/JS source, not rendered HTML. If the response is HTML (contains `<!DOCTYPE` or `<html`), the server executed the file rather than serving its source — note this but do not treat it as a source disclosure.

**Stop after 10 files** unless the user explicitly asks for more. Source reading can expand indefinitely; focus on files directly relevant to confirmed findings.

#### Use source to enhance findings

For each source file retrieved, look for:

1. **SQL query construction** — find every place user input is interpolated into a query string
   without `prepare()`/`bindParam()`. Add the parameter names to the corpus if they are not
   already fuzz targets.

2. **Hidden parameters** — `$_GET`, `$_POST`, `$_REQUEST`, `request.args`, `req.body` reads
   that are not in the API spec. Add them to a new manifest and fuzz them.

3. **Secondary sinks** — input that is passed to `include()`, `file_get_contents()`, `exec()`,
   `system()`, `eval()`, `unserialize()`, `pickle.loads()`, or similar. These are high-priority
   follow-up fuzz targets.

4. **Authentication and authorization logic** — look for conditions that gate access (e.g.
   `if ($role === 'admin')`). Check whether the condition can be bypassed using values already
   in the corpus.

5. **Cryptographic weaknesses** — `md5()`, `sha1()`, hardcoded secrets, weak token generation.
   Note these in the report even if they are not directly fuzzable.

6. **File paths and include targets** — new filenames to add to the working list for further
   retrieval.

#### Update the report and re-fuzz if warranted

After reading source, do two things before moving to Step 8:

1. **Add a "Source-Assisted Analysis" section** to the findings — for each file retrieved,
   note the filename, how it was obtained, and what it revealed.

2. **Re-fuzz any newly discovered parameters or endpoints** — go back to Step 2 and generate
   corpus files for them, then run a targeted fuzz (use `--param <name>` to limit scope). Report
   the results in the same report under the relevant finding or as a new finding.

**All follow-up fuzzing and any manual exploitation performed in this step must comply with
the safety constraints in `references/fuzz-strategies.md`** — no write-operation SQL, no
destructive deserialization payloads, no command injection, no time-delay SQL. Source code
may reveal tempting new attack surfaces (e.g. an `unserialize()` call or a raw `exec()`); the
same rules apply regardless of how the sink was discovered.

### Step 8: Write the Report

Use the Write tool to create `$WORK_DIR/http-fuzz-report.md` (absolute path). Write this
alongside the corpus files so the user can refer to both.

After writing the report, tell the user its location and summarize the key findings in 2–3
sentences.

---

## Reference Files

- `references/input-formats.md` — parsing guide for raw HTTP, curl, HAR, and PCAP/PCAPNG formats
- `references/fuzz-strategies.md` — semantic fuzz table: what values to generate per parameter type
- `references/anomaly-detection.md` — signal vs noise rules; when to stop; how to write explanations
- `references/preview-settings.md` — full decision procedure for --preview-length/offset/find and context budget guidance
- `references/report-template.md` — report structure and example output

## Related Skills

- `openapi-to-manifest` — converts an OpenAPI/Swagger spec into a fuzz manifest; invoke this
  skill first when the user provides a spec file or URL rather than a captured request. Verify
  the document is actually an OpenAPI or Swagger spec before invoking; if unclear, ask the user.
