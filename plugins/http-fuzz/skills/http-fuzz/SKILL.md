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

### Step 0: Preflight — Verify Dependencies and Capture Working Directory

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

Store the result with `/http-fuzz-report/` appended as `WORK_DIR`. Use `$WORK_DIR/<filename>` as the absolute path for every
subsequent write — the Write tool requires absolute paths, and `./` is ambiguous. All paths
below that start with `$WORK_DIR` refer to this captured value.

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
  [--no-verify]
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

# Send probes
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --probe-encodings \
  [--timeout 10] \
  [--no-verify]
```

The script automatically constructs and sends the appropriate probes for the manifest's
`body_format`: XML with a DOCTYPE XXE entity injection, form-encoded, and JSON (when the
original is not already that format). Results stream as NDJSON with `probe_encoding` set.

For each result: compare `status_code` and `body_preview` against the baseline. Apply the
anomaly rules from `references/anomaly-detection.md`.

**Any 2xx for an alternative encoding is a finding** even before looking for deeper
vulnerabilities — unexpected content negotiation is worth documenting on its own. A response
body containing `root:x:0:0` or a file path is a confirmed XXE. See
`references/fuzz-strategies.md` (Encoding Variation section) for full signal guidance.

Include all encoding probe results in the final report under their own section.

### Step 5: Choose Aggression Level

Ask the user: **How aggressive should the fuzz be?**

| Level | Threads | Delay | Use when |
|---|---|---|---|
| **Gentle** | 1–5 | 3000ms | Rate-limited APIs, WAFs, shared/staging environments |
| **Moderate** | 10–20 | 500ms | Dedicated test environments, most common choice |
| **Aggressive** | 50+ | 0ms | Isolated test environments, high-throughput APIs |

Note: aggressive mode against rate-limited APIs produces connection failures that look like
anomalies. Reduce thread count if many `"error": "timeout"` results appear.

### Step 6: Run the Fuzzer

```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --threads <N> \
  --delay-ms <MS> \
  [--timeout 10] \
  [--no-verify] \
  [--param email]    # optional: limit to specific parameters
```

Use `--dry-run` first to preview the full request plan without sending:
```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --dry-run
```

The fuzzer streams NDJSON to stdout — one result per line:
```json
{"param": "email", "value": "a@b.c'--", "status_code": 500, "response_time_ms": 89,
 "content_length": 1203, "content_type": "text/html", "body_preview": "...SQL syntax...", "error": null}
```

Read each line as it arrives and classify it using the rules in Step 7.
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
  --param <param-name>
```
Only report a timing anomaly if it reproduces in isolation. Discard otherwise — it was
server-side queuing, not a payload-triggered delay.

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
