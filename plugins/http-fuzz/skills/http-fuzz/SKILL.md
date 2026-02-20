---
name: http-fuzz
description: Performs HTTP endpoint fuzzing using semantic input generation. Accepts recorded HTTP requests in many formats, extracts fuzz targets, generates tailored payloads using parameter names and types, and produces a report of anomalous findings. 
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

**One parameter per turn — hard turn boundary.** For each parameter:
1. Silently decide which values to include (no narration, no explanation of reasoning).
2. Call the Write tool with the complete file content.
3. Output exactly one line: `✓ corpus/<name>.txt — N values` and nothing else.
4. End your response there. The next parameter starts in the next turn.

Do not mention what category the parameter matched. Do not preview the values. Do not
say "Next I will…". Any text beyond the single confirmation line is a token budget violation
that will cause the overall run to fail.

Additional principles:
- Ask the user which parameters to exclude before generating anything
- Cap at 50 values per parameter; prioritize coverage of distinct vulnerability classes over
  exhaustive enumeration within one class
- When a parameter matches multiple categories, include inputs from each but still stay under 50
- For no-category-match parameters, use the "Unmatched" fallback set from fuzz-strategies.md

### Step 3: Establish Baseline

Run 5 baseline requests with the original parameter values. The baseline script defaults to
`--preview-length 0` (full body, no truncation). **Do not override this default.** Reading
the full baseline body is the only way to:

- Confirm the session is active (look for authenticated UI elements, not a login page)
- Locate where errors appear in the response (character offset, HTML context) so you can
  set `--preview-find` or `--preview-offset` for the fuzz run
- Establish the true content-length and structure for anomaly comparison

Five full responses fit well within Claude's 200 K-token context window. Token cost here is
negligible compared to the risk of missing a signal that only appears deep in the body.

```bash
uv run {baseDir}/scripts/run_baseline.py \
  --manifest "$WORK_DIR/manifest.json" \
  --count 5 \
  [--timeout 10] \
  [--no-verify]
# --preview-length defaults to 0 (full body) — do not change for baseline
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

Truncation exists solely to keep fuzz result data within Claude's context window. A typical
fuzz run of ~200 requests × 1 000 chars each ≈ 200 K chars ≈ 50 K tokens, which fits
within the standard 200 K-token limit alongside the skill prompt and corpus. Larger runs or
larger responses require more care. **Always err towards larger previews and targeted
capture over aggressive truncation — a missed signal costs far more than extra tokens.**

Use the baseline bodies (captured in full in Step 3) to decide how to configure preview for
the fuzz run.

| Option | Default | Purpose |
|--------|---------|---------|
| `--preview-length N` | 1000 | Characters to capture per response |
| `--preview-offset N` | 0 | Skip the first N characters before capturing |
| `--preview-find STRING` | (off) | Fuzzy: centre the window on the first occurrence of STRING |

**Decision procedure — apply in order, stop when one matches:**

1. **You know what error string to look for** (identified from baseline or prior runs):
   Use `--preview-find` with that string. This is the preferred option — it guarantees the
   relevant signal is centred in the preview regardless of where it appears in the body.
   ```bash
   --preview-find "SQLSTATE" --preview-length 600
   --preview-find "Traceback" --preview-length 800
   --preview-find "Warning:" --preview-length 600
   ```

2. **Errors appear after a large fixed header** (identified from baseline offset):
   Use `--preview-offset` to skip boilerplate HTML, then capture from the dynamic region.
   ```bash
   --preview-offset 800 --preview-length 1200   # skip <head> + nav, capture <body> content
   ```

3. **API responses are short and structured (JSON/XML)** or errors appear at the start:
   The default `--preview-length 1000` is sufficient. No additional flags needed.

4. **Responses are large and you cannot predict error location**:
   Increase `--preview-length` to 3000–5000. At 200 requests this is still ~60 K tokens —
   acceptable. Beyond 500 requests, prefer option 1 or 2 to avoid context pressure.

5. **Small run (≤50 requests) or you want to do offline analysis**:
   Use `--preview-length 0` (no truncation). Full bodies for 50 responses ≈ 50–500 K tokens
   depending on response size — verify your estimates before using this at scale.

**Context budget guidance:**
Claude's standard context window is 200 K tokens. With the skill prompt (~5 K tokens),
corpus files, and NDJSON results, a rough budget for fuzz result data is ~100 K tokens.
At 1 000 chars/response ≈ 250 tokens, that accommodates ~400 responses comfortably.
Increase `--preview-length` when you have few results; use `--preview-find` when you have
many. Do not silently drop `--preview-find` to save tokens if it was chosen because a known
error signal is buried deep in the body — that tradeoff always loses.

**Example — hunt for SQL errors in a PHP app:**
```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --threads 5 --delay-ms 500 \
  --preview-find "SQLSTATE" \
  --preview-length 600
```

`SQLSTATE[HY000]: General error: unrecognized token` will be centred in the preview even if
it appears at character 700 of a 2 000-character page.

### Step 7: Classify Anomalies

**Before classifying, verify the session did not expire mid-run.** Check a sample of results across the run (first 10%, last 10%): if the majority share an identical small content_length that matches a login page size, or if `body_preview` shows navigation links like "Login / Sign Up" rather than authenticated UI, the session expired. In this case:
1. Note the approximate point where content_length collapsed to the login-page size.
2. Discard all results from that point onward — they are unauthenticated and produce no signal.
3. Warn the user that a fresh session is needed and the affected operations must be re-run.

Apply the rules from `references/anomaly-detection.md` to each result.

Compare against the baseline summary values:
- Baseline status code: `summary.status_codes` (most common value)
- Baseline timing: `summary.median_response_ms`
- Baseline content type: from the baseline responses

For each NDJSON result, check:
1. Status code ≠ baseline most-common → anomaly
2. Body contains error signal keywords → anomaly
3. Content-type changed → anomaly
4. Response time > 10× baseline median → **candidate** (see verification step below)
5. Network error (`"error": "timeout"`) → log separately as connection failure, not anomaly

Accumulate non-timing anomalies directly. Timing candidates require an extra step.

**Timing anomaly verification (required when threads > 1):**
Before reporting any timing candidate, re-run that parameter in isolation:

```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --threads 1 \
  --delay-ms 0 \
  --param <param-name>
```

Only promote a timing candidate to a confirmed anomaly if the isolation run also exceeds 10×
the baseline median for that specific value. If the isolation run shows normal timing, discard
it — it was server-side queuing from concurrent requests, not a payload-triggered delay.

See `references/anomaly-detection.md` for full details on concurrency queuing noise and the
other noise cases to ignore.

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
- `references/report-template.md` — report structure and example output

## Related Skills

- `openapi-to-manifest` — converts an OpenAPI/Swagger spec into a fuzz manifest; invoke this
  skill first when the user provides a spec file or URL rather than a captured request. Verify
  the document is actually an OpenAPI or Swagger spec before invoking; if unclear, ask the user.
