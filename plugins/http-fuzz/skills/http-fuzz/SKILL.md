---
name: http-fuzz
description: >
  Performs authorized HTTP endpoint fuzzing using semantic input generation. Accepts a raw HTTP
  request, curl command, or HAR file; extracts fuzz targets (query params, body params, path
  segments, headers); generates category-matched payloads using parameter names and types; and
  produces a markdown report of anomalous findings. For OpenAPI/Swagger specs, uses the
  openapi-to-manifest skill first. Triggers on: "fuzz this endpoint", "test this API for
  injection", "check how this request handles bad input", user provides a curl command or HAR
  file for security testing.
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
- A consistent baseline cannot be established (see Step 4) — fuzzing relies on detecting anomalies against a stable baseline
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

### Step 0: Capture the Working Directory

Before writing any file, run:

```bash
pwd
```

Store the result with `/http-fuzz/` appended as `WORK_DIR`. Use `$WORK_DIR/<filename>` as the absolute path for every
subsequent write — the Write tool requires absolute paths, and `./` is ambiguous. All paths
below that start with `$WORK_DIR` refer to this captured value.

### Step 1: Parse the Input Request

Save the input to a file, then run:

```bash
# Auto-detect format (raw HTTP, curl, or HAR)
uv run {baseDir}/scripts/parse_input.py --format auto request.txt > "$WORK_DIR/manifest.json"

# Or specify format explicitly
uv run {baseDir}/scripts/parse_input.py --format curl curl.txt > "$WORK_DIR/manifest.json"
uv run {baseDir}/scripts/parse_input.py --format har --list-entries export.har
uv run {baseDir}/scripts/parse_input.py --format har --entry 3 export.har > "$WORK_DIR/manifest.json"
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

Run 5 baseline requests with the original parameter values:

```bash
uv run {baseDir}/scripts/run_baseline.py \
  --manifest "$WORK_DIR/manifest.json" \
  --count 5 \
  [--timeout 10] \
  [--no-verify]
```

Read the summary JSON and evaluate consistency:

**Stop and warn the user if ANY of these are true:**
- `status_codes` has more than 1 distinct value (mixed responses)
- `p95_response_ms / median_response_ms > 3.0` (high timing variance)
- `content_length_variance_pct > 50` (high size variance)

**If the baseline is consistent**, confirm to the user:
> "Baseline established: 200 OK, median 145ms, p95 201ms. Consistent across 5 requests. Ready to fuzz."

If the user asks to proceed despite an inconsistent baseline, note this in the report and explain
that anomaly detection reliability will be reduced. See `references/anomaly-detection.md` for
guidance on this case.

### Step 4: Choose Aggression Level

Ask the user: **How aggressive should the fuzz be?**

| Level | Threads | Delay | Use when |
|---|---|---|---|
| **Gentle** | 1–5 | 3000ms | Rate-limited APIs, WAFs, shared/staging environments |
| **Moderate** | 10–20 | 500ms | Dedicated test environments, most common choice |
| **Aggressive** | 50+ | 0ms | Isolated test environments, high-throughput APIs |

Note: aggressive mode against rate-limited APIs produces connection failures that look like
anomalies. Reduce thread count if many `"error": "timeout"` results appear.

### Step 5: Run the Fuzzer

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

Read each line as it arrives and classify it using the rules in the next step.
For large runs (>500 requests), batch in groups of 50 to manage context.

### Step 6: Classify Anomalies

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

### Step 7: Write the Report

Use the Write tool to create `$WORK_DIR/http-fuzz-report.md` (absolute path). Write this
alongside the corpus files so the user can refer to both.

After writing the report, tell the user its location and summarize the key findings in 2–3
sentences.

---

## Reference Files

- `references/input-formats.md` — parsing guide for raw HTTP, curl, and HAR formats
- `references/fuzz-strategies.md` — semantic fuzz table: what values to generate per parameter type
- `references/anomaly-detection.md` — signal vs noise rules; when to stop; how to write explanations
- `references/report-template.md` — report structure and example output

## Related Skills

- `openapi-to-manifest` — converts an OpenAPI/Swagger spec into a fuzz manifest; invoke this
  skill first when the user provides a spec file or URL rather than a captured request. Verify
  the document is actually an OpenAPI or Swagger spec before invoking; if unclear, ask the user.
