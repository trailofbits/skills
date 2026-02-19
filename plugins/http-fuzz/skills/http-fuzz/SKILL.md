---
name: http-fuzz
description: >
  Performs smart, context-aware HTTP request fuzzing against a target endpoint. Accepts a raw
  HTTP request, curl command, or HAR file; extracts all fuzz targets (query params, body params,
  headers); generates semantically meaningful inputs per parameter using LLM reasoning (not blind
  mutation); saves a reusable corpus; and produces a markdown report of anomalous findings with
  explanations. Use this skill when conducting authorized API security testing, bug bounty research,
  pre-deployment security review, or any time you need to probe an HTTP endpoint for input
  handling bugs. Trigger when the user says "fuzz this endpoint", "test this API for injection",
  "check how this request handles bad input", or provides a curl command/HAR file for security
  testing.
allowed-tools:
  - Bash
  - Read
  - Write
---

# HTTP Fuzzing

This skill probes an HTTP endpoint by generating contextually meaningful fuzz inputs for each
parameter — using the names and types of parameters to create targeted test cases rather than
random noise. A Python script handles the actual HTTP requests; you handle the reasoning.

## When to Use

- Authorized penetration testing of an HTTP API or web application
- Bug bounty research on an in-scope target
- Pre-deployment security review of your own API
- Investigating how an endpoint handles malformed, boundary, or injection inputs
- Generating a reusable fuzz corpus for integration with other tools (ffuf, nuclei, etc.)

## When NOT to Use

- A consistent baseline cannot be established (see Step 4) - fuzzing relies on detecting anomalies against a stable baseline
- A non-HTTP target (use a different skill for TCP fuzzing, smart contract fuzzing, etc.)
- Testing that requires protocol-level mutation (use a network fuzzing tool instead)

## Rationalizations to Reject

- "It's just a staging/dev server" — staging servers often contain real data and credentials
- "I'll only send a few requests" — fuzzing requires enough volume to be meaningful; if rate is
  a concern, use gentle mode but still obtain authorization
- "The endpoint looks safe, skipping the baseline" — inconsistent baselines produce noise;
  always establish a baseline before fuzzing
- "I'll skip the auth headers in the corpus to be safe" — that's correct behavior, not a shortcut

## Prerequisites

- `uv` installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Network access to the target
- Explicit authorization to test the target (document it before starting)

---

## Workflow

### Step 1: Parse the Input Request

Detect the format (raw HTTP, curl, HAR) and extract a normalized parameter manifest.

Save the input to a file first, then run:

```bash
# Auto-detect format
uv run {baseDir}/scripts/parse_input.py --format auto request.txt > manifest.json

# Or specify format explicitly
uv run {baseDir}/scripts/parse_input.py --format curl curl.txt > manifest.json
uv run {baseDir}/scripts/parse_input.py --format har --list-entries export.har
uv run {baseDir}/scripts/parse_input.py --format har --entry 3 export.har > manifest.json
```

Read the manifest and present the extracted parameters as a table to the user:

| Parameter | Location | Type | Value (truncated) | Fuzz? |
|---|---|---|---|---|
| email | body (JSON) | string | user@example.com | Yes |
| role | body (JSON) | string | member | Yes |
| Authorization | header | string | Bearer eyJ... | **No** (auth token) |

Ask the user to confirm or remove any parameters before proceeding. This is important: fuzzing
CSRF tokens or session cookies produces noise, not findings.

See `references/input-formats.md` for format-specific details and known limitations.

### Step 2: Generate Corpus

For each fuzz target, generate a curated set of inputs using the semantic strategy table in
`references/fuzz-strategies.md`. Match the parameter name to a category, generate the
corresponding values, and write them to corpus files:

```
./corpus/<param-name>.txt   (one value per line, UTF-8, blank lines ignored)
```

**Use the Write tool** to create each corpus file. The fuzzer reads these files directly.

Key principles:
- Generate inputs that test what the parameter *means*, not random garbage
- When a parameter matches multiple categories (e.g. `user_id` matches both "Numeric ID" and
  general fuzz), include inputs from all matching categories
- For parameters with no category match, use the "Unmatched" fallback set from fuzz-strategies.md
- After writing the files, summarize how many values were generated per parameter

### Step 3: Choose Aggression Level

Ask the user: **How aggressive should the fuzz be?**

| Level | Threads | Delay | Use when |
|---|---|---|---|
| **Gentle** | 1–5 | 3000ms | Rate-limited APIs, WAFs, shared/staging environments |
| **Moderate** | 10–20 | 500ms | Dedicated test environments, most common choice |
| **Aggressive** | 50+ | 0ms | Isolated test environments, high-throughput APIs |

Warn: aggressive mode against rate-limited APIs produces connection failures that look like
anomalies — reduce thread count if you see many `"error": "timeout"` results.

### Step 4: Establish Baseline

Run 5 baseline requests with the original parameter values:

```bash
uv run {baseDir}/scripts/run_baseline.py \
  --manifest manifest.json \
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

### Step 5: Run the Fuzzer

```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest manifest.json \
  --corpus-dir ./corpus \
  --threads <N> \
  --delay-ms <MS> \
  [--timeout 10] \
  [--no-verify] \
  [--param email]    # optional: limit to specific parameters
```

Use `--dry-run` first to preview the full request plan without sending:
```bash
uv run {baseDir}/scripts/run_fuzz.py --manifest manifest.json --corpus-dir ./corpus --dry-run
```

The fuzzer streams NDJSON to stdout — one result per line. Each line looks like:
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
4. Response time > 10× baseline median → anomaly
5. Network error (`"error": "timeout"`) → log separately as connection failure, not anomaly

Accumulate anomalies with their reason. Ignore the noise cases listed in anomaly-detection.md.

### Step 7: Write the Report

Use the Write tool to create `./http-fuzz-report.md`:

```markdown
# HTTP Fuzz Report

**Target**: <METHOD> <URL>
**Date**: <date>
**Aggression**: <level> (<N> threads, <MS>ms delay)
**Parameters fuzzed**: <list> (<N> of <total>; <excluded> excluded)

## Summary

- Requests sent: <N>
- Anomalies found: <N>
- Connection failures: <N>
- Baseline: <status> OK, median <N>ms

## Anomalies

| # | Parameter | Value | Status | Time (ms) | Finding |
|---|-----------|-------|--------|-----------|---------|
| 1 | email | `a@b.c'--` | 500 | 89 | SQL syntax in response body |

### Anomaly 1: <Short Title>

**Parameter**: `email`
**Value**: `a@b.c'--`
**Response**: 500 Internal Server Error
**Body preview**: `...SQL syntax error near '--'...`

<One sentence explaining what the anomaly indicates.>

[... one section per anomaly ...]

## Corpus Files

Reusable corpus files were written to `./corpus/`:
- `./corpus/email.txt` (<N> values)
- `./corpus/role.txt` (<N> values)

## Raw Evidence Appendix

<details>
<summary>Baseline responses</summary>

[full baseline JSON]

</details>

<details>
<summary>Full anomalous responses</summary>

[full response bodies for each anomaly]

</details>
```

After writing the report, tell the user its location and summarize the key findings in 2–3
sentences.

---

## Reference Files

- `references/input-formats.md` — detailed parsing guide for raw HTTP, curl, and HAR formats
- `references/fuzz-strategies.md` — semantic fuzz table: what values to generate per parameter type
- `references/anomaly-detection.md` — signal vs noise rules; when to stop; how to write explanations
