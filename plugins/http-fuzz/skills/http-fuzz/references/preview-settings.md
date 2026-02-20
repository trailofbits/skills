# Preview Settings: Choosing --preview-length, --preview-offset, --preview-find

Both `run_fuzz.py` and `run_baseline.py` expose identical preview options:

| Option | Default | Purpose |
|--------|---------|---------|
| `--preview-length N` | **0** (full body) | Characters to capture in `body_preview`; 0 = no truncation |
| `--preview-offset N` | 0 | Skip first N characters before capturing (no effect when length=0) |
| `--preview-find STRING` | (off) | Fuzzy mode: centre the window on the first occurrence of STRING (no effect when length=0) |

---

## Why Truncation Exists

Truncation exists only to keep fuzz result data within Claude's context window. The goal is
never to reduce tokens for their own sake — it is to avoid overflowing context on large runs.

**Rule of thumb:** always err towards larger previews and targeted capture. A missed signal
costs far more than extra tokens.

Use the baseline bodies (captured in full at `--preview-length 0`) to inform your settings
before running the full fuzz.

---

## Decision Procedure

Apply in order; stop when one case matches:

### 1. You know what error string to look for

Use `--preview-find`. It centres a window of `--preview-length` chars on the first occurrence
of the needle, snapping start/end to the nearest HTML element boundary. This is the **preferred
option** when truncation is needed — it guarantees the relevant signal appears in the preview
regardless of where it sits in the body.

```bash
# PHP SQL errors
--preview-find "SQLSTATE" --preview-length 600

# Python tracebacks
--preview-find "Traceback" --preview-length 800

# PHP warnings
--preview-find "Warning:" --preview-length 600

# Generic exceptions
--preview-find "Exception" --preview-length 800
```

If the needle is not found in a given response, the window falls back to
`--preview-offset + --preview-length` from the start.

### 2. Errors appear after a large fixed header

Use `--preview-offset` to skip boilerplate (e.g. a full HTML `<head>` and nav bar), then
capture from the dynamic region.

```bash
--preview-offset 800 --preview-length 1200   # skip <head> + nav, capture <body> content
```

Identify the right offset from the baseline: find where the dynamic content begins in a
typical response body and use that character position as `--preview-offset`.

### 3. API responses are short and structured, or errors appear at the start

The default (`--preview-length 0`, no truncation) is fine. No additional flags needed.

### 4. Large run with large and unpredictable responses

Set `--preview-length` to 3000–5000. At 200 requests this adds ~60 K tokens — acceptable.
Beyond 500 requests or with very large responses, prefer option 1 or 2.

### 5. Small run or offline analysis

`--preview-length 0` (no truncation) is safe for ≤50 results regardless of body size.
For larger runs, estimate token cost first: N responses × avg_body_chars ÷ 4 ≈ tokens.

---

## Context Budget

Claude's standard context window is 200 K tokens. With the skill prompt, manifests, and
corpus files consuming ~10–15 K tokens, the practical budget for fuzz result data is roughly
**100–150 K tokens**.

| Config | Tokens per result | Max results in budget |
|--------|------------------|-----------------------|
| No truncation, 1 KB response | ~250 | ~500 |
| No truncation, 10 KB response | ~2500 | ~50 |
| `--preview-length 2000` | ~500 | ~250 |
| `--preview-find` + `--preview-length 600` | ~150 | ~750 |

**Do not drop `--preview-find` to save tokens** if it was chosen because a known error signal
is buried deep in the body. That tradeoff always loses — you save tokens but miss the finding.

---

## Examples

**Hunt for SQL errors in a PHP app:**
```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --threads 5 --delay-ms 500 \
  --preview-find "SQLSTATE" \
  --preview-length 600
```
`SQLSTATE[HY000]: General error: unrecognized token` will be centred in the preview even
if it appears at character 700 of a 2 000-character page.

**Skip a large HTML header in a legacy app:**
```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --threads 10 --delay-ms 500 \
  --preview-offset 1200 --preview-length 1000
```

**Full-body capture for a small JSON API run:**
```bash
uv run {baseDir}/scripts/run_fuzz.py \
  --manifest "$WORK_DIR/manifest.json" \
  --corpus-dir "$WORK_DIR/corpus" \
  --threads 5 --delay-ms 500
# --preview-length defaults to 0; full body captured automatically
```
