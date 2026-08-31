---
name: burpsuite-project-parser
description: Searches and explores Burp Suite project files (.burp) from the command line. Use when searching response headers or bodies with regex patterns, extracting security audit findings, dumping proxy history or site map data, or analyzing HTTP traffic captured in a Burp project.
allowed-tools: Bash Read
---

# Burp Project Parser

Search and extract data from Burp Suite project files using the burpsuite-project-file-parser extension.

## When to Use

- Searching response headers or bodies with regex patterns
- Extracting security audit findings from Burp projects
- Dumping proxy history or site map data
- Analyzing HTTP traffic captured in a Burp project file

## Prerequisites

This skill **delegates parsing to Burp Suite Professional** - it does not parse .burp files directly.

**Required:**
1. **Burp Suite Professional** - Must be installed ([portswigger.net](https://portswigger.net/burp/pro))
2. **burpsuite-project-file-parser extension** - Provides CLI functionality

**Install the extension:**
1. Download from [github.com/BuffaloWill/burpsuite-project-file-parser](https://github.com/BuffaloWill/burpsuite-project-file-parser)
2. In Burp Suite: Extender → Extensions → Add
3. Select the downloaded JAR file

## Quick Reference

Use the wrapper script:
```bash
{baseDir}/scripts/burp-search.sh /path/to/project.burp [FLAGS]
```

The script uses environment variables for platform compatibility:
- `BURP_JAVA`: Path to Java executable
- `BURP_JAR`: Path to burpsuite_pro.jar

**Check the exit code. Empty output is not a clean result.** Burp ignores flags it does not recognise, so
without the parser extension it starts normally and drops the query — which looks exactly like a search that
matched nothing.

| Exit | Meaning | What to do |
|------|---------|------------|
| 0 | Output produced | Proceed |
| 1 | Bad usage, or a missing file, Java or JAR | Read the message; fix the path |
| 3 | No output at all | **Do not report this as "nothing found".** An empty result set and an unloaded extension are indistinguishable from here. Run the control query below to tell them apart |
| 4 | Output was not JSON | The extension is not loaded and Burp ignored the flags. Install it before trusting any result |

Anything other than 0 means the search result is unverified, and saying "no matching traffic" on the strength
of it is a false negative reported as a clean finding.

### Resolving Exit 3: the control query

Exit 3 is the common case — most narrowly-scoped regexes legitimately match nothing — so it needs a resolution
you can carry out yourself. You have `Bash` and `Read`; Burp runs headless here, so there is no Extensions tab
to open and no GUI to inspect. Re-running the same query just returns 3 again.

Run a **control query** instead: a selector broad enough that it must return rows if the parser is working at
all, against the same project file. Use the sub-component filter, not the bare selector — a control is still a
query, and the rules above apply to it unchanged.

```bash
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.request.headers | head -c 2000
```

`proxyHistory.request.headers` is the right control precisely because it is broad but bounded: it covers every
record in the project, at under 1KB each. Bare `proxyHistory` would answer the same question and is banned
above for a reason — one record with bodies can be megabytes, and `head -n 1` does not stop that, it delivers
exactly one of them in full.

| Control result | What it means | What to do |
|---|---|---|
| Rows on stdout | The parser works | Your narrower query genuinely matched nothing. Report that as a result |
| Exit 3 again | Nothing comes back at all | Either the extension is not loaded, or this project holds no proxy history. Check you named the right project file and that it is non-empty, then ask the user to confirm `burpsuite-project-file-parser` under Burp Suite → Extensions |
| Exit 4 | Burp started and dropped the flags | The extension is not loaded. Say so; do not report on traffic |

**Run the control before concluding anything about the project's traffic.** Assuming the extension is loaded is
exactly how an unverified empty result becomes a clean bill of health — and asking the user to check the GUI is
a legitimate answer where the control is inconclusive. Guessing is not.

**Through a pipe the exit code is not yours to read.** A pipeline reports the status of its *last* command, and
nearly every example here ends in `| jq`, `| head` or `| wc -cl` — so `$?` is `head`'s 0, not the script's 3.
Two reliable signals:

- **stderr**, which reaches you regardless of piping. `Error: the parser produced no output.` or
  `Error: Burp produced output, but not one JSON object` is the answer; no such block means the run was fine.
- **`set -o pipefail`** when you want the code itself, or read `${PIPESTATUS[0]}`:

```bash
set -o pipefail
{baseDir}/scripts/burp-search.sh project.burp auditItems | jq -c 'select(.severity == "High")'
echo "exit: $?"
```

Non-JSON output never reaches stdout, so a downstream `grep` or `jq` cannot match a Burp startup banner and
mistake it for data.

See [Platform Configuration](#platform-configuration) for setup instructions.

## Sub-Component Filters (USE THESE)

**ALWAYS use sub-component filters instead of full dumps.** Full `proxyHistory` or `siteMap` can return gigabytes of data. Sub-component filters return only what you need.

### Available Filters

| Filter | Returns | Typical Size |
|--------|---------|--------------|
| `proxyHistory.request.headers` | Request line + headers only | Small (< 1KB/record) |
| `proxyHistory.request.body` | Request body only | Variable |
| `proxyHistory.response.headers` | Status + headers only | Small (< 1KB/record) |
| `proxyHistory.response.body` | Response body only | **LARGE - avoid** |
| `siteMap.request.headers` | Same as above for site map | Small |
| `siteMap.request.body` | | Variable |
| `siteMap.response.headers` | | Small |
| `siteMap.response.body` | | **LARGE - avoid** |

### Default Approach

**Start with headers, not bodies:**

```bash
# GOOD - headers only, safe to retrieve
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.request.headers | head -c 50000
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.response.headers | head -c 50000

# BAD - full records include bodies, can be gigabytes
{baseDir}/scripts/burp-search.sh project.burp proxyHistory  # NEVER DO THIS
```

**Only fetch bodies for specific URLs after reviewing headers, and ALWAYS truncate:**

```bash
# 1. First, find interesting URLs from headers
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.response.headers | \
  jq -r 'select(.headers | test("text/html")) | .url' | head -n 20

# 2. Then search bodies with targeted regex - MUST truncate body to 1000 chars
{baseDir}/scripts/burp-search.sh project.burp "responseBody='.*specific-pattern.*'" | \
  head -n 10 | jq -c '.body = (.body[:1000] + "...[TRUNCATED]")'
```

**HARD RULE: Body content > 1000 chars must NEVER enter context.** If the user needs full body content, they must view it in Burp Suite's UI.

## Regex Search Operations

### Search Response Headers
```bash
responseHeader='.*regex.*'
```
Searches all response headers. Output: `{"url":"...", "header":"..."}`

Example - find server signatures:
```bash
responseHeader='.*(nginx|Apache|Servlet).*' | head -c 50000
```

### Search Response Bodies
```bash
responseBody='.*regex.*'
```
**MANDATORY: Always truncate body content to 1000 chars max.** Response bodies can be megabytes each.

```bash
# REQUIRED format - always truncate .body field
{baseDir}/scripts/burp-search.sh project.burp "responseBody='.*<form.*action.*'" | \
  head -n 10 | jq -c '.body = (.body[:1000] + "...[TRUNCATED]")'
```

**Never retrieve full body content.** If you need to see more of a specific response, ask the user to open it in Burp Suite's UI.

## Other Operations

### Extract Audit Items
```bash
auditItems
```
Returns all security findings. Output includes: name, severity, confidence, host, port, protocol, url.

**Note:** Audit items are small (no bodies) - safe to retrieve with `head -n 100`.

### Dump Proxy History (AVOID)
```bash
proxyHistory
```
**NEVER use this directly.** Use sub-component filters instead:
- `proxyHistory.request.headers`
- `proxyHistory.response.headers`

### Dump Site Map (AVOID)
```bash
siteMap
```
**NEVER use this directly.** Use sub-component filters instead.

## Output Limits (REQUIRED)

**CRITICAL: Always check result size BEFORE retrieving data.** A broad search can return thousands of records, each potentially megabytes. This will overflow the context window.

### Step 1: Always Check Size First

Before any search, check BOTH record count AND byte size:

```bash
# Check record count AND total bytes - never skip this step
{baseDir}/scripts/burp-search.sh project.burp proxyHistory | wc -cl
{baseDir}/scripts/burp-search.sh project.burp "responseHeader='.*Server.*'" | wc -cl
{baseDir}/scripts/burp-search.sh project.burp auditItems | wc -cl
```

The `wc -cl` output shows: `<bytes> <lines>` (e.g., `524288 42` means 512KB across 42 records).

**Interpret the results - BOTH must pass:**

| Metric | Safe | Narrow search | Too broad | STOP |
|--------|------|---------------|-----------|------|
| **Lines** | < 50 | 50-200 | 200+ | 1000+ |
| **Bytes** | < 50KB | 50-200KB | 200KB+ | 1MB+ |

**A single 10MB response on one line will show high byte count but only 1 line - the byte check catches this.**

`0 0` from `wc -cl` is not a size to act on — the script exited 3 and nothing was verified. Piping hides that,
so re-run the query on its own and read the exit code before concluding the project holds no matching traffic.

### Step 2: Refine Broad Searches

If count/size is too high:

1. **Use sub-component filters** (see table above):
   ```bash
   # Instead of: proxyHistory (gigabytes)
   # Use: proxyHistory.request.headers (kilobytes)
   ```

2. **Narrow regex patterns:**
   ```bash
   # Too broad (matches everything):
   responseHeader='.*'

   # Better - target specific headers:
   responseHeader='.*X-Frame-Options.*'
   responseHeader='.*Content-Security-Policy.*'
   ```

3. **Filter with jq before retrieving:**
   ```bash
   # Get only specific content types
   {baseDir}/scripts/burp-search.sh project.burp proxyHistory.response.headers | \
     jq -c 'select(.url | test("/api/"))' | head -n 50
   ```

### Step 3: Always Truncate Output

Even after narrowing, always pipe through truncation:

```bash
# ALWAYS use head -c to limit total bytes (max 50KB)
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.request.headers | head -c 50000

# For body searches, truncate each JSON object's body field:
{baseDir}/scripts/burp-search.sh project.burp "responseBody='pattern'" | \
  head -n 20 | jq -c '.body = (.body | if length > 1000 then .[:1000] + "...[TRUNCATED]" else . end)'

# Limit both record count AND byte size:
{baseDir}/scripts/burp-search.sh project.burp auditItems | head -n 50 | head -c 50000
```

**Hard limits to enforce:**
- `head -c 50000` (50KB max) on ALL output
- **Truncate `.body` fields to 1000 chars - MANDATORY, no exceptions**
  ```bash
  jq -c '.body = (.body[:1000] + "...[TRUNCATED]")'
  ```

**Never run these without counting first AND truncating:**
- `proxyHistory` / `siteMap` (full dumps - always use sub-component filters)
- `responseBody='...'` searches (bodies can be megabytes each)
- Any broad regex like `.*` or `.+`

## Investigation Workflow

1. **Identify scope** - What are you looking for? (specific vuln type, endpoint, header pattern)

2. **Search audit items first** - Start with Burp's findings:
   ```bash
   {baseDir}/scripts/burp-search.sh project.burp auditItems | jq 'select(.severity == "High")'
   ```

3. **Check confidence scores** - Filter for actionable findings:
   ```bash
   ... | jq 'select(.confidence == "Certain" or .confidence == "Firm")'
   ```

4. **Extract affected URLs** - Get the attack surface:
   ```bash
   ... | jq -r '.url' | sort -u
   ```

5. **Search raw traffic for context** - Examine actual requests/responses:
   ```bash
   {baseDir}/scripts/burp-search.sh project.burp "responseBody='pattern'"
   ```

6. **Validate manually** - Burp findings are indicators, not proof. Verify each one.

## Understanding Results

### Severity vs Confidence

Burp reports both **severity** (High/Medium/Low) and **confidence** (Certain/Firm/Tentative). Use both when triaging:

| Combination | Meaning |
|-------------|---------|
| High + Certain | Likely real vulnerability, prioritize investigation |
| High + Tentative | Often a false positive, verify before reporting |
| Medium + Firm | Worth investigating, may need manual validation |

A "High severity, Tentative confidence" finding is frequently a false positive. Don't report findings based on severity alone.

### When Proxy History is Incomplete

Proxy history only contains what Burp captured. It may be missing traffic due to:
- **Scope filters** excluding domains
- **Intercept settings** dropping requests
- **Browser traffic** not routed through Burp proxy

If you don't find expected traffic, check Burp's scope and proxy settings in the original project.

### HTTP Body Encoding

Response bodies may be gzip compressed, chunked, or use non-UTF8 encoding. Regex patterns that work on plaintext may silently fail on encoded responses. If searches return fewer results than expected:
- Check if responses are compressed
- Try broader patterns or search headers first
- Use Burp's UI to inspect raw vs rendered response

## Rationalizations to Reject

Common shortcuts that lead to missed vulnerabilities or false reports:

| Shortcut | Why It's Wrong |
|----------|----------------|
| "This regex looks good" | Verify on sample data first—encoding and escaping cause silent failures |
| "High severity = must fix" | Check confidence score too; Burp has false positives |
| "All audit items are relevant" | Filter by actual threat model; not every finding matters for every app |
| "Proxy history is complete" | May be filtered by Burp scope/intercept settings; you see only what Burp captured |
| "Burp found it, so it's a vuln" | Burp findings require manual verification—they indicate potential issues, not proof |
| "The search returned nothing, so the traffic isn't there" | Check the exit code first. Exit 3 means the script could not tell an empty result from an unloaded extension, and exit 4 means the query never ran. Only a 0 makes "nothing found" a statement about the project rather than about the tooling |

## Output Format

All output is JSON, one object per line. Pipe to `jq` for formatting:
```bash
{baseDir}/scripts/burp-search.sh project.burp auditItems | jq .
```

Filter with grep:
```bash
{baseDir}/scripts/burp-search.sh project.burp auditItems | grep -i "sql injection"
```

## Examples

Search for CORS headers (with byte limit):
```bash
{baseDir}/scripts/burp-search.sh project.burp "responseHeader='.*Access-Control.*'" | head -c 50000
```

Get all high-severity findings (audit items are small, but still limit):
```bash
{baseDir}/scripts/burp-search.sh project.burp auditItems | jq -c 'select(.severity == "High")' | head -n 100
```

Extract just request URLs from proxy history:
```bash
{baseDir}/scripts/burp-search.sh project.burp proxyHistory.request.headers | jq -r '.request.url' | head -n 200
```

Search response bodies (MUST truncate body to 1000 chars):
```bash
{baseDir}/scripts/burp-search.sh project.burp "responseBody='.*password.*'" | \
  head -n 10 | jq -c '.body = (.body[:1000] + "...[TRUNCATED]")'
```

## Platform Configuration

The wrapper script requires two environment variables to locate Burp Suite's bundled Java and JAR file.

### macOS

```bash
export BURP_JAVA="/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java"
export BURP_JAR="/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar"
```

### Windows

```powershell
$env:BURP_JAVA = "C:\Program Files\BurpSuiteProfessional\jre\bin\java.exe"
$env:BURP_JAR = "C:\Program Files\BurpSuiteProfessional\burpsuite_pro.jar"
```

### Linux

```bash
export BURP_JAVA="/opt/BurpSuiteProfessional/jre/bin/java"
export BURP_JAR="/opt/BurpSuiteProfessional/burpsuite_pro.jar"
```

Add these exports to your shell profile (`.bashrc`, `.zshrc`, etc.) for persistence.

### Manual Invocation

If not using the wrapper script, invoke directly:
```bash
"$BURP_JAVA" -jar -Djava.awt.headless=true "$BURP_JAR" \
  --project-file=/path/to/project.burp [FLAGS]
```
