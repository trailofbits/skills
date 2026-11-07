# Burp Suite Project Parser

Search and extract data from Burp Suite project files (.burp) for use in Claude

**Author:** Will Vandevanter

## Prerequisites

- **Burp Suite Professional** - Required for project file support
- **burpsuite-project-file-parser extension** - Must be installed in Burp Suite (Available: https://github.com/BuffaloWill/burpsuite-project-file-parser)
- **jq** (optional) - Recommended for formatting/filtering JSON output

## When to Use

Use this skill when you need to get the following from a Burp project:
- Search response headers or bodies using regex patterns
- Extract security audit findings and vulnerabilities
- Dump proxy history or site map data for analysis
- Programmatically analyze HTTP traffic captured by Burp Suite

Trigger phrases: "search the burp project", "find in burp file", "what vulnerabilities in the burp", "get audit items from burp"

## What It Does

This skill provides CLI access to Burp Suite project files through the burpsuite-project-file-parser extension:

1. **Search headers/bodies** - Find specific patterns in captured HTTP traffic using regex
2. **Extract audit items** - Get all security findings with severity, confidence, and URLs
3. **Dump traffic data** - Export proxy history and site map entries as JSON
4. **Filter output** - Use sub-component filters to optimize performance on large projects

## Installation

```
/plugin install trailofbits/skills/plugins/burpsuite-project-parser
```

## Usage

Inside Claude Code, run `/burpsuite-project-parser:burp-search` — it takes the same
project path and flags as the script below.


Base command:
```bash
scripts/burp-search.sh /path/to/project.burp [FLAGS]
```

### Available Commands

| Command | Description | Output |
|---------|-------------|--------|
| `auditItems` | Extract all security findings | JSON: name, severity, confidence, host, port, protocol, url |
| `proxyHistory` | Dump all captured HTTP traffic | Complete request/response data |
| `siteMap` | Dump all site map entries | Site structure |
| `responseHeader='.*regex.*'` | Search response headers | JSON: url, header |
| `responseBody='.*regex.*'` | Search response bodies | Matching content |

### Sub-Component Filters

For large projects, filter to specific data to improve performance:

```bash
proxyHistory.request.headers    # Only request headers
proxyHistory.request.body       # Only request body
proxyHistory.response.headers   # Only response headers
proxyHistory.response.body      # Only response body
```

Same patterns work with `siteMap.*`

## Examples

Search for CORS headers:
```bash
scripts/burp-search.sh project.burp "responseHeader='.*Access-Control.*'"
```

Get all high-severity findings:
```bash
scripts/burp-search.sh project.burp auditItems | jq 'select(.severity == "High")'
```

Find server signatures:
```bash
scripts/burp-search.sh project.burp "responseHeader='.*(nginx|Apache|Servlet).*'"
```

Extract request URLs from proxy history:
```bash
scripts/burp-search.sh project.burp proxyHistory.request.headers | jq -r '.request.url'
```

Search for HTML forms:
```bash
scripts/burp-search.sh project.burp "responseBody='.*<form.*action.*'"
```

## Output Format

All output is JSON, one object per line. Pipe to `jq` for formatting or use `grep` for filtering:

```bash
scripts/burp-search.sh project.burp auditItems | jq .
scripts/burp-search.sh project.burp auditItems | grep -i "sql injection"
```

## Calcifier recipe for `burpsuite-project-parser`

The [`burpsuite-project-parser` Python recipe](skills/burpsuite-project-parser/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/burpsuite-project-parser/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/burpsuite-project-parser/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `project_file` | `str` | Required |
| `scope` | `str` | Required |
| `collection` | `Literal['proxyHistory', 'siteMap']` | `'proxyHistory'` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
