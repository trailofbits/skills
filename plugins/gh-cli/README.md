# gh-cli

A Claude Code plugin that intercepts GitHub URL fetches and redirects Claude to use the authenticated `gh` CLI instead.

## Problem

Claude Code's `WebFetch` tool, MCP fetch tools (Exa's `web_fetch_exa` and similar), and Bash `curl`/`wget` commands don't use the user's GitHub authentication. This means:

- **Private repos**: Fetches fail with 404 errors
- **Rate limits**: Unauthenticated requests are limited to 60/hour (vs 5,000/hour authenticated)
- **Missing data**: Some API responses are incomplete without authentication

## Solution

This plugin provides:

1. **PreToolUse hooks** that intercept GitHub URL access via `WebFetch`, MCP fetch/scrape/crawl/extract tools, or `curl`/`wget`, and suggest the correct `gh` CLI command
2. **A `gh` PATH shim** that blocks anti-patterns: API `/contents/` fetching and non-session-scoped temp directory clones
3. **A SessionEnd hook** that automatically cleans up cloned repositories when the session ends

### What Gets Intercepted

The fetch hook matches `WebFetch` plus any MCP tool whose name contains `fetch`,
`scrape`, `crawl`, or `extract` — `mcp__exa__web_fetch_exa`,
`mcp__firecrawl__firecrawl_scrape`, `mcp__tavily__tavily_extract`, and
equivalents from other MCP servers. Web tools named something else entirely
(browser navigation, for instance) are not covered; `hooks/matcher.bats` records
exactly which names match.

It reads both fetch payload shapes — `WebFetch`'s single `url`, and the `urls`
field MCP fetch tools use to batch several pages into one call, whether that
field arrives as an array or a bare string. Because a tool call is atomic, one
GitHub URL anywhere in a batch denies the whole call; the denial names each
offending URL alongside its suggestion. `WebFetch`'s `prompt` field is
deliberately not scanned, so a prompt that merely mentions a GitHub URL is not
denied.

| Tool | Pattern | Suggestion |
|------|---------|------------|
| `WebFetch`, MCP fetch | `github.com/{owner}/{repo}` | `gh repo view owner/repo` |
| `WebFetch`, MCP fetch | `github.com/.../blob/...` | `gh repo clone` + Read |
| `WebFetch`, MCP fetch | `github.com/.../tree/...` | `gh repo clone` + Read/Glob/Grep |
| `WebFetch`, MCP fetch | `github.com/.../pull/{n}` | `gh pr view` |
| `WebFetch`, MCP fetch | `github.com/.../issues/{n}` | `gh issue view` |
| `WebFetch`, MCP fetch | `github.com/.../releases/download/...` | `gh release download` |
| `WebFetch`, MCP fetch | `api.github.com/repos/.../pulls` | `gh pr list` / `gh pr view` |
| `WebFetch`, MCP fetch | `api.github.com/repos/.../issues` | `gh issue list` / `gh issue view` |
| `WebFetch`, MCP fetch | `api.github.com/repos/.../contents/...` | `gh repo clone` + Read |
| `WebFetch`, MCP fetch | `api.github.com/repos/.../releases` | `gh release list` |
| `WebFetch`, MCP fetch | `api.github.com/repos/.../actions` | `gh run list` |
| `WebFetch`, MCP fetch | `api.github.com/...` (anything else) | `gh api <endpoint>` |
| `WebFetch`, MCP fetch | `raw.githubusercontent.com/...` | `gh repo clone` + Read |
| `WebFetch`, MCP fetch | `gist.github.com/...` | `gh gist view` |
| `Bash` | `curl https://api.github.com/...` | `gh api <endpoint>` |
| `Bash` | `curl https://raw.githubusercontent.com/...` | `gh repo clone` + Read |
| `Bash` | `wget https://github.com/...` | `gh release download` |
| `Bash` (shim) | `gh api repos/.../contents/...` | `gh repo clone` + Read |
| `Bash` (shim) | `gh repo clone ... /tmp/...` (non-session-scoped) | Session-scoped clone path |

### What Passes Through

- Non-GitHub URLs (any domain that isn't `github.com`, `api.github.com`, `raw.githubusercontent.com`, or `gist.github.com`)
- GitHub Pages sites (`*.github.io`)
- Commands already using `gh` (except anti-patterns blocked by the shim; see table above)
- Git commands (`git clone`, `git push`, etc.)
- Search commands that mention GitHub URLs (`grep`, `rg`, etc.)

**Note:** When hooks deny blob/tree/raw URLs, the denial message explicitly warns against using `gh api` to fetch and base64-decode file contents as a fallback — clone the repo instead.

### Automatic Cleanup

Cloned repositories are stored in session-scoped temp directories (`$TMPDIR/gh-clones-<session-id>/`). A SessionEnd hook automatically removes them when the session ends, so there's no manual cleanup needed and concurrent sessions don't interfere with each other.

## Prerequisites

- [GitHub CLI (`gh`)](https://cli.github.com/) must be installed and authenticated (`gh auth login`)
- If `gh` is not installed, the hooks pass through without disruption

## Installation

```
/plugin marketplace add trailofbits/skills
/plugin install gh-cli
```
