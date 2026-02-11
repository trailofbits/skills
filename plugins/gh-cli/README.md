# gh-cli

A Claude Code plugin that intercepts GitHub URL fetches and redirects Claude to use the authenticated `gh` CLI instead.

## Problem

Claude Code's `WebFetch` tool and Bash `curl`/`wget` commands don't use the user's GitHub authentication. This means:

- **Private repos**: Fetches fail with 404 errors
- **Rate limits**: Unauthenticated requests are limited to 60/hour (vs 5,000/hour authenticated)
- **Missing data**: Some API responses are incomplete without authentication

## Solution

This plugin provides:

1. **PreToolUse hooks** that intercept GitHub URL access and suggest the correct `gh` CLI command
2. **A skill** with comprehensive `gh` CLI reference documentation

### What Gets Intercepted

| Tool | Pattern | Suggestion |
|------|---------|------------|
| `WebFetch` | `github.com/{owner}/{repo}` | `gh repo view owner/repo` |
| `WebFetch` | `api.github.com/repos/.../pulls` | `gh pr list` / `gh pr view` |
| `WebFetch` | `api.github.com/repos/.../issues` | `gh issue list` / `gh issue view` |
| `WebFetch` | `api.github.com/...` | `gh api <endpoint>` |
| `WebFetch` | `raw.githubusercontent.com/...` | `gh api repos/.../contents/...` |
| `Bash` | `curl https://api.github.com/...` | `gh api <endpoint>` |
| `Bash` | `wget https://github.com/...` | `gh release download` |

### What Passes Through

- Non-GitHub URLs (any domain that isn't `github.com`, `api.github.com`, `raw.githubusercontent.com`, or `gist.github.com`)
- GitHub Pages sites (`*.github.io`)
- Commands already using `gh`
- Git commands (`git clone`, `git push`, etc.)
- Search commands that mention GitHub URLs (`grep`, `rg`, etc.)

## Prerequisites

- [GitHub CLI (`gh`)](https://cli.github.com/) must be installed and authenticated (`gh auth login`)
- If `gh` is not installed, the hooks silently pass through (no disruption)

## Installation

```
/plugin marketplace add trailofbits/skills
/plugin install gh-cli
```
