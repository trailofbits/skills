---
name: using-gh-cli
description: "Guides usage of the GitHub CLI (gh) for interacting with GitHub repositories, PRs, issues, and API. Use when working with GitHub resources instead of WebFetch or curl."
allowed-tools:
  - Bash
  - Read
---

# Using the GitHub CLI (`gh`)

## When to Use

- Viewing or creating pull requests, issues, releases, or gists
- Fetching file contents, repo metadata, or any GitHub API data
- Interacting with GitHub Actions (runs, workflows)
- Any task involving GitHub that you might otherwise use `curl`, `wget`, or `WebFetch` for

## When NOT to Use

- Non-GitHub URLs (use `WebFetch` or `curl` for those)
- Public web content that happens to be hosted on GitHub Pages (`*.github.io`) — those are regular websites
- Local git operations (`git commit`, `git push`) — use `git` directly

## Key Principle

**Always use `gh` instead of `curl`, `wget`, or `WebFetch` for GitHub URLs.** The `gh` CLI uses the user's authenticated token automatically, so it:

- Works with private repositories
- Avoids GitHub API rate limits (unauthenticated: 60 req/hr; authenticated: 5,000 req/hr)
- Handles pagination correctly
- Provides structured output and filtering

## Quick Start

```bash
# View a repo
gh repo view owner/repo

# List and view PRs
gh pr list --repo owner/repo
gh pr view 123 --repo owner/repo

# List and view issues
gh issue list --repo owner/repo
gh issue view 456 --repo owner/repo

# Call any REST API endpoint
gh api repos/owner/repo/contents/README.md

# Call with pagination and jq filtering
gh api repos/owner/repo/pulls --paginate --jq '.[].title'
```

## Common Patterns

| Instead of | Use |
|------------|-----|
| `WebFetch` on `github.com/owner/repo` | `gh repo view owner/repo` |
| `WebFetch` on `api.github.com/...` | `gh api <endpoint>` |
| `WebFetch` on `raw.githubusercontent.com/...` | `gh api repos/owner/repo/contents/path` |
| `curl https://api.github.com/...` | `gh api <endpoint>` |
| `curl` with `-H "Authorization: token ..."` | `gh api <endpoint>` (auth is automatic) |
| `wget` to download a release asset | `gh release download --repo owner/repo` |

## Decoding File Contents

`gh api repos/.../contents/...` returns base64-encoded content. Decode it:

```bash
gh api repos/owner/repo/contents/path/to/file --jq '.content' | base64 -d
```

Or for binary files / large files, use the raw media type:

```bash
gh api repos/owner/repo/contents/path/to/file -H "Accept: application/vnd.github.raw+json"
```

## References

- [Pull Requests](references/pull-requests.md) — list, view, create, merge, review PRs
- [Issues](references/issues.md) — list, view, create, close, comment on issues
- [Repos and Files](references/repos-and-files.md) — view repos, browse files, clone
- [API](references/api.md) — raw REST/GraphQL access, pagination, jq filtering
- [Releases](references/releases.md) — list, create, download releases
- [Actions](references/actions.md) — view runs, trigger workflows, check logs
