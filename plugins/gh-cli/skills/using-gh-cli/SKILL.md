---
name: using-gh-cli
description: "Guides usage of the GitHub CLI (gh) for interacting with GitHub repositories, PRs, issues, and API. Use when working with GitHub resources instead of WebFetch or curl."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Using the GitHub CLI (`gh`)

## When to Use

- **Browsing or reading code** from a GitHub repository — clone it and use Read/Glob/Grep
- Viewing or creating pull requests, issues, releases, or gists
- Fetching repo metadata or any GitHub API data
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

## Browsing Repository Code

**To read or browse files from a GitHub repo, clone it locally and use normal file tools** (Read, Glob, Grep). This is much faster and more natural than fetching files one-by-one via the API.

```bash
# Clone to a session-scoped temp directory (cleaned up automatically on session end)
clonedir="$TMPDIR/gh-clones-${CLAUDE_SESSION_ID}"
mkdir -p "$clonedir"
gh repo clone owner/repo "$clonedir/repo" -- --depth 1
```

After cloning, use the **Explore agent** (via the Task tool with `subagent_type=Explore`) to investigate the cloned repo. The Explore agent can use Read, Glob, and Grep across the clone efficiently — much better than calling them one at a time:

```
Task(subagent_type="Explore", prompt="In $clonedir/repo/, find how authentication is implemented")
```

For targeted lookups on a clone you already understand, use Read/Glob/Grep directly.

- `gh repo clone` uses the user's authenticated token — works with private repos
- `--depth 1` keeps the clone fast (only latest commit)
- No cleanup needed — a SessionEnd hook removes the clone directory automatically
- Use `gh api` only when you need a quick single-file lookup without cloning

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
| `WebFetch` on a blob/tree URL | Clone with `gh repo clone` and use Read/Glob/Grep |
| `WebFetch` on `raw.githubusercontent.com/...` | Clone with `gh repo clone` and use Read |
| `WebFetch` on `api.github.com/...` | `gh api <endpoint>` |
| `curl https://api.github.com/...` | `gh api <endpoint>` |
| `curl` with `-H "Authorization: token ..."` | `gh api <endpoint>` (auth is automatic) |
| `wget` to download a release asset | `gh release download --repo owner/repo` |

## References

- [Pull Requests](references/pull-requests.md) — list, view, create, merge, review PRs
- [Issues](references/issues.md) — list, view, create, close, comment on issues
- [Repos and Files](references/repos-and-files.md) — view repos, browse files, clone
- [API](references/api.md) — raw REST/GraphQL access, pagination, jq filtering
- [Releases](references/releases.md) — list, create, download releases
- [Actions](references/actions.md) — view runs, trigger workflows, check logs
