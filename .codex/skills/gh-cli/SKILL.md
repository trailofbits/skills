---
name: gh-cli
description: Use when working with GitHub URLs or API access so Codex prefers authenticated gh CLI workflows over unauthenticated WebFetch/curl patterns.
---

# gh-cli

## When to Use

- Working with GitHub repositories, pull requests, issues, releases, or raw file URLs.
- You need authenticated access to private repositories or higher API rate limits.
- You are about to use `curl`, `wget`, or unauthenticated web fetches against GitHub.

## When NOT to Use

- The target is not GitHub.
- Plain local git operations already solve the task.

## Guidance

Prefer the authenticated `gh` CLI over raw HTTP fetches for GitHub content. In particular:

- Prefer `gh repo view`, `gh pr view`, `gh pr list`, `gh issue view`, and `gh api` over unauthenticated `curl` or `wget`.
- Prefer cloning a repository and reading files locally over fetching `raw.githubusercontent.com` blobs directly.
- Avoid using GitHub API `/contents/` endpoints as a substitute for cloning and reading repository files.

Examples:

```sh
gh repo view owner/repo
gh pr view 123 --repo owner/repo
gh api repos/owner/repo/pulls
```

For the original Claude plugin implementation, see:
- `plugins/gh-cli/README.md`
- `plugins/gh-cli/hooks/`
