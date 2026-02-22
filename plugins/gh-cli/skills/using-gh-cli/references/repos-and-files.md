# Repos and Files

## Browsing Code (Preferred)

**Clone the repo and use normal file tools.** This is the best approach when you need to read multiple files, search code, or explore a repository structure.

```bash
# Clone to a session-scoped temp directory
clonedir="$TMPDIR/gh-clones-${CLAUDE_SESSION_ID}"
mkdir -p "$clonedir"
gh repo clone owner/repo "$clonedir/repo" -- --depth 1
```

> **IMPORTANT:** Always use `$TMPDIR/gh-clones-${CLAUDE_SESSION_ID}` exactly as shown. Do NOT invent alternative paths like `/tmp/claude/gh-clones/` — they conflict across sessions and won't be cleaned up.

```bash
# Clone a specific branch
gh repo clone owner/repo "$clonedir/repo" -- --depth 1 --branch develop
```

After cloning, use the **Explore agent** (via the Task tool with `subagent_type=Explore`) to explore the codebase — it can search, read, and navigate across the clone efficiently in a single invocation. For targeted lookups where you already know what you're looking for, use Read, Glob, and Grep directly.

## Anti-Pattern: Fetching and Base64-Decoding File Contents via API

**Never do this:**

```bash
# BAD — slow, lossy, and wasteful compared to cloning
gh api repos/owner/repo/contents/path/to/file.py --jq '.content' | base64 -d
```

This is a common fallback when direct URL access is denied. It fetches files one-by-one through the API, requires base64 decoding, has a 1 MB size limit per file, and is far slower than cloning. **Clone the repo instead.**

## Quick Single-File Lookup (Last Resort)

When you need a single file at a **specific commit SHA** and cloning is impractical, use the raw accept header (not base64 decoding):

```bash
# Get raw file content directly (skips base64)
gh api repos/owner/repo/contents/path/to/file.py \
  -H "Accept: application/vnd.github.raw+json"

# Get file from a specific branch/ref
gh api repos/owner/repo/contents/path/to/file.py?ref=develop \
  -H "Accept: application/vnd.github.raw+json"

# List directory contents
gh api repos/owner/repo/contents/src/ --jq '.[].name'
```

## When to Clone vs. Use API

| Scenario | Approach |
|----------|----------|
| Explore/understand a codebase | Clone, then use Explore agent |
| Search code with Grep/Glob | Clone, then search directly |
| Read a single file at a specific commit SHA | `gh api` with raw accept header and `?ref=<sha>` |
| Read a single known file (current branch) | Clone — faster than API for follow-up reads |
| List directory contents | Either works |
