# Repos and Files

## Browsing Code (Preferred)

**Clone the repo and use normal file tools.** This is the best approach when you need to read multiple files, search code, or explore a repository structure.

```bash
# Clone to a session-scoped temp directory
clonedir="$TMPDIR/gh-clones-${CLAUDE_SESSION_ID}"
mkdir -p "$clonedir"
gh repo clone owner/repo "$clonedir/repo" -- --depth 1

# Clone a specific branch
gh repo clone owner/repo "$clonedir/repo" -- --depth 1 --branch develop
```

After cloning, use the **Explore agent** (via the Task tool with `subagent_type=Explore`) to explore the codebase — it can search, read, and navigate across the clone efficiently in a single invocation. For targeted lookups where you already know what you're looking for, use Read, Glob, and Grep directly.

## Quick Single-File Lookup (Alternative)

When you only need one file and don't want to clone, use `gh api`:

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
| Read a single known file | `gh api` with raw accept header |
| List directory contents | Either works |
| Need file from a specific commit SHA | `gh api` with `?ref=<sha>` |
