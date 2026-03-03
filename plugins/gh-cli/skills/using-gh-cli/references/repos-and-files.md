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

## Anti-Pattern: Fetching File Contents via API

**Never do this:**

```bash
# BAD — blocked by the gh shim
gh api repos/owner/repo/contents/path/to/file.py
```

The gh shim blocks all `gh api repos/.../contents/` access — regardless of flags (`--jq`, `-H Accept: ...raw+json`, etc.). This endpoint fetches files one-by-one and is far slower than cloning. **Clone the repo instead.**

## When to Clone vs. Use API

| Scenario | Approach |
|----------|----------|
| Explore/understand a codebase | Clone, then use Explore agent |
| Search code with Grep/Glob | Clone, then search directly |
| Read a single file at a specific commit SHA | Clone with `--depth 1`, then `git fetch --depth 1 origin <sha>` and `git show <sha>:path/to/file` |
| Read a single known file (current branch) | Clone — faster than API for follow-up reads |
| List directory contents | Clone, then use Glob |
