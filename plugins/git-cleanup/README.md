# git-cleanup

A Claude Code skill for safely cleaning up accumulated git worktrees and local branches.

## What It Does

Analyzes your local git repository and categorizes branches/worktrees into:

- **Safe to delete**: Branches fully merged into the default branch
- **Needs review**: Branches with deleted remotes (`[gone]`) that may have local-only work
- **Theme-related**: Groups of branches working on similar functionality
- **Keep**: Active work with unpushed commits or untracked local branches

The skill uses a gated workflow requiring explicit user confirmation before any deletions.

## When to Use

Invoke with `/git-cleanup` when you have accumulated many local branches and worktrees that need cleanup.

**Important**: This skill only runs when explicitly invoked. It will never suggest cleanup proactively or run automatically.

## Safety Features

- Two confirmation gates (analysis review, then deletion confirmation)
- Uses safe delete (`git branch -d`) for merged branches; force delete (`git branch -D`) only for squash-merged branches where git cannot detect the merge
- Blocks removal of worktrees with uncommitted changes
- Never touches protected branches (main, master, develop)
- Flags `[gone]` branches for review instead of auto-deleting

## Installation

```bash
claude plugins:add trailofbits/skills/git-cleanup
```

## Example

```
User: /git-cleanup

Claude: [Analyzes branches and worktrees]
        [Presents categorized tables]
        "I found 5 branches safe to delete, 2 needing review.
         Which would you like to clean up?"

User: "Delete the merged branches"

Claude: "I will delete these branches:
         - feature/auth
         - bugfix/login
         Confirm? (yes/no)"

User: "yes"

Claude: [Executes and reports results]
```
