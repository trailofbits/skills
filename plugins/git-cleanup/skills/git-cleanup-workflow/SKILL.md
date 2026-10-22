---
name: git-cleanup-workflow
description: "Analyzes local git branches and worktrees for cleanup, distinguishing merged, squash-merged, superseded, and active work. Use when the user requests git branch or worktree cleanup."
disable-model-invocation: true
allowed-tools: Bash Read AskUserQuestion Workflow
---

# Git Cleanup

This is the `/git-cleanup` command for hosts that load skills but not commands. Read
[the command](../../commands/git-cleanup.md) and follow it, with these substitutions:

- **Repository:** the one the user named (default: the current directory) where the command says `$ARGUMENTS`.
- **Plugin root:** this plugin's directory, resolved from this SKILL.md's installed location, where the command says `${CLAUDE_PLUGIN_ROOT}`. Its workflow is [`workflows/analyze-branches.js`](../../workflows/analyze-branches.js).
- **No AskUserQuestion tool:** ask each gate's question as an ordinary question and wait for the answer.

**Outside Claude Code** (no `Workflow` tool): run this skill's workflow with the `workflow-runner:run-workflow` skill. If that skill is not installed, say so and stop. Use it instead of the command's inline fallback. First run `git -C '<repo>' fetch --prune` here, with escalated permissions on Codex: the workflow's workers cannot write `.git`, so they read the refs you fetched.
