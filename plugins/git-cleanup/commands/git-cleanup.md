---
description: "Safely analyzes and cleans up local git branches and worktrees, categorizing them as merged, squash-merged, superseded, or active work before deleting anything."
argument-hint: "[repo-path]"
disable-model-invocation: true
allowed-tools: Bash Read AskUserQuestion Workflow
---

# Git Cleanup

Clean up accumulated git worktrees and local branches. A dynamic workflow gathers the evidence in parallel and tries to disprove its own delete recommendations; you keep the two safety gates and run the deletions yourself.

Repository: `$ARGUMENTS` — when empty, use the current working directory.

## Core Principle: SAFETY FIRST

**Never delete anything without explicit user confirmation.**

The split between the workflow and this session is the safety property, not an implementation detail:

| Runs in the workflow (subagents) | Runs here (main session) |
|----------------------------------|--------------------------|
| Read-only inspection of git state | Both user gates |
| Merge-evidence investigation | Every `git branch -d/-D` |
| Refutation of delete candidates | Every `git worktree remove` |

Workflow agents run in the background with no way to reach the user. Nothing destructive may move into the script — if it did, deletions would happen while the user was still being asked about them.

## Phase 1: Run the Analysis Workflow

`${CLAUDE_PLUGIN_ROOT}` is set in the Bash tool's environment, not in this prompt's text — nothing expands it for you here. **Resolve it first**, in the same call that finds the repo root:

```bash
echo "$CLAUDE_PLUGIN_ROOT"
git rev-parse --show-toplevel
```

Then call the `Workflow` tool with `scriptPath` set to `<that plugin root>/workflows/analyze-branches.js` and this as `args`, both values substituted rather than passed as the literal `${CLAUDE_PLUGIN_ROOT}`:

```json
{ "repoPath": "<absolute path to the repo>", "pluginDir": "<that plugin root>" }
```

This command being invoked is the opt-in that workflow needs.

It runs three phases — survey, investigate, refute — and returns:

| Field | Meaning |
|-------|---------|
| `deleteCandidates` | Recommended deletions. Each carries `evidence`, the exact `command` (`-d` or `-D`), `worktreePath` when a worktree holds the branch, `group` for related-branch display, and `verifyWith` on `SAFE_TO_DELETE` entries. |
| `needsReview` | Remote gone, work not found in the default branch. Never recommend these. |
| `keep` | Unpushed, local-only, or synced with a live remote — plus `PROTECTED` entries, excluded from analysis but still reported. |
| `worktrees` | Path, branch, `dirty`, `dirtyFiles`, and whether the branch is stale. |
| `unanalyzed` | Branches no verdict came back for. **Must be shown to the user.** |

**Exit criteria:** you hold a result object, or the workflow threw.

If it throws with "survey returned zero local branches", the inventory failed — say so and stop. Do not report a clean repository.

If it throws about an unreadable `scriptPath`, the path did not resolve — most likely `$CLAUDE_PLUGIN_ROOT` was empty or reached the tool unexpanded. Check what the `echo` above printed, and if there is no usable plugin root, take the inline fallback below rather than aborting the run.

**Fallback.** If the `Workflow` tool is unavailable, do the same analysis inline: read [merge-evidence.md](../references/merge-evidence.md), gather the state below, and apply the decision table in [Phase 2](#phase-2-check-the-workflows-work). It is slower and the refutation pass is on you, but the categories and the gates are identical.

```bash
# Assign, then default with ${:-}. Do not fall back with `... | sed ... || echo main`:
# a pipeline's status is the last command's, sed succeeds on empty input, so the ||
# never fires and default_branch ends up empty — every command below then silently
# operates on "".
default_branch=$(git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null)
default_branch="${default_branch#origin/}"
default_branch="${default_branch:-main}"
git fetch --prune
git branch -vv                        # tracking info and [gone] markers
git branch --merged "$default_branch"
git worktree list --porcelain
git log --oneline "$default_branch" | grep -iE "#[0-9]+" | head -40
```

## Phase 2: Check the Workflow's Work

The workflow reports evidence so you can audit it, not so you can forward it unread. Before building the gate-1 table:

1. **Every `deleteCandidate` names specific evidence** — a PR number, a commit sha, or a superseding branch. "Similar name", "looks stale", or an empty evidence string is not a delete recommendation. Move it to needs-review. `SAFE_TO_DELETE` entries satisfy this by naming the tip commit; they also carry `verifyWith`, which phase 3 runs before deleting.
2. **No protected branch is a delete candidate.** The script filters long-lived integration and environment names (`main`, `master`, `develop`, `dev`, `staging`, `production`, `qa`, `uat`, `release/*`, `hotfix/*`, and similar), plus the repository's actual default branch and the current branch, programmatically. They do still appear — under `keep` with category `PROTECTED`, and with their unpushed count when they have one. That is deliberate: excluded from analysis is not the same as absent from the report, and a `staging` branch carrying unpushed commits must not vanish. If one reaches `deleteCandidates` or `needsReview` regardless, drop it and say so.
3. **`unanalyzed` is empty, or you list it.** A partial run must not read as a complete one.
4. **Dirty worktrees are flagged**, whatever their branch's category.

The categories, and what has to be true for each:

| Category | Meaning | Delete Command |
|----------|---------|----------------|
| SAFE_TO_DELETE | Reported by `git branch --merged`, re-checked by `verifyWith` at execution | `git branch -d` |
| SQUASH_MERGED | Work incorporated via squash merge, PR or commit named | `git branch -D` |
| SUPERSEDED | Work verified in main via PR, or contained in a named newer branch | `git branch -D` |
| REMOTE_GONE | Remote deleted, work NOT found in main | Review needed |
| UNPUSHED_WORK | Has commits not pushed to remote | Keep |
| LOCAL_WORK | Untracked branch with unique commits | Keep |
| SYNCED_WITH_REMOTE | Up to date with a live remote | Keep |

`git branch -d` will ALWAYS fail for a squash-merged branch, because git compares shas and the squash produced a new one. Plan `-D` from the start for SQUASH_MERGED and SUPERSEDED; never try `-d` first and then return to the user for a second confirmation.

**Exit criteria:** every candidate has evidence you have read, and the review and keep lists are populated.

## GATE 1: Present Complete Analysis

Present everything in ONE view, related branches together:

```markdown
## Git Cleanup Analysis

### Related Branch Group: feature/api-*
| Branch | Status | Evidence |
|--------|--------|----------|
| feature/api | Superseded | Work merged in PR #29, no unaccounted commits |
| feature/api-v2 | Superseded | Work merged in PR #45, no unaccounted commits |

### Safe to Delete (merged, `-d`)
| Branch | Merged Into |
|--------|-------------|
| fix/typo | main |

### Safe to Delete (squash-merged, `-D`)
| Branch | Merged As |
|--------|-----------|
| feature/login | PR #42 |

### Needs Review (remote gone, work not found)
| Branch | Last Commit | Why |
|--------|-------------|-----|
| experiment/old | abc1234 "WIP something" | 3 commits not found in main |

### Keep (active work)
| Branch | Status |
|--------|--------|
| wip/new-feature | 5 unpushed commits |

### Worktrees
| Path | Branch | Status |
|------|--------|--------|
| ../proj-auth | feature/auth | STALE (merged) |

**Summary:** 2 superseded, 1 merged, 1 squash-merged, 1 needs review, 1 to keep.
```

Warn prominently and separately about any dirty worktree:

```markdown
WARNING: ../proj-auth has uncommitted changes:
  M  src/auth.js
  ?? new-file.txt

These changes will be LOST if you remove this worktree.
```

Then use AskUserQuestion with options along the lines of:

- Delete all recommended (groups + merged + squash-merged)
- Delete specific groups or categories
- Let me pick individual branches

**Exit criteria:** the user answered. Do not proceed on silence, and do not treat "clean it up" as an answer to which branches.

## GATE 2: Final Confirmation with Exact Commands

Show the exact commands, with the flags you will actually use:

**Worktrees come first.** A branch that is checked out in a worktree cannot be deleted — git refuses with "used by worktree at …" — so removing the worktree has to precede deleting its branch, or the branch delete fails for exactly the case the analysis flagged. Each `deleteCandidate` carries `worktreePath`; order the commands from that.

```markdown
I will execute:

# Worktrees holding branches being deleted (must precede the branch delete)
git worktree remove '../proj-auth'

# Merged branches (safe delete, each guarded by its verifyWith precondition)
git merge-base --is-ancestor 'refs/heads/fix/typo' 'main' && git branch -d 'fix/typo'

# Squash-merged and superseded (force delete — work is in main via PRs)
git branch -D 'feature/auth'
git branch -D 'feature/login'
git branch -D 'feature/api'

Confirm? (yes/no)
```

This is the ONLY confirmation needed for deletion. Do not add a third gate because `-D` is involved — that was decided at gate 1.

A worktree with uncommitted changes is refused here, not confirmed. Removing it requires the user to explicitly acknowledge the data loss for that specific worktree.

**Exit criteria:** an explicit yes.

## Phase 3: Execute and Report

Run each deletion as a **separate** Bash command so one failure does not block the rest. Report each result; on failure, report the error and continue.

**Single-quote every branch name and worktree path.** Git's refname rules forbid spaces but permit `$`, backticks, `;`, `|`, and `&`, so `$(id)` and `` `id` `` are legal branch names. These names arrive from the workflow's JSON and go straight into a shell: unquoted, `git branch -D $(id)` runs the substitution before git ever sees the argument. Single quotes, not double — `"$(id)"` still substitutes.

Keep the gate-2 order: every `git worktree remove` runs before the `git branch` delete for the branch that worktree holds.

```bash
git worktree remove '../proj-auth'
git merge-base --is-ancestor 'refs/heads/fix/typo' 'main' && git branch -d 'fix/typo'
git branch -D 'feature/auth'
```

**Run each `SAFE_TO_DELETE` candidate's `verifyWith` immediately before its delete, and skip the delete if it fails.** That category is the one that never went through the refutation pass, and `git branch -d` is not the backstop it looks like: it accepts a branch merged into `HEAD` *or* into its own upstream, so a branch level with its remote but never merged to the default branch deletes cleanly under `-d`. `verifyWith` tests the property actually being claimed — `git merge-base --is-ancestor 'refs/heads/<branch>' '<default>'`, naming the branch rather than the sha the survey reported, so it cannot pass on a row the survey joined wrongly. Run it as given rather than rebuilding it; it is already single-quoted for refnames that contain `$(...)`, backticks or `'`. If it fails, report the branch as needing review instead of deleting it.

If a branch name itself contains a single quote, end the quoting around it: `'wip/it'\''s'`.

If a branch delete still fails with "used by worktree at …", the branch is checked out somewhere the analysis did not report. Report it and move on — do not remove that worktree without taking it back to the user, since it was never covered by the gate-2 confirmation.

Then report what happened:

```markdown
## Cleanup Complete

### Deleted
- fix/typo, feature/login
- Worktree: ../proj-auth

### Failed
- feature/api — worktree ../api still checked out

### Remaining
| Branch | Status |
|--------|--------|
| main | current |
| wip/new-feature | active work |
| experiment/old | needs review |
```

**Exit criteria:** every command from gate 2 is accounted for as deleted or failed.

## Safety Rules

1. **Two confirmation gates only** — analysis review, then deletion confirmation
2. **Deletions run here, never in the workflow** — subagents cannot ask the user anything
3. **Use the right flag** — `-d` for merged, `-D` for squash-merged and superseded
4. **Never touch protected branches** — main, master, develop, release/*, the repository's actual default branch whatever it is named, and the current branch (all filtered programmatically)
5. **Single-quote every branch name and path** in a shell command — branch names may legally contain `$`, backticks, and `;`
6. **Block dirty worktree removal** — refuse without explicit data-loss acknowledgment
7. **Surface `unanalyzed`** — a partial analysis must never be presented as a complete one

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "The workflow said delete, so it's verified" | The workflow reports evidence for you to check. A verdict with no PR, sha, or superseding branch named is a guess wearing a category label. |
| "The branch is old, it's probably safe to delete" | Age doesn't indicate merge status. Old branches may contain unmerged work. |
| "I can recover from reflog if needed" | Reflog entries expire, and worktree removal takes uncommitted changes with it. Don't rely on it as a safety net. |
| "It's just a local branch, nothing important" | Local branches may contain the only copy of work not pushed anywhere. |
| "The PR was merged, so the branch is safe" | Squash merges don't preserve branch history. Verify the *specific* commits were incorporated. |
| "I'll just delete all the `[gone]` branches" | `[gone]` only means the remote was deleted. The local branch may have unpushed commits. |
| "The user seems to want everything deleted" | Always present analysis first. Let the user choose what to delete. |
| "The branch has commits not in main, so it has unpushed work" | "Not in main" is not "not pushed". A branch can be synced with its remote but not merged to main. Check `git log origin/<branch>..<branch>`. |
| "A few branches failed to analyze, the rest is the answer" | An unanalyzed branch is an unknown, and the user reads an unqualified list as complete. |

## Reference Index

| File | Content |
|------|---------|
| [analyze-branches.js](../workflows/analyze-branches.js) | The dynamic workflow: survey, investigate, refute. Read-only. |
| [merge-evidence.md](../references/merge-evidence.md) | What counts as proof a branch is merged, and what doesn't |
