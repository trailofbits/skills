# Merge Evidence Standard

What counts as proof that a branch's work is already in the default branch, and what does not.
The workflow's investigator and refuter agents both read this file; the command's inline fallback path follows the same standard.

## The asymmetry that sets the bar

A wrong "keep" costs the user one more look at a branch list.
A wrong "delete" costs them work that exists in no other place.
Every rule below is calibrated to that: when the evidence is thin, the answer is `REMOTE_GONE` (needs review), never a delete recommendation.

## Evidence by category

| Category | Accepted evidence | Delete command |
|----------|-------------------|----------------|
| `SAFE_TO_DELETE` | The branch appears in `git branch --merged <default>`. Report the tip commit alongside it: this is the one category that skips refutation, so the main session re-checks it with `git merge-base --is-ancestor` before deleting, and `git branch -d` is not itself that check — it also accepts a branch merged only into `HEAD` or into its own upstream. | `git branch -d` |
| `SQUASH_MERGED` | A named commit or PR number in the default branch whose diff carries this branch's changes. | `git branch -D` |
| `SUPERSEDED` | Either a named PR that merged the work, or a named newer branch that contains every commit of the older one. | `git branch -D` |
| `REMOTE_GONE` | The upstream is `[gone]` and the work was not located in the default branch. | none — review |
| `UNPUSHED_WORK` | `git log <upstream>..<branch>` is non-empty. | none — keep |
| `LOCAL_WORK` | Untracked branch holding commits that exist nowhere else. | none — keep |
| `SYNCED_WITH_REMOTE` | Level with a live upstream. Nothing local to clean. | none — keep |

## Commands that produce the evidence

**Wrap every branch name in SINGLE quotes.** Git's refname rules reject a space and little else — `evil$(id)`, ``evil`id` ``, `has'quote`, `a;b`, and `a|b` are all legal branch names. You are pasting literal names into commands, not expanding a shell variable, and double quotes still run `$(...)` and backticks. For a name containing a single quote, close and reopen around it: `'has'\''quote'`.

The examples below use `"$branch"` because they read a shell variable you control. That is not the case you are in.

```bash
# What this branch has that the default branch does not, by commit
git log --oneline "$default".."$branch"

# The same question, but tolerant of squash and rebase: compares patch content,
# not sha. Lines starting with + are commits with no equivalent in $default.
git cherry -v "$default" "$branch"
git log --cherry-pick --right-only --oneline "$default"..."$branch"

# Find the PR that absorbed the work: search default-branch subjects for the
# branch name, a distinctive commit subject, and PR numbers
git log --oneline "$default" | grep -iE "(branch-name|distinctive-keyword|#[0-9]+)"

# Confirm a candidate PR really carries the change
git show --stat <merge-sha>

# Does a newer sibling contain the older branch entirely?
git merge-base --is-ancestor "$older" "$newer" && echo contained
```

## What is not evidence

| Not evidence | Why |
|--------------|-----|
| A shared name prefix | `feature/api` and `feature/api-v2` can hold unrelated work that merely started from the same idea. Prefix selects branches to compare; it never concludes the comparison. |
| The branch is old | Age is orthogonal to merge status. The oldest branch in a repo is often the one nobody finished. |
| The upstream is `[gone]` | `[gone]` means someone deleted the remote branch. It says nothing about whether the commits landed, and nothing about unpushed local commits. |
| A PR with a matching title | Titles get reused across attempts. Check the diff, not the subject line. |
| `git branch -d` refusing to delete | This is the expected outcome for a squash-merged branch — git compares shas, and a squash produced a new one. Refusal is not proof of unmerged work, and success is not the only proof of merged work. |
| "It's recoverable from reflog" | Reflog entries expire, and worktree removal takes uncommitted changes with it. Recovery is not a substitute for evidence. |

## Squash merges specifically

The common case: a branch was pushed, its PR was squash-merged, and the remote branch was deleted.
The local branch now has commits that are absent from the default branch *by sha* while their content is fully present.

`git log <default>..<branch>` shows those commits and proves nothing.
`git cherry -v` compares patch IDs and is the tool that distinguishes "content already merged" from "content still only here".
A `+` line from `git cherry` is a commit whose content was not found — investigate it individually before recommending deletion.
