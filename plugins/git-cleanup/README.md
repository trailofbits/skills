# git-cleanup

A Claude Code slash command for safely cleaning up accumulated git worktrees and local branches.

## What It Does

Analyzes your local git repository and sorts branches and worktrees into:

- **Delete candidates**: merged into the default branch (`-d`), or squash-merged or superseded with a named PR or commit as evidence (`-D`)
- **Needs review**: work that could not be located in the default branch, including `[gone]` remotes and any candidate a skeptic managed to refute
- **Keep**: unpushed commits, untracked local work, or level with a live remote
- **Unanalyzed**: branches no verdict came back for, listed explicitly so a partial run never reads as a complete one

The command is gated: it requires explicit user confirmation before any deletion.

## How It Works

Analysis runs as a [dynamic workflow](workflows/analyze-branches.js) — a JavaScript orchestration script that coordinates subagents:

1. **Survey** — one agent inventories branches, worktrees, tracking state, and recent merge history.
2. **Triage** — the script decides, in plain JavaScript, everything git can already prove: merged branches, branches with unpushed commits, branches level with a live remote. No agent is spawned for a question `git branch --merged` already answers.
3. **Investigate** — batched agents hunt for merge evidence on the branches that remain ambiguous, mostly `[gone]` remotes and groups of similarly-named branches. Related branches go to one agent so supersession is visible.
4. **Refute** — every delete candidate goes to a skeptic whose job is to find a commit that is *not* in the default branch. A refuted candidate is downgraded to "needs review", never deleted.

Typical runs are small: a repo with a dozen branches spawns about three agents, because the triage in step 2 decides most of them without spawning anything. Eleven is the ceiling, not the norm — one survey, at most five investigators, at most five skeptics — and past five batches the batches grow rather than the agent count, so the number stops rising even as the repository gets messier. Tokens still scale with the number of ambiguous branches; it is the coordination cost that is capped, not the reading.

The workflow is strictly read-only. Both confirmation gates and every `git branch -d/-D` and `git worktree remove` run in the main session, because subagents have no way to ask the user anything.

## When to Use

Invoke with `/git-cleanup` when you have accumulated many local branches and worktrees that need cleanup.

**Important**: the command sets `disable-model-invocation: true`, so Claude cannot invoke it on its own — it runs only when you type it. That flag is what closes autonomous invocation; the `description` in the frontmatter is matchable text and would otherwise let a cleanup-shaped request trigger a plugin whose job is `git branch -D`.

## Safety Features

- Two confirmation gates (analysis review, then deletion confirmation), both in the main session
- Safe delete (`git branch -d`) for branches git itself reports as merged; force delete (`git branch -D`) only for squash-merged and superseded branches, where git compares shas and cannot see that a squash carried the work across
- Every squash-merged or superseded candidate must survive a skeptic tasked with finding a commit the claim cannot account for — tested against whatever the claim named, the default branch for a PR or commit and the superseding branch for a supersession. Refuted, unverified, missing a verdict, and lost-to-a-failed-agent all fall back to needs-review. `SAFE_TO_DELETE` is the one category that skips this. It does not rest on `git branch -d` catching a mistake at execution time: `-d` accepts a branch merged into `HEAD` or into its own upstream, neither of which is "merged into the default branch". Instead each entry names its tip commit in its evidence, for a human to check at gate 1, and ships a `verifyWith` precondition — `git merge-base --is-ancestor 'refs/heads/<branch>' '<default>'` — which the main session runs immediately before the delete and skips the delete on failure. The precondition names the branch rather than the reported sha, so it cannot pass on a stale or transposed commit while the branch itself was never merged. The category is still pinned to `-d` and never `-D`
- A `[gone]` remote is treated as a question, not an answer: the branch is investigated, and it only becomes a delete candidate once a specific PR or commit is named and that claim survives refutation
- Blocks removal of worktrees with uncommitted changes
- Never touches the current branch, the repository's actual default branch whatever it is called, or any long-lived integration or environment branch — `main`, `master`, `trunk`, `develop`, `dev`, `integration`, `staging`, `production`, `preprod`, `qa`, `uat`, `next`, `canary`, `stable` and `release/*`, `hotfix/*`, `support/*`, `maint*/*` among them, matched case-insensitively. Filtered by a regex in the script, not by instructions to a model: an agent can be talked out of a rule, a regex cannot
- Protected branches are excluded from analysis but **not** from the report: they come back under `keep` as `PROTECTED`, carrying their unpushed-commit count. Never deletable and never mentioned are different guarantees, and only the first one is wanted — a `staging` branch with unpushed work on it has to stay visible

## Installation

```bash
claude plugins:add trailofbits/skills/git-cleanup
```

## Layout

| Path | Role |
|------|------|
| `commands/git-cleanup.md` | The `/git-cleanup` entry point: gates, confirmations, and the deletions |
| `workflows/analyze-branches.js` | The dynamic workflow, shipping as `/git-cleanup:git-cleanup-analysis` — workflows are namespaced by `meta.name`, not the filename. Read-only — it never deletes |
| `references/merge-evidence.md` | What counts as proof a branch is merged, read by the agents and the fallback path |
| `tests/analyze-branches.test.mjs` | Stubs every agent and asserts the triage, clustering, and failure handling |
| `evals/` | End-to-end evals: does the model produce a correct gate-1 analysis on a real repository? |

The suite runs in CI and under `make check` via the `js-tests` target, which fails if it discovers no `*.test.mjs` files. To run just this one:

```bash
node plugins/git-cleanup/tests/analyze-branches.test.mjs
```

## Tests vs evals

The two cover different halves, and neither substitutes for the other:

- **`tests/`** stubs every agent and asserts the JavaScript in `analyze-branches.js` — triage, clustering, protected-branch filtering, failure handling. Deterministic, free, and blind to what the model actually does with the result.
- **`evals/`** runs the real model against a real repository and grades the gate-1 analysis: does unpushed work stay in Keep, does every delete candidate name its evidence, does anything get deleted before the user answers. See [evals/README.md](evals/README.md).

```bash
make eval-self-tests  # free; proves the graders still fire. Part of `make check`
make evals           # the real suite — costs API calls, opt-in only
```

## Example

```
User: /git-cleanup

Claude: [Runs the workflow: survey, then investigates 4 ambiguous branches,
         then refutes 3 delete candidates]

        GATE 1 — analysis

        Safe to delete (merged, -d)
        | fix/typo      | merged into main                                |

        Safe to delete (squash-merged / superseded, -D)
        | feature/auth  | PR #42, no unaccounted commits                  |
        | feature/api   | PR #29, no unaccounted commits                  |

        Needs review
        | bugfix/login  | claimed PR #51, refuted: commit 9ab2c1e missing  |
        | experiment/x  | remote gone, work not found in main             |

        Keep
        | wip/parser    | 5 unpushed commits                              |

        Worktrees
        | ../proj-auth  | feature/auth | STALE (merged)                   |

        Which would you like to clean up?
        [Delete all recommended] [Pick categories] [Pick individual branches]

User: [Delete all recommended]

Claude: GATE 2 — I will execute:

        # Worktrees holding branches being deleted (must come first)
        git worktree remove '../proj-auth'

        # Merged (safe delete, each guarded by its verifyWith precondition)
        git merge-base --is-ancestor 'refs/heads/fix/typo' 'main' && git branch -d 'fix/typo'

        # Squash-merged and superseded (force delete)
        git branch -D 'feature/auth'
        git branch -D 'feature/api'

        Confirm? (yes/no)

User: "yes"

Claude: Deleted fix/typo, feature/auth, feature/api, worktree ../proj-auth.
        Kept wip/parser. bugfix/login and experiment/x still need review.
```

Three things in that transcript are load-bearing: every delete candidate arrives with its evidence attached so you can audit it, `bugfix/login` was demoted because a skeptic found a commit its merge claim could not account for, and gate 2 lists exact commands with the flag each branch actually needs rather than a list of names.
