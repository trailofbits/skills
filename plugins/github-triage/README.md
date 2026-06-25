# github-triage

A Claude Code skill for triaging the open GitHub issues of a repository with the
`gh` CLI.

## What It Does

Runs against the current repository's open issues and:

- **Closes already-resolved issues** — when a merged PR or a commit on the default
  branch resolved the work but the issue was left open, it closes the issue with a
  comment that cites the resolving PR/commit.
- **Cross-links pending fixes** — when an open PR would resolve an issue, it ensures
  the issue and the PR reference each other (e.g. adding `Closes #N` to the PR body),
  filling only the links that are genuinely missing.
- **Scores everything outstanding** — assigns each remaining issue a **priority**
  (Critical / High / Medium / Low) and an estimated **change size** (`size/XS`–
  `size/XXL`, based on predicted changed lines using the Kubernetes/Prow thresholds).
  These are shown **locally only** and are never posted to GitHub.

All GitHub writes are batched and require your approval before anything runs, and you
can revise the proposed set before approving.

## Repository Selection

- A git repo with exactly **one** GitHub-hosted remote → used automatically.
- **Not** a git repo, or **no** GitHub remote → prompts for the `OWNER/REPO`.
- **Multiple** distinct GitHub repos among the remotes → prompts you to pick one.

## When to Use

Invoke with `/github-triage` to groom or review a repository's open issue backlog.

**Important**: This skill only runs when explicitly invoked. It never triages or
modifies issues proactively.

## Safety Features

- Single gated review of all proposed writes, with iteration before approval.
- Issues are closed only with concrete evidence (a merged PR or default-branch
  commit) and a comment that cites it; ambiguous cases are left open for review.
- Priority and change-size estimates are local planning aids, never written to GitHub.
- Large outstanding sets (> 32 issues) can be saved to a Markdown file (written to
  the current directory unless you specify a path) instead of flooding the terminal.

## Prerequisites

- [`gh`](https://cli.github.com/) installed and authenticated (`gh auth status`).
- `git` (for remote detection and default-branch / commit lookups).

## Installation

Add the Trail of Bits marketplace, then enable the plugin from the menu:

```
/plugin marketplace add trailofbits/skills
/plugin menu
```

Invoke it with `/github-triage`. The slash command *is* the skill — this plugin
ships no separate command file.

## Example

```
User: /github-triage

Claude: [Detects the single GitHub remote, lists open issues and PRs]
        ## Triage for acme/widget  (41 open issues)

        ### Proposed closes (already resolved) — WRITES to GitHub
        | Issue | Title             | Evidence       | Draft comment        |
        | #123  | Crash on empty in | merged PR #130 | "Resolved by #130 …" |

        ### Proposed cross-links (pending PR) — WRITES to GitHub
        | Issue | PR   | Gap                    | Proposed action          |
        | #140  | #145 | PR omits `Closes #140` | edit PR body to add ref  |

        ### Outstanding issues — LOCAL ONLY (37 issues)
        That's a large table — save to a Markdown file instead?

User: "Save it, and approve the closes but skip the #140 link for now."

Claude: [Closes #123 with the cited comment, skips the cross-link,
         writes github-triage-acme-widget-20260625.md]
        "Closed #123. Skipped the #140 ↔ #145 link. Saved 37 outstanding
         issues to github-triage-acme-widget-20260625.md."
```
