---
max_turns: 50
timeout_seconds: 900
allowed_tools: [Read, Write, Bash, Glob, Grep, Skill]
---
/review-walkthrough:review-walkthrough

The working directory already holds a git repository with the changes to review on
a feature branch. If `.git` is missing or `git merge-base HEAD origin/main`
fails, the fixture was not built. Report that the runner needs `--scaffold` and
stop. Do **not** create a repository yourself:
a walkthrough of invented changes is worse than no walkthrough, because it scores
partial credit and hides the real problem.

Build a walkthrough of the changes on the current branch of the repository in
the working directory.

Two accommodations for this being a headless run:

- Write the finished walkthrough to `walkthrough.html` in the working directory,
  and do **not** run `open` on it. This run has no browser.
- This repository has no GitHub remote and no open pull request, so there is no
  PR metadata to collect. Do not call `gh`; treat the PR metadata as absent and
  carry on rather than stopping to ask.

Everything else about the skill applies unchanged. Produce the real artifact.
This run is checked by reading `walkthrough.html`, not by reading your summary,
so a description of what the walkthrough would contain scores zero.
