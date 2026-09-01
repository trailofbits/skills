---
name: review-pr
description: "Reviews the current branch's changes against its base branch as a pull request: correctness of new and modified code, test coverage for it, and documentation accuracy. Use when asked to review a branch, a diff, or a pull request."
allowed-tools: Read Grep Glob Bash
---

# PR Review

Review the branch's change surface, not the whole repository.

1. Establish the diff: `git diff <base>...HEAD` (and `git diff <base>` when the working
   tree carries uncommitted changes that belong to the branch). The base branch is named
   by the caller; fall back to `main`.
2. Review every changed hunk for correctness: wrong results on edge inputs, unhandled
   error paths, and behavior that contradicts the function's name or callers.
3. Check test coverage for the changed behavior: new logic without a test exercising its
   edge cases is a finding.
4. Check documentation the diff made stale: statements in README or docs that were true
   on the base branch and are false after the change.
5. Report every defect found, each with a severity; include minor and informational
   findings. Do not report defects in files the branch did not touch — they are outside
   the pull request.
