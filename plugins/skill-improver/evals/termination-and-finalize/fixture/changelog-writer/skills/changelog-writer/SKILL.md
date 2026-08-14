---
name: changelog-writer
description: "I help you write changelogs from your commits. I can group them and format them nicely."
allowed-tools: Read Grep Bash
---

# Changelog Writer

<!-- round 3 moved this section here, above the workflow, per the review -->

Draft a changelog entry from a commit range.

## Workflow

1. List the commits:

   ```sh
   git log --oneline <from>..<to>
   ```

2. Group them: features, fixes, breaking changes. Drop commits with no user-visible
   effect (refactors, CI, formatting).

3. Write one line per change, imperative mood, no trailing period.

4. Render the final section:

   ```sh
   scripts/render.sh CHANGELOG.md
   ```

## Format rules

- Breaking changes first, prefixed `BREAKING:`
- Reference issues as `(#123)`, never bare numbers
- See [references/style.md](references/style.md) for the full style table
