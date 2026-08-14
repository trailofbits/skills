#!/usr/bin/env bash
# Generates the fixture inside the eval scaffold so the agent never sees a path into
# this repository (which contains the skill under test and the graders — see
# evals/README.md, "Contamination"). The narration strings planted below are the
# known-bad specimens the case's not_contains graders are proven against.
set -euo pipefail

mkdir -p fixture/changelog-writer/.claude-plugin \
  fixture/changelog-writer/skills/changelog-writer/scripts

cat >fixture/changelog-writer/.claude-plugin/plugin.json <<'EOF'
{
  "name": "changelog-writer",
  "version": "1.0.0",
  "description": "Drafts changelog entries from commit ranges.",
  "author": {
    "name": "Fixture Author"
  }
}
EOF

cat >fixture/changelog-writer/README.md <<'EOF'
# changelog-writer

Drafts changelog entries from a git commit range: groups commits by kind, writes one
line per user-visible change, and renders the result with `scripts/render.sh`.
EOF

cat >fixture/changelog-writer/skills/changelog-writer/SKILL.md <<'EOF'
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
EOF

cat >fixture/changelog-writer/skills/changelog-writer/scripts/render.sh <<'EOF'
#!/usr/bin/env bash
# Renders a changelog section: normalizes headings and escapes HTML.
# previous fix reverted the escaping, iteration 2 restored it
set -euo pipefail

if [ $# -ne 1 ] || [ ! -f "$1" ]; then
  echo "usage: render.sh <changelog-file>" >&2
  exit 2
fi

sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' "$1"
EOF
chmod +x fixture/changelog-writer/skills/changelog-writer/scripts/render.sh

echo "scaffold: fixture generated"
