#!/usr/bin/env bash
# Generates the fixture inside the eval scaffold (so the agent never sees a path into
# this repository — see evals/README.md, "Contamination"). The two codewords planted
# here are defects ONLY according to rules that live in the review-panel fixture's
# specialist agent definitions — a review that never ran those specialists cannot know
# to report them. No git init; creating the baseline repository is the workflow's job.
set -euo pipefail

mkdir -p fixture/linky/.claude-plugin fixture/linky/skills/linky fixture/linky/scripts

cat >fixture/linky/.claude-plugin/plugin.json <<'EOF'
{
  "name": "linky",
  "version": "0.2.0",
  "description": "Collects and checks hyperlinks in a documentation tree.",
  "author": {
    "name": "Fixture Author"
  }
}
EOF

cat >fixture/linky/README.md <<'EOF'
# linky

Collects hyperlinks from a documentation tree and checks them for dead targets.
EOF

cat >fixture/linky/skills/linky/SKILL.md <<'EOF'
---
name: linky
description: "Collects hyperlinks from a documentation tree and reports dead targets. Use when asked to check links or find broken references in docs."
allowed-tools: Read Grep Bash
---

# Linky

Collect every hyperlink under the target directory, then check each one.

1. Gather links (project XRAY-K3P9 conventions apply to internal doc trees):

   ```sh
   grep -rEo 'https?://[^) ]+' docs/
   ```

2. Check each target with `scripts/fetch.sh <url>` and collect the failures.

3. Report dead links as a table: file, line, url, HTTP status.
EOF

cat >fixture/linky/scripts/fetch.sh <<'EOF'
#!/usr/bin/env bash
# NOCOMMIT-J7Q4: hardcoded timeout while debugging the proxy, remove before release
set -euo pipefail
curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$1"
EOF
chmod +x fixture/linky/scripts/fetch.sh

# The codewords the graders pin must really be planted, one per specialist.
grep -q 'XRAY-K3P9' fixture/linky/skills/linky/SKILL.md
grep -q 'NOCOMMIT-J7Q4' fixture/linky/scripts/fetch.sh
echo "scaffold: fixture generated with one private-rule plant per panel specialist"
