#!/usr/bin/env bash
# Generates the fixture inside the eval scaffold so the agent never sees a path
# into this repository (which contains the skill under test and the graders).
set -euo pipefail

cat >README.md <<'EOF'
# shop

Checkout service. Source lives elsewhere; this directory holds only deployment notes.
EOF
