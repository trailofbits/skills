#!/usr/bin/env bash
# Run one c-review bench cell inside a hermetic container.
#
# Why this exists. A cell run on the host is not measuring the plugin: the 2026-08-07 sigil
# cell's own `"subtype":"init"` record shows 20 plugins and 48 skills reaching the driving
# session and all 8 subagents — including `c-review:c-review` itself and two other
# security-review skills (`concept-prover:*`, `contrarian:*`) — plus a foreign `SessionStart`
# hook from an unrelated plugin that actually executed four times and injected its stdout
# into the context. `--strict-mcp-config` closes the MCP surface and nothing else.
#
# The same probe inside this container reports 1 plugin, 18 skills (built-ins + c-review),
# no foreign hook, and a container-local memory path.
#
# Auth. The host authenticates through the macOS Keychain, which does not travel into a
# container, and no API key exists here. The OAuth access token is read out of the Keychain
# at launch and passed as CLAUDE_CODE_OAUTH_TOKEN. It is read fresh every run and never
# written to disk, because it expires — a stale copy in a file is a mid-cell failure that
# looks like a model error. If a run dies with "Not logged in", the token expired; re-run.
set -euo pipefail

IMAGE=${IMAGE:-creview-hermetic-proto:latest}
REPO=${REPO:-/Users/gros/ToB/tools/tob/skills}
DRIVER_DIR=${DRIVER_DIR:-/Users/gros/c-review-bench-runs/2026-08-06-guard}

usage() {
  cat >&2 <<EOF
usage: $0 --run <cell-dir> --tree <isolated-corpus-tree> [--arm c-review|fanout|bare|taxonomy]
          [--corpus sigil] [--variant bench] [--model sonnet]

  --run    host directory holding packets/ logs/ results/ (created if absent)
  --tree   host directory holding the isolated corpus copy; the cell writes
           .c-review-results/ inside it
  --arm    which arm to run. Every arm gets the SAME container and the same scoped
           plugin set, because an arm run on the host and an arm run hermetically are
           not comparable — the host session carries ~48 skills, including c-review's
           own, into every agent.

Both are bind-mounted read-write. The repo and driver are mounted read-only.
EOF
  exit 2
}

RUN='' TREE='' ARM=c-review CORPUS=sigil VARIANT=bench MODEL=sonnet
while [ $# -gt 0 ]; do
  case $1 in
    --run)
      RUN=$2
      shift 2
      ;;
    --tree)
      TREE=$2
      shift 2
      ;;
    --arm)
      ARM=$2
      shift 2
      ;;
    --corpus)
      CORPUS=$2
      shift 2
      ;;
    --variant)
      VARIANT=$2
      shift 2
      ;;
    --model)
      MODEL=$2
      shift 2
      ;;
    *) usage ;;
  esac
done
[ -n "$RUN" ] && [ -n "$TREE" ] || usage
[ -d "$TREE" ] || {
  echo "$0: --tree $TREE does not exist" >&2
  exit 1
}
case $ARM in
  c-review | fanout | bare | taxonomy) ;;
  *)
    echo "$0: unknown arm '$ARM'" >&2
    exit 2
    ;;
esac
mkdir -p "$RUN/logs" "$RUN/results"
[ -f "$RUN/packets/${ARM}__${CORPUS}__${VARIANT}.md" ] || {
  echo "$0: no packet at $RUN/packets/${ARM}__${CORPUS}__${VARIANT}.md" >&2
  exit 1
}

# Transcripts must land on a host mount: they outlive the container and the anti-cheat gate
# reads them. Mount only projects/, never all of ~/.claude — the rest of that directory in
# the image is where the scoped plugin install lives, and shadowing it with the host's would
# reintroduce exactly the pollution this script exists to remove.
TRANSCRIPTS="$RUN/transcripts"
mkdir -p "$TRANSCRIPTS"

TOKEN=$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null |
  jq -r '.claudeAiOauth.accessToken')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || {
  echo "$0: no OAuth access token in the Keychain item 'Claude Code-credentials'." >&2
  echo "     Log in on the host first, or export CLAUDE_CODE_OAUTH_TOKEN yourself." >&2
  exit 1
}

EXP=$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null |
  jq -r '.claudeAiOauth.expiresAt // 0')
NOW=$(($(date +%s) * 1000))
if [ "$EXP" -gt 0 ] && [ "$EXP" -lt $((NOW + 3600000)) ]; then
  echo "$0: WARNING: the OAuth token expires in under an hour. A cell takes 30-100 min." >&2
  echo "     Refresh it on the host (run any claude command) before starting." >&2
fi

echo "cell: $ARM/$CORPUS/$VARIANT  model=$MODEL"
echo "  tree=$TREE"
echo "  run=$RUN"

# `drive.py`'s non-c-review arms hardcode the corpus tree as
# /Users/gros/.cache/c-review-bench/work/<corpus>/<variant>. Rather than fork the driver
# mid-measurement, mount the isolated tree at exactly that path inside the container as
# well as at /corpus. Both names then point at the same isolated copy, so whichever the
# driver reaches for, it cannot touch the shared cache on the host.
LEGACY_TREE="/Users/gros/.cache/c-review-bench/work/$CORPUS/$VARIANT"

# `drive.py` has no --settings flag, so the guard hooks cannot be passed to it that way.
# They are installed as the container's own ~/.claude/settings.json instead, which every
# arm picks up without a flag — and which is the only way a fanout or bare cell gets the
# network guard at all. `creview_run.py` is still handed the file explicitly because it
# supports it and being explicit there costs nothing.
if [ "$ARM" = "c-review" ]; then
  DRIVER_CMD="uv run --no-project --python 3.11 python creview_run.py \
    --run /cell --corpus '$CORPUS' --variant '$VARIANT' --model '$MODEL' \
    --tree /corpus --settings /tmp/hs.json"
else
  DRIVER_CMD="uv run --no-project --python 3.11 python drive.py $ARM \
    --run /cell --arm '$ARM' --corpus '$CORPUS' --variant '$VARIANT' --model '$MODEL'"
fi

exec docker run --rm -i \
  -e CLAUDE_CODE_OAUTH_TOKEN="$TOKEN" \
  -e CREVIEW_GUARD_LOG=/cell/guard-blocks.log \
  -v "$REPO":/workspace/skills-repo:ro \
  -v "$DRIVER_DIR":/opt/driver:ro \
  -v "$TREE":/corpus \
  -v "$TREE":"$LEGACY_TREE" \
  -v "$RUN":/cell \
  -v "$TRANSCRIPTS":/home/hermetic/.claude/projects \
  "$IMAGE" bash -lc "
set -euo pipefail
cp /workspace/skills-repo/tools/c-review-bench/devcontainer/hermetic-settings.json /tmp/hs.json
mkdir -p /home/hermetic/.claude
cp /tmp/hs.json /home/hermetic/.claude/settings.json
claude plugin marketplace add /workspace/skills-repo >/dev/null
claude plugin install c-review@trailofbits >/dev/null
# Refuse to run if the scoping did not take: a cell with the host's plugin set is the
# measurement this whole script exists to avoid, and it is invisible once collected.
# Note this holds for EVERY arm, not just c-review — a fanout or bare cell that could see
# c-review's own skill is not measuring undirected review.
n=\$(claude plugin list 2>/dev/null | grep -c '@' || true)
if [ \"\$n\" -ne 1 ]; then
  echo \"run-cell: expected exactly 1 installed plugin, got \$n\" >&2
  claude plugin list >&2
  exit 1
fi
cd /opt/driver
exec $DRIVER_CMD
"
