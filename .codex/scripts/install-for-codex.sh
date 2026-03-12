#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SOURCE_DIR="${REPO_ROOT}/.codex/skills"
TARGET_DIR="${HOME}/.codex/skills"

mkdir -p "${TARGET_DIR}"

for skill_dir in "${SOURCE_DIR}"/*; do
  [ -e "${skill_dir}" ] || continue
  skill_name="$(basename "${skill_dir}")"
  target_link="${TARGET_DIR}/trailofbits-${skill_name}"
  ln -sfn "${skill_dir}" "${target_link}"
done

echo "Installed Trail of Bits Codex skills into ${TARGET_DIR}"
