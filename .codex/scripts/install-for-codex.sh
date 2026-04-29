#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SOURCE_DIR="${REPO_ROOT}/.codex/skills"
TARGET_DIR="${HOME}/.codex/skills"

mkdir -p "${TARGET_DIR}"

if [ ! -d "${SOURCE_DIR}" ]; then
  echo "ERROR: Source directory does not exist: ${SOURCE_DIR}" >&2
  echo "Ensure .codex/skills/ is present in the repository." >&2
  exit 1
fi

count=0
for skill_dir in "${SOURCE_DIR}"/*; do
  [ -e "${skill_dir}" ] || continue
  skill_name="$(basename "${skill_dir}")"
  target_link="${TARGET_DIR}/trailofbits-${skill_name}"
  ln -sfn "${skill_dir}" "${target_link}"
  count=$((count + 1))
done

if [ "${count}" -eq 0 ]; then
  echo "WARNING: No skills found in ${SOURCE_DIR}" >&2
  exit 1
fi
echo "Installed ${count} Trail of Bits Codex skills into ${TARGET_DIR}"
