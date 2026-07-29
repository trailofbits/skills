#!/usr/bin/env bash
# Reports release-readiness indicators for the current repository.
# Informational only: an unchecked item is a discussion prompt, not a
# hard failure. Run from the repository root.
# -e is intentionally omitted: check commands are expected to fail.
set -uo pipefail

exists_any() {
  local f
  for f in "$@"; do
    [ -e "$f" ] && return 0
  done
  return 1
}

check() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf '  [x] %s\n' "$label"
  else
    printf '  [ ] %s\n' "$label"
  fi
}

has_ci_workflows() {
  exists_any .github/workflows/*.yml .github/workflows/*.yaml
}

has_dependency_updates() {
  exists_any .github/dependabot.yml .github/dependabot.yaml \
    renovate.json renovate.json5 .github/renovate.json .github/renovate.json5
}

has_tests() {
  exists_any tests test spec ||
    git ls-files 2>/dev/null | grep -E '(_test\.(go|py|rb)$|\.test\.(ts|js|tsx|jsx)$|_spec\.rb$)' >/dev/null
}

has_semver_tags() {
  git tag --list 'v[0-9]*' 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+' >/dev/null
}

list_suspicious_files() {
  git ls-files 2>/dev/null |
    grep -iE '(^|/)(\.env(\..+)?|.*\.pem|.*\.p12|.*\.pfx|.*\.keystore|id_(rsa|dsa|ecdsa|ed25519).*|.*credentials.*\.(json|xml|yml|yaml))$' |
    grep -vE '\.(example|sample|template)(\.|$)'
}

main() {
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: not inside a git repository" >&2
    exit 1
  fi

  echo "Release-readiness indicators:"
  check "README" exists_any README.md README.rst README.txt README
  check "LICENSE" exists_any LICENSE LICENSE.md LICENSE.txt COPYING COPYING.md
  check "CONTRIBUTING" exists_any CONTRIBUTING.md CONTRIBUTING.rst .github/CONTRIBUTING.md
  check "SECURITY policy" exists_any SECURITY.md .github/SECURITY.md
  check "Code of conduct" exists_any CODE_OF_CONDUCT.md .github/CODE_OF_CONDUCT.md
  check ".gitignore" exists_any .gitignore
  check ".editorconfig" exists_any .editorconfig
  check "CI workflows" has_ci_workflows
  check "Automated dependency updates (Dependabot/Renovate)" has_dependency_updates
  check "Tests" has_tests
  check "Semver release tags (vX.Y.Z)" has_semver_tags

  local suspicious
  suspicious=$(list_suspicious_files)
  if [ -n "${suspicious}" ]; then
    echo
    echo "WARNING: tracked files that commonly contain secrets:"
    printf '%s\n' "${suspicious}" | sed 's/^/  - /'
    echo "Review these (and full history) before making the repository public."
  fi
}

main "$@"
