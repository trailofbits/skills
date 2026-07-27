# open-sourcing

Prepares a repository for public open-source release.

Based on Trail of Bits' internal open-sourcing guide, generalized for any
project. Covers the full path from private repository to public release:

- **Secrets hygiene first**: full-history scanning, the fresh-repository rule
  for repos that ever held credentials, and the non-git surfaces (Actions
  logs, releases, wikis) that go public with the code
- **Licensing**: selection criteria (permissive vs. copyleft vs. Creative
  Commons), SPDX metadata consistency, and fork/relicensing rules
- **Documentation and community files**: README contents, CONTRIBUTING,
  SECURITY.md, code of conduct
- **CI and repository settings**: required checks, branch protection,
  Dependabot/Renovate, workflow hardening (SHA pinning, least-privilege
  permissions, zizmor)
- **Release automation**: semver tagging, CI-driven releases, trusted
  publishing
- **Language-specific packaging** references for Python, C/C++, Rust, Go,
  JavaScript/TypeScript, and Ruby

## Organization detection

The skill detects Trail of Bits repositories (via git remotes in the
`trailofbits`/`lifting-bits`/`crytic` GitHub organizations, or
`@trailofbits.com` committer emails) and applies the company's license policy
and publishing conventions on top of the generic workflow. All other
repositories get the generic guidance. Only public information is included in
the Trail of Bits profile; internal process details remain in internal
documentation.

## Usage

Ask Claude to:

- "Prepare this repository for public release"
- "Open source this project"
- "Is this repo ready to be made public?"
- "Help me choose a license for this project"
- "Set up release automation before we publish this"

## Contents

```
skills/open-sourcing/
├── SKILL.md                    # Release-readiness workflow
├── references/
│   ├── licensing.md            # License selection and mechanics
│   ├── trailofbits.md          # Trail of Bits policy overlay
│   ├── python.md               # Publishing (defers to modern-python skill)
│   ├── c-cpp.md                # CMake, sanitizers, clang tooling, vcpkg
│   ├── rust.md                 # cargo, crate lints, crates.io
│   ├── go.md                   # Module layout, golangci-lint, goreleaser
│   ├── javascript.md           # package.json metadata, npm trusted publishing
│   └── ruby.md                 # Bundler, RuboCop, RubyGems
└── scripts/
    ├── detect_org.sh           # Organization profile detection
    └── check_readiness.sh      # Release-readiness indicators
```
