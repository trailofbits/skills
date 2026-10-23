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

## Calcifier recipe for `open-sourcing`

The [`open-sourcing` Python recipe](skills/open-sourcing/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/open-sourcing/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/open-sourcing/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `project_directory` | `str` | Required |
| `validation_directory` | `str` | Required |
| `request` | `str` | Required |
| `confidentiality_history` | `str` | Required |
| `external_audit_evidence` | `str` | `''` |
| `scope` | `Literal['public-repository', 'private-package']` | `'public-repository'` |
| `organization` | `Literal['auto', 'generic', 'trailofbits']` | `'auto'` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
