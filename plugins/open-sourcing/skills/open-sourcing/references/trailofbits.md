# Trail of Bits Profile

Apply this guidance **in addition to** the generic workflow when
`scripts/detect_org.sh` prints `trailofbits`. Everything in this file is
public information; internal process details (credentials, announcement
workflow, release sign-off) live in Trail of Bits' internal documentation,
which the maintainer should consult directly.

## License policy

- **Default to [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)**
  for nearly all projects.
- **Use [AGPLv3](https://www.gnu.org/licenses/agpl-3.0.en.html)** when the
  project would offer a significant advantage to competitors who modify it
  without contributing changes back.
- **Use Creative Commons for non-code work:**
  - [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)
    for rulesets (e.g., [semgrep-rules](https://github.com/trailofbits/semgrep-rules))
  - [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) for
    publications and informational material (e.g.,
    [publications](https://github.com/trailofbits/publications))
- When in doubt, confirm with the project manager or an existing open-source
  maintainer before publishing.

Copyright line convention (current year only, no ranges):

```
Copyright (c) 2026 Trail of Bits <opensource@trailofbits.com>
```

For forks and adopted projects, add this line under the existing copyright
rather than relicensing, unless the changes involve the company's competitive
interests (see the AGPLv3 criterion above).

## Repository location

Official projects live in the [trailofbits](https://github.com/trailofbits)
GitHub organization. Related ecosystems use
[lifting-bits](https://github.com/lifting-bits) (binary lifting) and
[crytic](https://github.com/crytic) (smart contract tooling). Move personal
repositories into the appropriate organization before announcing them.

## Package publishing

Publish under the company's shared accounts so ownership survives individual
departures:

- **PyPI:** add the [trailofbits organization](https://pypi.org/org/trailofbits/)
  as an owner of the package.
- **RubyGems:** add the [trailofbits account](https://rubygems.org/profiles/trailofbits)
  as a gem co-owner.
- Prefer **trusted publishing** (OIDC from GitHub Actions) over long-lived
  API tokens on every index that supports it (PyPI, RubyGems, crates.io).

Account access is handled internally; consult the internal documentation
rather than creating parallel accounts.

## Project scaffolding

- **Python:** generate new projects with
  [cookiecutter-python](https://github.com/trailofbits/cookiecutter-python),
  which encodes current company practices: uv, ruff, ty, prek, pdoc,
  SHA-pinned CI audited by zizmor, trusted publishing with SLSA provenance,
  and 100% coverage and docstring-coverage gates. Generated projects also
  ship `AGENTS.md` agent instructions. The `modern-python` skill in this
  marketplace covers the same toolchain.
- Example repositories for release automation:
  [pe-parse](https://github.com/trailofbits/pe-parse/blob/master/.github/workflows/release.yml)
  (C++/CI-managed packaging) and
  [pip-audit](https://github.com/pypa/pip-audit/blob/main/.github/workflows/release.yml)
  (Python/trusted publishing).

## Before flipping the repository public

Beyond the generic checklist, Trail of Bits maintainers should:

1. Confirm the license choice with their project manager if it deviates from
   Apache 2.0.
2. Follow the internal public-release checklist and announcement process
   (blog post, social media) documented internally — public release is often
   paired with an announcement, and coordinating that before the repository
   goes public preserves the option.
