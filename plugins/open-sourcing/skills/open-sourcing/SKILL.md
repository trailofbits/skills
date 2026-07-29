---
name: open-sourcing
description: This skill should be used when the user asks to "open source this project", "prepare this repository for public release", "make this repo public", "check open-source readiness", "choose a license for this project", or "set up release automation" ahead of a public launch. Provides a release-readiness workflow covering secrets hygiene, licensing, documentation, CI, and language-specific packaging.
---

# Open-Sourcing a Repository

Prepare a repository for public release so that an outsider with no prior
context can build, use, and contribute to it — and so that nothing sensitive
ships with it. Work through the steps in order; the secrets audit comes first
because its outcome (keeping vs. recreating the repository) affects
everything after it.

## When to Use

- Making a private repository public
- Auditing an existing public repository for release quality ("make it
  official")
- Choosing a license for a project
- Setting up packaging, versioning, or release automation ahead of a public
  launch

## When NOT to Use

- Routine development on an already-released project (no release event)
- Auditing third-party code for vulnerabilities (use a security-review skill)
- Publishing a package from a repository that will stay private — only the
  release-management steps apply; skip the rest

## Workflow

### Step 1: Detect the organization profile

```sh
bash {baseDir}/scripts/detect_org.sh
```

The script inspects git remotes and recent committer emails, and prints a
profile name. If it prints `trailofbits`, read
[references/trailofbits.md](references/trailofbits.md) now and apply its
license policy, publishing accounts, and process notes throughout the
remaining steps. If it prints `generic`, proceed with the generic guidance
alone. If the user says the detection is wrong, trust the user.

### Step 2: Audit for secrets — before anything else

A repository that has **ever** contained secrets (API keys, credentials,
client data) should not be flipped public. History rewriting is error-prone
and does not reach forks, caches, or CI artifacts. The reliable fix is a
fresh repository: copy the current tree over, commit, and archive the old
repository privately.

1. Ask whether the project ever handled secrets or client-confidential
   material. For a security consultancy's tooling, also ask whether test
   fixtures or example data came from client engagements.
2. Scan the full history with a dedicated tool if available —
   `gitleaks git .` or `trufflehog git file://.` — rather than eyeballing.
3. Check beyond the git tree: GitHub Actions logs and artifacts, old
   releases, issue and PR history, and the repository wiki all become public
   with the repository.
4. After going public, enable GitHub secret scanning and push protection in
   the repository settings.

Reject these rationalizations — this is the one step that cannot be fixed
after publication:

- *"The key was revoked, so the history is fine."* Revoked credentials still
  leak infrastructure names, internal URLs, and patterns attackers use for
  targeting.
- *"We'll rewrite history with git-filter-repo."* Rewrites miss forks,
  clones, caches, and CI artifacts; the fresh-repository approach does not.
- *"It's only test data."* Fixtures derived from client engagements or
  production systems are confidential regardless of how they are labeled.

### Step 3: Run the readiness check

```sh
bash {baseDir}/scripts/check_readiness.sh
```

The script prints a checklist of presence indicators (README, LICENSE,
CONTRIBUTING, SECURITY.md, CI, tests, semver tags, ...) and warns about
tracked files that commonly contain secrets. Treat unchecked items as
discussion prompts, not hard failures — a research prototype does not need
everything a flagship library needs. Walk through the gaps with the user and
fix the ones that matter for this project.

### Step 4: Documentation

The README is the project's front door. Confirm it explains:

- **What the project is** and what problem it solves (first paragraph)
- **How to install it** — package manager, container image, or build from
  source; a fresh-clone build must work using only what is in the repository
- **How to use it** — at least one concrete, copy-pasteable example
- **How to contribute** — inline or via `CONTRIBUTING.md`
- **The license** — a short section naming it

Also add:

- **`SECURITY.md`** with vulnerability-reporting instructions (a contact
  address or GitHub private vulnerability reporting). For security tooling
  this is table stakes.
- **API documentation**, built and hosted (GitHub Pages via CI is the usual
  route), linked from the README and the repository website field. See the
  language references below for per-ecosystem doc tooling.
- A **code of conduct** if the project expects outside contributors.

### Step 5: Licensing

No license means not open source, regardless of visibility. Read
[references/licensing.md](references/licensing.md) for selection criteria and
mechanics. The short version:

1. Apply the organization's policy if one was detected in Step 1.
2. Otherwise: Apache 2.0 as the permissive default, AGPLv3 when private
   modification by competitors is a real concern, Creative Commons for
   non-code artifacts.
3. Add the `LICENSE` file, set SPDX identifiers in package metadata, state
   the license in the README, and verify all three agree.

### Step 6: Tests and CI

- Confirm the test suite exists and passes; a public repository with a
  failing default branch signals abandonment.
- Ensure CI runs the tests on every PR, across the supported
  language-version and platform matrix.
- Enforce formatting and linting in CI (per-language tooling in the
  references below), so style debates never reach review.
- **Respect existing tooling.** Do not replace a working formatter, linter,
  or type checker as part of open-sourcing. If it lags the current
  generation (the language references name the current tools), warn the
  maintainer and let them decide; only when a category is missing entirely —
  no type checker, no formatter — add the current default.
- Consider a coverage gate that fails CI when coverage drops.
- Harden the workflows themselves before they become public attack surface:
  - Pin third-party actions to full commit SHAs; enable Dependabot for
    `github-actions` so pins stay current.
  - Set least-privilege `permissions:` blocks (start from `permissions: {}`).
  - Audit with `zizmor .github/workflows/` and lint with `actionlint`.

### Step 7: Repository settings

- **Branch protection** on the default branch: no force pushes, PRs
  required. Prefer rulesets for new repositories; classic branch protection
  remains supported.
- **Merge protection**: required status checks so PRs cannot merge with
  failing tests.
- **Dependabot or Renovate** for dependency and Actions updates. Group
  updates to cut PR noise, and set a cooldown window (e.g., 7 days) so
  freshly published — and occasionally hijacked — versions age before
  adoption.
- **`.editorconfig`** so contributors' editors agree on whitespace basics.
- **Labels**: create them as soon as more than one issue or PR needs one;
  prefixes for facets scale well (`C:` component, `P:` platform). See
  [blight's labels](https://github.com/trailofbits/blight/labels) for a
  worked example.

### Step 8: Releases and versioning

- Tag every release `vX.Y.Z`, following [semver](https://semver.org/); use
  `-rc.N` / `-pre.N` suffixes for release candidates and prereleases.
- Make releases CI-driven: pushing a tag (or publishing a GitHub Release)
  triggers build, packaging, and upload with no manual steps. A release
  should be `git tag vX.Y.Z && git push origin vX.Y.Z`.
- Publish packages under an organization-owned account, not a personal one,
  and use **trusted publishing** (OIDC) instead of long-lived tokens wherever
  the index supports it.

### Step 9: Language-specific practices

Identify the project's languages from its marker files and read the matching
reference for packaging, publishing, and quality tooling:

| Marker file | Reference |
|-------------|-----------|
| `pyproject.toml`, `setup.py` | [references/python.md](references/python.md) — defers to the modern-python skill for tooling |
| `CMakeLists.txt`, `Makefile` (C/C++) | [references/c-cpp.md](references/c-cpp.md) |
| `Cargo.toml` | [references/rust.md](references/rust.md) |
| `go.mod` | [references/go.md](references/go.md) |
| `package.json` | [references/javascript.md](references/javascript.md) |
| `Gemfile`, `*.gemspec` | [references/ruby.md](references/ruby.md) |

For other ecosystems, apply the cross-cutting principles: reproducible
builds from a fresh clone, CI-driven releases, trusted publishing or
organization-owned accounts, and license metadata in the package manifest.

## Final Review

Before the visibility switch is flipped, verify from an outsider's
perspective:

1. Clone into a clean directory and follow the README's build instructions
   verbatim — do they work with no tribal knowledge?
2. Re-run `{baseDir}/scripts/check_readiness.sh` and confirm the remaining
   gaps are deliberate choices, stated to the user.
3. Confirm the secrets audit (Step 2) actually happened; it is the one step
   that cannot be fixed after publication.

Making the repository public is then a repository-settings change. Pair the
release with an announcement where the organization has a process for one.

## Additional Resources

### Reference Files

- **[references/licensing.md](references/licensing.md)** — license selection
  criteria, SPDX metadata, forks and relicensing
- **[references/trailofbits.md](references/trailofbits.md)** — Trail of Bits
  policy overlay (loaded only when detected in Step 1)
- **[references/python.md](references/python.md)**,
  **[references/c-cpp.md](references/c-cpp.md)**,
  **[references/rust.md](references/rust.md)**,
  **[references/go.md](references/go.md)**,
  **[references/javascript.md](references/javascript.md)**,
  **[references/ruby.md](references/ruby.md)** — per-language packaging,
  publishing, and quality tooling

### Scripts

- **`scripts/detect_org.sh`** — prints the organization profile
  (`trailofbits` or `generic`) from git remotes and committer emails
- **`scripts/check_readiness.sh`** — prints presence indicators for
  release-readiness files and flags tracked files that commonly hold secrets
