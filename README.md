# Trail of Bits Skills Marketplace

A Claude Code plugin marketplace from Trail of Bits providing skills to enhance AI-assisted security analysis, testing, and development workflows. Codex can load this marketplace through its Claude marketplace compatibility.

> Also see: [claude-code-config](https://github.com/trailofbits/claude-code-config) · [codex-config](https://github.com/trailofbits/codex-config) · [skills-curated](https://github.com/trailofbits/skills-curated) · [claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer) · [dropkit](https://github.com/trailofbits/dropkit) · [coop](https://github.com/trailofbits/coop)

## Installation

### Claude Code Marketplace

```
/plugin marketplace add trailofbits/skills
```

### Browse and Install Plugins

```
/plugin menu
```

### Codex

Codex supports Claude plugin marketplaces directly, so this repository does not need Codex-specific sidecar metadata.

Install the marketplace with:

```sh
codex plugin marketplace add trailofbits/skills
codex plugin list
codex plugin add <plugin-name>@trailofbits
```

### Local Development

To add the marketplace locally (e.g., for testing or development), navigate to the **parent directory** of this repository:

```
cd /path/to/parent  # e.g., if repo is at ~/projects/skills, be in ~/projects
/plugins marketplace add ./skills
```

## Available Plugins

### Smart Contract Security

| Plugin | Description |
|--------|-------------|
| [building-secure-contracts](plugins/building-secure-contracts/) | Smart contract security toolkit with vulnerability scanners for 6 blockchains |
| [entry-point-analyzer](plugins/entry-point-analyzer/) | Identify state-changing entry points in smart contracts for security auditing |

### Code Auditing

| Plugin | Description |
|--------|-------------|
| [agentic-actions-auditor](plugins/agentic-actions-auditor/) | Audit GitHub Actions workflows for AI agent security vulnerabilities |
| [audit-context-building](plugins/audit-context-building/) | Understand a codebase before looking for bugs in it, one function at a time |
| [burpsuite-project-parser](plugins/burpsuite-project-parser/) | Search and extract data from Burp Suite project files |
| [c-review](plugins/c-review/) | Comprehensive C/C++ security code review, with coverage verified against a parse of the source |
| [differential-review](plugins/differential-review/) | Security-focused differential review of code changes with git history analysis |
| [dimensional-analysis](plugins/dimensional-analysis/) | Annotate codebases with dimensional analysis comments to detect unit mismatches and formula bugs |
| [fp-check](plugins/fp-check/) | Systematic false positive verification for security bug analysis with mandatory gate reviews |
| [insecure-defaults](plugins/insecure-defaults/) | Parallel audit workflow for fail-open insecure defaults, with a refuting verifier per candidate file |
| [rust-review](plugins/rust-review/) | Comprehensive Rust security review covering safe/unsafe boundary, memory safety, concurrency, panic-DoS, FFI, and async runtime with SARIF output |
| [semgrep-rule-creator](plugins/semgrep-rule-creator/) | Create and refine Semgrep rules for custom vulnerability detection |
| [semgrep-rule-variant-creator](plugins/semgrep-rule-variant-creator/) | Port existing Semgrep rules to new target languages with test-driven validation |
| [sharp-edges](plugins/sharp-edges/) | Identify error-prone APIs, dangerous configurations, and footgun designs |
| [static-analysis](plugins/static-analysis/) | Static analysis toolkit with CodeQL, Semgrep, and SARIF parsing |
| [supply-chain-risk-auditor](plugins/supply-chain-risk-auditor/) | Audit npm, PyPI, and Go dependencies for version-matched advisories, abandoned upstreams, publisher concentration, and install scripts |
| [testing-handbook-skills](plugins/testing-handbook-skills/) | Skills from the [Testing Handbook](https://appsec.guide): fuzzers, static analysis, sanitizers, coverage |
| [trailmark](plugins/trailmark/) | Code graph analysis, bounded subagent context slicing, Mermaid diagrams, mutation testing triage, and protocol verification |
| [variant-analysis](plugins/variant-analysis/) | Find similar vulnerabilities across codebases using pattern-based analysis |
| [vulnerability-triage-brocards](plugins/vulnerability-triage-brocards/) | Triage vulnerability reports using 7 brocards to accept, dismiss, or request more info before deeper analysis |

### Malware Analysis

| Plugin | Description |
|--------|-------------|
| [yara-authoring](plugins/yara-authoring/) | YARA detection rule authoring with linting, atom analysis, and best practices |

### Verification

| Plugin | Description |
|--------|-------------|
| [constant-time-analysis](plugins/constant-time-analysis/) | Detect compiler-induced timing side-channels in cryptographic code |
| [mutation-testing](plugins/mutation-testing/) | Configure mewt/muton mutation testing campaigns — scope targets, tune timeouts, optimize long runs |
| [property-based-testing](plugins/property-based-testing/) | Write, review, and triage property-based tests — Hypothesis, fast-check, proptest, and Echidna or Medusa for Solidity invariants |
| [spec-to-code-compliance](plugins/spec-to-code-compliance/) | Check code against the documentation that specifies it, across contracts, C/C++, services, and firmware |
| [writing-lean-proofs](plugins/writing-lean-proofs/) | Write structured Lean 4 proofs and design Lean libraries following Mathlib conventions |
| [zeroize-audit](plugins/zeroize-audit/) | Detect missing or compiler-eliminated zeroization of secrets in C/C++ and Rust |

### Reverse Engineering

| Plugin | Description |
|--------|-------------|
| [dwarf-expert](plugins/dwarf-expert/) | Analyze DWARF debug info: parse and search DIEs, verify integrity, write DWARF parsing code |

### Mobile Security

| Plugin | Description |
|--------|-------------|
| [firebase-apk-scanner](plugins/firebase-apk-scanner/) | Scan Android APKs for Firebase security misconfigurations |

### Development

| Plugin | Description |
|--------|-------------|
| [code-improver](plugins/code-improver/) | Autonomous review-and-fix workflow over skills, plugins, or a branch, with a pluggable reviewer, findings ledger, escalation, and scope guard |
| [devcontainer-setup](plugins/devcontainer-setup/) | Create pre-configured devcontainers with Claude Code and language-specific tooling |
| [gh-cli](plugins/gh-cli/) | Intercept GitHub URL fetches — `WebFetch`, MCP fetch tools, and curl/wget — and redirect to the authenticated `gh` CLI |
| [git-cleanup](plugins/git-cleanup/) | Safely clean up git worktrees and local branches: a dynamic workflow gathers merge evidence and tries to refute its own delete recommendations, behind gated confirmation |
| [goal-prompt](plugins/goal-prompt/) | Draft `/goal` commands for goal mode in Claude Code and Codex — verifiable completion conditions formatted to a copy-ready single line |
| [github-triage](plugins/github-triage/) | Triage open GitHub issues and PRs: merge ready bot/approved PRs, review unreviewed ones via subagents, close resolved issues with cited comments, cross-link pending fixes, and score the rest with local-only priority and change-size estimates |
| [let-fate-decide](plugins/let-fate-decide/) | Draw Tarot cards using cryptographic randomness to add entropy to vague planning |
| [modern-cpp](plugins/modern-cpp/) | Modern C++ best practices (C++20/23/26) with compiler hardening and safe idioms |
| [modern-python](plugins/modern-python/) | Modern Python tooling and best practices with uv, ruff, and pytest |
| [open-sourcing](plugins/open-sourcing/) | Prepare a repository for public release: secrets hygiene, licensing, CI readiness, and release automation |
| [second-opinion](plugins/second-opinion/) | Run code reviews using external LLM CLIs (OpenAI Codex, Google Gemini) on changes, diffs, or commits. Bundles Codex's built-in MCP server. |

### Team Management

| Plugin | Description |
|--------|-------------|
| [culture-index](plugins/culture-index/) | Interpret Culture Index survey results for individuals and teams |

### Tooling

| Plugin | Description |
|--------|-------------|
| [claude-in-chrome-troubleshooting](plugins/claude-in-chrome-troubleshooting/) | Diagnose and fix Claude in Chrome MCP extension connectivity issues |

## Trophy Case

Bugs discovered using Trail of Bits Skills. Found something? [Let us know!](https://github.com/trailofbits/skills/issues/new?template=trophy-case.yml)

When reporting bugs you've found, feel free to mention:
> Found using [Trail of Bits Skills](https://github.com/trailofbits/skills)

| Skill | Bug |
|-------|-----|
| constant-time-analysis | [Timing side-channel in ML-DSA signing](https://github.com/RustCrypto/signatures/pull/1144) |

## Contributing

We welcome contributions! See [AGENTS.md](AGENTS.md) for skill authoring guidelines, and
run `make check` before you push — it runs most of CI locally (see AGENTS.md for
what it does not cover).

## License

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). Made by [Trail of Bits](https://www.trailofbits.com/).
