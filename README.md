# Trail of Bits Skills Marketplace

A Claude Code plugin marketplace from Trail of Bits providing skills to enhance AI-assisted security analysis, testing, and development workflows.

> Also see: [claude-code-config](https://github.com/trailofbits/claude-code-config) · [skills-curated](https://github.com/trailofbits/skills-curated) · [claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer) · [dropkit](https://github.com/trailofbits/dropkit)

## Installation

### Add the Marketplace

```
/plugin marketplace add trailofbits/skills
```

### Browse and Install Plugins

```
/plugin menu
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
| [audit-context-building](plugins/audit-context-building/) | Build deep architectural context through ultra-granular code analysis |
| [burpsuite-project-parser](plugins/burpsuite-project-parser/) | Search and extract data from Burp Suite project files |
| [differential-review](plugins/differential-review/) | Security-focused differential review of code changes with git history analysis |
| [insecure-defaults](plugins/insecure-defaults/) | Detect insecure default configurations, hardcoded credentials, and fail-open security patterns |
| [semgrep-rule-creator](plugins/semgrep-rule-creator/) | Create and refine Semgrep rules for custom vulnerability detection |
| [semgrep-rule-variant-creator](plugins/semgrep-rule-variant-creator/) | Port existing Semgrep rules to new target languages with test-driven validation |
| [sharp-edges](plugins/sharp-edges/) | Identify error-prone APIs, dangerous configurations, and footgun designs |
| [static-analysis](plugins/static-analysis/) | Static analysis toolkit with CodeQL, Semgrep, and SARIF parsing |
| [supply-chain-risk-auditor](plugins/supply-chain-risk-auditor/) | Audit supply-chain threat landscape of project dependencies |
| [testing-handbook-skills](plugins/testing-handbook-skills/) | Skills from the [Testing Handbook](https://appsec.guide): fuzzers, static analysis, sanitizers, coverage |
| [variant-analysis](plugins/variant-analysis/) | Find similar vulnerabilities across codebases using pattern-based analysis |

### Malware Analysis

| Plugin | Description |
|--------|-------------|
| [yara-authoring](plugins/yara-authoring/) | YARA detection rule authoring with linting, atom analysis, and best practices |

### Verification

| Plugin | Description |
|--------|-------------|
| [constant-time-analysis](plugins/constant-time-analysis/) | Detect compiler-induced timing side-channels in cryptographic code |
| [property-based-testing](plugins/property-based-testing/) | Property-based testing guidance for multiple languages and smart contracts |
| [spec-to-code-compliance](plugins/spec-to-code-compliance/) | Specification-to-code compliance checker for blockchain audits |
| [zeroize-audit](plugins/zeroize-audit/) | Detect missing or compiler-eliminated zeroization of secrets in C/C++ and Rust |

### Reverse Engineering

| Plugin | Description |
|--------|-------------|
| [dwarf-expert](plugins/dwarf-expert/) | Interact with and understand the DWARF debugging format |

### Mobile Security

| Plugin | Description |
|--------|-------------|
| [firebase-apk-scanner](plugins/firebase-apk-scanner/) | Scan Android APKs for Firebase security misconfigurations |

### Development

| Plugin | Description |
|--------|-------------|
| [ask-questions-if-underspecified](plugins/ask-questions-if-underspecified/) | Clarify requirements before implementing |
| [devcontainer-setup](plugins/devcontainer-setup/) | Create pre-configured devcontainers with Claude Code and language-specific tooling |
| [gh-cli](plugins/gh-cli/) | Intercept GitHub URL fetches and redirect to the authenticated `gh` CLI |
| [git-cleanup](plugins/git-cleanup/) | Safely clean up git worktrees and local branches with gated confirmation workflow |
| [let-fate-decide](plugins/let-fate-decide/) | Draw Tarot cards using cryptographic randomness to add entropy to vague planning |
| [modern-python](plugins/modern-python/) | Modern Python tooling and best practices with uv, ruff, and pytest |
| [seatbelt-sandboxer](plugins/seatbelt-sandboxer/) | Generate minimal macOS Seatbelt sandbox configurations |
| [second-opinion](plugins/second-opinion/) | Run code reviews using external LLM CLIs (OpenAI Codex, Google Gemini) on changes, diffs, or commits. Bundles Codex's built-in MCP server. |
| [skill-improver](plugins/skill-improver/) | Iterative skill refinement loop using automated fix-review cycles |
| [workflow-skill-design](plugins/workflow-skill-design/) | Design patterns for workflow-based Claude Code skills with review agent |

### Team Management

| Plugin | Description |
|--------|-------------|
| [culture-index](plugins/culture-index/) | Interpret Culture Index survey results for individuals and teams |

### Tooling

| Plugin | Description |
|--------|-------------|
| [claude-in-chrome-troubleshooting](plugins/claude-in-chrome-troubleshooting/) | Diagnose and fix Claude in Chrome MCP extension connectivity issues |

### Infrastructure

| Plugin | Description |
|--------|-------------|
| [debug-buttercup](plugins/debug-buttercup/) | Debug [Buttercup](https://github.com/trailofbits/buttercup) Kubernetes deployments |

## Trophy Case

Bugs discovered using Trail of Bits Skills. Found something? [Let us know!](https://github.com/trailofbits/skills/issues/new?template=trophy-case.yml)

When reporting bugs you've found, feel free to mention:
> Found using [Trail of Bits Skills](https://github.com/trailofbits/skills)

| Skill | Bug |
|-------|-----|
| constant-time-analysis | [Timing side-channel in ML-DSA signing](https://github.com/RustCrypto/signatures/pull/1144) |

## Contributing

We welcome contributions! Please see [CLAUDE.md](CLAUDE.md) for skill authoring guidelines.

## License

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). Made by [Trail of Bits](https://www.trailofbits.com/).
