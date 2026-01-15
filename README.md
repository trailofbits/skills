# Trail of Bits Skills Marketplace

A Claude Code plugin marketplace from Trail of Bits providing skills to enhance AI-assisted security analysis, testing, and development workflows.

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
| [audit-context-building](plugins/audit-context-building/) | Build deep architectural context through ultra-granular code analysis |
| [burpsuite-project-parser](plugins/burpsuite-project-parser/) | Search and extract data from Burp Suite project files |
| [differential-review](plugins/differential-review/) | Security-focused differential review of code changes with git history analysis |
| [semgrep-rule-creator](plugins/semgrep-rule-creator/) | Create and refine Semgrep rules for custom vulnerability detection |
| [sharp-edges](plugins/sharp-edges/) | Identify error-prone APIs, dangerous configurations, and footgun designs |
| [static-analysis](plugins/static-analysis/) | Static analysis toolkit with CodeQL, Semgrep, and SARIF parsing |
| [testing-handbook-skills](plugins/testing-handbook-skills/) | Skills from the [Testing Handbook](https://appsec.guide): fuzzers, static analysis, sanitizers, coverage |
| [variant-analysis](plugins/variant-analysis/) | Find similar vulnerabilities across codebases using pattern-based analysis |

### Verification

| Plugin | Description |
|--------|-------------|
| [constant-time-analysis](plugins/constant-time-analysis/) | Detect compiler-induced timing side-channels in cryptographic code |
| [property-based-testing](plugins/property-based-testing/) | Property-based testing guidance for multiple languages and smart contracts |
| [spec-to-code-compliance](plugins/spec-to-code-compliance/) | Specification-to-code compliance checker for blockchain audits |

### Audit Lifecycle

| Plugin | Description |
|--------|-------------|
| [fix-review](plugins/fix-review/) | Verify fix commits address audit findings without introducing bugs |

### Reverse Engineering

| Plugin | Description |
|--------|-------------|
| [dwarf-expert](plugins/dwarf-expert/) | Interact with and understand the DWARF debugging format |

### Development

| Plugin | Description |
|--------|-------------|
| [ask-questions-if-underspecified](plugins/ask-questions-if-underspecified/) | Clarify requirements before implementing |

### Team Management

| Plugin | Description |
|--------|-------------|
| [culture-index](plugins/culture-index/) | Interpret Culture Index survey results for individuals and teams |

## Trophy Case

Bugs discovered using Trail of Bits Skills. Found something? [Let us know!](https://github.com/trailofbits/skills/issues/new?template=trophy-case.yml)

When reporting bugs you've found, feel free to mention:
> Found using [Trail of Bits Skills](https://github.com/trailofbits/skills)

| Skill | Bug |
|-------|-----|
| constant-time-analysis | [Timing side-channel in ECDSA verification](https://github.com/RustCrypto/signatures/pull/1144) |

## Contributing

We welcome contributions! Please see [CLAUDE.md](CLAUDE.md) for skill authoring guidelines.

## License

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

## About Trail of Bits

[Trail of Bits](https://www.trailofbits.com/) is a security research and consulting firm.
