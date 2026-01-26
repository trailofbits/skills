# Dependabot: Automated Dependency Updates

[Dependabot](https://docs.github.com/en/code-security/dependabot) automatically creates pull requests to keep your dependencies up to date. GitHub hosts it natively—no external service required.

## Why Use Dependabot?

- **Security**: Automatically patches known vulnerabilities
- **Freshness**: Keeps dependencies current without manual tracking
- **Visibility**: PRs show changelogs and compatibility notes

## Configuration

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7  # Wait 7 days before updating new releases

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7
```

## Supply Chain Protection

The `cooldown.default-days: 7` setting delays updates for newly published versions. This provides time for the community to detect compromised packages before they reach your project.

**Why this matters:**
- Attackers sometimes publish malicious versions of legitimate packages
- A 7-day delay allows time for detection and removal
- Combined with weekly schedules, this balances security with freshness

## Common Options

| Option | Description |
|--------|-------------|
| `interval` | `daily`, `weekly`, or `monthly` |
| `cooldown.default-days` | Days to wait before updating new releases |
| `ignore` | Skip specific dependencies or versions |
| `groups` | Group related updates into single PRs |
| `reviewers` | Auto-assign reviewers to PRs |

## Grouping Updates

Reduce PR noise by grouping related updates:

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7
    groups:
      dev-dependencies:
        patterns:
          - "pytest*"
          - "ruff"
          - "ty"
      production:
        update-types:
          - "minor"
          - "patch"
```

## See Also

- [GitHub Dependabot docs](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)
- [prek.md](./prek.md) - Pre-commit hooks (complementary tool)
