# Semgrep Rulesets Reference

## Finding Rules in the Official Registry

Browse the [Semgrep Registry](https://semgrep.dev/explore) to find rulesets.

### Search Strategies

1. **By language:** Search "python", "javascript", "go", etc.
2. **By framework:** Search "django", "flask", "react", "spring", "rails"
3. **By vulnerability type:** Search "sql injection", "xss", "ssrf", "secrets"
4. **By standard:** Search "owasp", "cwe"

### Official Rulesets by Category

**Security baseline (always include):**
- `p/security-audit` - Comprehensive security rules
- `p/owasp-top-ten` - OWASP Top 10 vulnerabilities
- `p/secrets` - Hardcoded credentials, API keys

**Language-specific:**

| Language | Primary Ruleset | Framework Rulesets |
|----------|-----------------|-------------------|
| Python | `p/python` | `p/django`, `p/flask`, `p/fastapi` |
| JavaScript | `p/javascript` | `p/react`, `p/nodejs`, `p/express` |
| TypeScript | `p/typescript` | `p/react`, `p/nodejs` |
| Go | `p/golang` | - |
| Java | `p/java` | `p/spring` |
| Ruby | `p/ruby` | `p/rails` |
| PHP | `p/php` | `p/symfony`, `p/laravel` |
| C/C++ | `p/c` | - |
| Rust | `p/rust` | - |

**Infrastructure:**

| Technology | Ruleset |
|------------|---------|
| Docker | `p/dockerfile` |
| Terraform | `p/terraform` |
| Kubernetes | `p/kubernetes` |
| CloudFormation | `p/cloudformation` |

### Using Registry Rulesets

```bash
# Single ruleset
semgrep --metrics=off --config p/python .

# Multiple rulesets
semgrep --metrics=off --config p/python --config p/django --config p/security-audit .

# Scope to specific files
semgrep --metrics=off --config p/security-audit --include="*.py" .
```

## Third-Party Rulesets

Use directly from GitHub with `--config <url>`:

```bash
semgrep --metrics=off --config https://github.com/trailofbits/semgrep-rules .
```

### Third-Party Sources

| Source | URL | Languages | Focus |
|--------|-----|-----------|-------|
| **Trail of Bits** | [github.com/trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules) | Python, Go, Ruby, JS/TS, Terraform, YAML | Security audits, research findings |
| **GitLab SAST** | [gitlab.com/gitlab-org/security-products/sast-rules](https://gitlab.com/gitlab-org/security-products/sast-rules) | Java, JS, Scala, Python, C/C++, Kotlin, Ruby, Go, C# | CI/CD security |
| **0xdea** | [github.com/0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules) | C, C++ | Low-level security, memory safety |
| **elttam** | [github.com/elttam/semgrep-rules](https://github.com/elttam/semgrep-rules) | Java, Go, JS/TS, YAML, C# | Enterprise security |
| **Decurity** | [github.com/Decurity/semgrep-smart-contracts](https://github.com/Decurity/semgrep-smart-contracts) | Solidity, Cairo, Rust | Blockchain, Web3, smart contracts |
| **MindedSecurity** | [github.com/mindedsecurity/semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security) | Java, Kotlin | Android security |
| **Apiiro** | [github.com/apiiro/code-risk-rules](https://github.com/apiiro/code-risk-rules) | Python, JS/TS, Java, Ruby, Go, Rust, PHP | Application risk |
| **dgryski** | [github.com/dgryski/semgrep-go](https://github.com/dgryski/semgrep-go) | Go | Go-specific patterns |
| **HashiCorp** | [github.com/hashicorp/security-scanner](https://github.com/hashicorp/security-scanner) | Terraform | IaC patterns |

### Combining Official and Third-Party

```bash
# Comprehensive Python scan
semgrep --metrics=off \
  --config p/python \
  --config p/security-audit \
  --config p/secrets \
  --config https://github.com/trailofbits/semgrep-rules \
  .

# Comprehensive Go scan
semgrep --metrics=off \
  --config p/golang \
  --config p/trailofbits \
  --config https://github.com/dgryski/semgrep-go \
  .

# Smart contract scan
semgrep --metrics=off \
  --config https://github.com/Decurity/semgrep-smart-contracts \
  .
```
