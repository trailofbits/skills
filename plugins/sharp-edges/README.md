# Sharp Edges

Identifies error-prone APIs, dangerous configurations, and footgun designs that enable security mistakes through developer confusion, laziness, or malice.

## When to Use

- Reviewing API designs for security-relevant interfaces
- Auditing configuration schemas that expose security choices
- Evaluating cryptographic library ergonomics
- Assessing authentication/authorization APIs
- Any code review where developers make security-critical decisions

## What It Does

Analyzes code and designs through the lens of three adversaries:

1. **The Scoundrel**: Can a malicious developer or attacker disable security via configuration?
2. **The Lazy Developer**: Will copy-pasting the first example lead to insecure code?
3. **The Confused Developer**: Can parameters be swapped without type errors?

## Core Principle

**The pit of success**: Secure usage should be the path of least resistance. If developers must read documentation carefully or remember special rules to avoid vulnerabilities, the API has failed.

## Installation

```
/plugin install trailofbits/skills/plugins/sharp-edges
```

## Sharp Edge Categories

The skill identifies six categories of misuse-prone designs:

| Category | Example |
|----------|---------|
| Algorithm Selection | JWT `alg: none` attack; PHP `hash("crc32", $password)` |
| Dangerous Defaults | `session_timeout: 0` meaning infinite; empty password accepted |
| Primitive vs. Semantic APIs | `encrypt(msg, bytes, bytes)` where key/nonce can be swapped |
| Configuration Cliffs | `verify_ssl: false` disables all certificate validation |
| Silent Failures | Verification returns `False` instead of throwing; ignored return values |
| Stringly-Typed Security | Permissions as comma-separated strings; SQL from concatenation |

## Agent

The `sharp-edges-analyzer` agent runs the full analysis workflow autonomously in a subagent context. Use it when you want a dedicated, isolated analysis of APIs, configurations, or interfaces for misuse resistance.

## Related Skills

- [constant-time-analysis](../constant-time-analysis) - Detect timing side-channels in cryptographic code
- [differential-review](../differential-review) - Security-focused code change review
- [audit-context-building](../audit-context-building) - Deep architectural analysis before auditing

## Calcifier recipe for `sharp-edges`

The [`sharp-edges` Python recipe](skills/sharp-edges/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/sharp-edges/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/sharp-edges/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `target` | `str` | `'.'` |
| `request` | `str` | `''` |
