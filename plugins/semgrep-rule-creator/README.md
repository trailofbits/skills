# Semgrep Rule Creator

Create production-quality Semgrep rules for detecting bug patterns and security vulnerabilities.

**Author:** Maciej Domanski

## Skills Included

| Skill                 | Purpose                                              |
|-----------------------|------------------------------------------------------|
| `semgrep-rule-creator` | Guide creation of custom Semgrep rules with testing |

## When to Use

Use this skill when you need to:
- Create custom Semgrep rules for detecting specific bug patterns
- Write rules for security vulnerability detection
- Build taint mode rules for data flow analysis
- Develop pattern matching rules for code quality checks

## What It Does

- Guides test-driven rule development (write tests first, then iterate)
- Analyzes AST structure to help craft precise patterns
- Supports both taint mode (data flow) and pattern matching approaches
- Includes comprehensive reference documentation from Semgrep docs
- Provides common vulnerability patterns by language

## Prerequisites

- [Semgrep](https://semgrep.dev/docs/getting-started/) installed (`uv tool install semgrep` or `brew install semgrep`)

## Installation

```
/plugin install trailofbits/skills/plugins/semgrep-rule-creator
```

Then run `/semgrep-rule-creator:semgrep-rule` to walk through building a rule.

```
```

## Related Skills

- `semgrep-rule-variant-creator` - Port existing Semgrep rules to new target languages
- `static-analysis` - General static analysis toolkit with Semgrep, CodeQL, and SARIF parsing
- `variant-analysis` - Find similar vulnerabilities across codebases

## Calcifier recipe for `semgrep-rule-creator`

The [`semgrep-rule-creator` Python recipe](skills/semgrep-rule-creator/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/semgrep-rule-creator/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/semgrep-rule-creator/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `request` | `str` | Required |
| `rule_id` | `str` | Required |
| `language` | `str` | Required |
| `test_extension` | `str` | Required |
| `source_directory` | `str` | `'.'` |

The recipe declares `Bash`, `WebFetch`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
