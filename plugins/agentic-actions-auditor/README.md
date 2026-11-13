# agentic-actions-auditor

Audits GitHub Actions workflows for security vulnerabilities in AI agent integrations. Detects misconfigurations and attack vectors specific to Claude Code Action, Gemini CLI, OpenAI Codex, and GitHub AI Inference when used in CI/CD pipelines.

## What It Does

This plugin provides a security audit skill that analyzes GitHub Actions workflow YAML files for vulnerabilities arising from AI agent integrations. It focuses on scenarios where attacker-controlled input (pull request titles, branch names, issue bodies, comments, commit messages, file contents, environment variables) can reach an AI agent running with elevated permissions in CI.

## Attack Vectors Detected

The skill checks for nine categories of security issues:

- **A. Env Var Intermediary** -- Attacker data flows through `env:` blocks to AI prompt fields with no visible `${{ }}` expressions
- **B. Direct Expression Injection** -- `${{ github.event.* }}` expressions embedded directly in AI prompt fields
- **C. CLI Data Fetch** -- `gh` CLI commands in prompts fetch attacker-controlled content at runtime
- **D. PR Target + Checkout** -- `pull_request_target` trigger combined with checkout of PR head code
- **E. Error Log Injection** -- CI error output or build logs fed to AI prompts carry attacker payloads
- **F. Subshell Expansion** -- Restricted tools like `echo` allow subshell expansion (`echo $(env)`) bypass
- **G. Eval of AI Output** -- AI response flows to `eval`, `exec`, or unquoted `$()` in subsequent steps
- **H. Dangerous Sandbox Configs** -- `danger-full-access`, `Bash(*)`, `--yolo` disable safety protections
- **I. Wildcard Allowlists** -- `allowed_non_write_users: "*"` or `allow-users: "*"` permit any user to trigger

## Supported AI Actions

| Action | Repository | Notes |
|--------|------------|-------|
| Claude Code Action | anthropics/claude-code-action | |
| Gemini CLI | google-github-actions/run-gemini-cli | Primary |
| Gemini CLI (legacy) | google-gemini/gemini-cli-action | Archived |
| OpenAI Codex | openai/codex-action | |
| GitHub AI Inference | actions/ai-inference | |

## Installation

From a project with the Trail of Bits internal marketplace configured:

```
/plugin menu
```

Select **agentic-actions-auditor** from the Security Tooling section.

## Skills Included

| Skill | Description |
|-------|-------------|
| agentic-actions-auditor | Audits GitHub Actions workflow files for AI agent security vulnerabilities |

## Target Audience

- **Security auditors** reviewing repositories that use AI agents in CI/CD
- **Developers** configuring Claude Code Action, Gemini CLI, OpenAI Codex, or GitHub AI Inference in their workflows
- **DevSecOps engineers** establishing secure defaults for AI-assisted code review pipelines

## Usage

Once installed, the skill activates automatically when Claude detects GitHub Actions workflow files (`.github/workflows/*.yml`) containing AI agent action references. You can also invoke it directly:

```
Audit the GitHub Actions workflows in this repository for AI agent security issues.
```

The skill produces a structured findings report covering each applicable attack vector with severity ratings and remediation guidance.

## License

[Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/)

## Calcifier recipe for `agentic-actions-auditor`

The [`agentic-actions-auditor` Python recipe](skills/agentic-actions-auditor/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/agentic-actions-auditor/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/agentic-actions-auditor/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

| Input | Type | Default |
| --- | --- | --- |
| `target` | `str` | `'.'` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
