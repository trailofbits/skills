# Differential Review

Security-focused differential review of code changes with git history analysis and blast radius estimation.

**Author:** Omar Inuwa

## When to Use

Use this skill when you need to:
- Review PRs, commits, or diffs for security vulnerabilities
- Detect security regressions (re-introduced vulnerabilities)
- Analyze the blast radius of code changes
- Check test coverage gaps for modified code

## What It Does

This skill performs comprehensive security review of code changes:

- **Risk-First Analysis** - Prioritizes auth, crypto, value transfer, external calls
- **Git History Analysis** - Uses blame to understand why code existed and detect regressions
- **Blast Radius Calculation** - Quantifies impact by counting callers
- **Test Coverage Gaps** - Identifies untested changes
- **Adaptive Depth** - Scales analysis based on codebase size (small/medium/large)

## Installation

```
/plugin install trailofbits/skills/plugins/differential-review
```

## Components

| Component | Name | Purpose |
|---|---|---|
| Skill | `differential-review` | The review itself — Pre-Analysis plus Phases 0–6, described below |
| Command | `/differential-review:diff-review` | Entry point taking `<pr-url\|commit-sha\|diff-path> [--baseline <ref>]` |
| Agent | `differential-review:adversarial-modeler` | Phase 5 only. The skill delegates to it for HIGH RISK changes to build concrete exploit paths and rate exploitability |

## Documentation Structure

This skill uses a **modular documentation architecture** for token efficiency and progressive disclosure:

### Core Entry Point
- **[SKILL.md](skills/differential-review/SKILL.md)** - Main entry point (224 lines)
  - Quick reference tables for triage
  - Decision tree routing to detailed docs
  - Quality checklist and red flags
  - Integration with other skills

### Supporting Documentation
- **[methodology.md](skills/differential-review/methodology.md)** - Detailed phase-by-phase workflow (234 lines)
  - Pre-Analysis: Baseline context building
  - Phase 0: Intake & Triage
  - Phase 1: Changed Code Analysis
  - Phase 2: Test Coverage Analysis
  - Phase 3: Blast Radius Analysis
  - Phase 4: Deep Context Analysis

- **[adversarial.md](skills/differential-review/adversarial.md)** - Attacker modeling and exploit scenarios (203 lines)
  - Phase 5: Adversarial Vulnerability Analysis
  - Attacker model definition (WHO/ACCESS/INTERFACE)
  - Exploitability rating framework
  - Complete exploit scenario templates

- **[reporting.md](skills/differential-review/reporting.md)** - Report structure and formatting (369 lines)
  - Phase 6: Report Generation
  - 9-section report template
  - Formatting guidelines and conventions
  - File naming and notification templates

- **[patterns.md](skills/differential-review/patterns.md)** - Common vulnerability patterns (300 lines)
  - Security regressions detection
  - Reentrancy, access control, overflow patterns
  - Quick detection bash commands

### Benefits of This Structure
- **Token Efficient** - Load only the documentation you need
- **Progressive Disclosure** - Quick reference for triage, detailed docs for deep analysis
- **Maintainable** - Each concern separated into its own file
- **Navigable** - Decision tree routes you to the right document

## Workflow

The complete workflow spans Pre-Analysis + Phases 0-6:

1. **Pre-Analysis** - Build baseline context with `audit-context-building` skill (if available)
2. **Phase 0: Intake** - Extract changes, assess size, risk-score files
3. **Phase 1: Changed Code** - Analyze diffs, git blame, check for regressions
4. **Phase 2: Test Coverage** - Identify coverage gaps
5. **Phase 3: Blast Radius** - Calculate impact of changes
6. **Phase 4: Deep Context** - Five Whys root cause analysis
7. **Phase 5: Adversarial Analysis** - Hunt vulnerabilities with attacker model
8. **Phase 6: Report** - Generate comprehensive markdown report

**Navigation:** Use the decision tree in SKILL.md to jump directly to the phase you need.

## Output

Generates a markdown report with:
- Executive summary with severity distribution
- Critical findings with attack scenarios and PoCs
- Test coverage analysis
- Blast radius analysis
- Historical context and regression risks
- Actionable recommendations

## Example Usage

```
Review the security implications of this PR:
git diff main..feature/auth-changes
```

## Related Skills

- `context-building` - Used for baseline context analysis
- `issue-writer` - Transform findings into formal audit reports

## Calcifier recipe for `differential-review`

The [`differential-review` Python recipe](skills/differential-review/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/differential-review/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/differential-review/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `repository` | `str` | Required |
| `baseline` | `str` | Required |
| `head` | `str` | `'HEAD'` |
| `mode` | `Literal['full', 'quick-triage']` | `'full'` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
