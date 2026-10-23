# Culture Index

Interprets Culture Index survey results for individuals and teams.

**Author:** Dan Guido

## When to Use

Use this skill when you need to:
- Interpret an individual's Culture Index profile
- Analyze team composition for gas/brake/glue balance
- Detect burnout signals by comparing Survey vs Job traits
- Compare multiple profiles for compatibility
- Get motivator recommendations for specific trait types

## What It Does

This skill provides expert interpretation of Culture Index behavioral assessments:

- **Relative Interpretation** - Always uses distance from arrow, never absolute values
- **Survey vs Job Analysis** - Identifies behavior modification and energy drain
- **Pattern Recognition** - Maps profiles to 19 archetypes
- **Team Analysis** - Assesses gas/brake/glue balance and gaps
- **Burnout Detection** - Calculates energy utilization and flags risk

## Installation

```
/plugin install trailofbits/skills/plugins/culture-index
```

The plugin ships one skill, `interpreting-culture-index`. It triggers on its own when
you bring it a profile; invoke it directly with
`/culture-index:interpreting-culture-index`.

## Key Concepts

### Trait Colors
| Trait | Color | Measures |
|-------|-------|----------|
| A | Maroon | Autonomy, initiative |
| B | Yellow | Social ability |
| C | Blue | Pace/Patience |
| D | Green | Conformity, detail |
| L | Purple | Logic |
| I | Cyan | Ingenuity |

### Energy Utilization
```
Utilization = (Job EU / Survey EU) x 100

70-130% = Healthy
>130% = STRESS (burnout risk)
<70% = FRUSTRATION (flight risk)
```

### Gas/Brake/Glue Framework
| Role | Trait | Function |
|------|-------|----------|
| Gas | High A | Growth, risk-taking |
| Brake | High D | Quality control |
| Glue | High B | Relationships, morale |

## Input Formats

- **JSON** - Extracted profiles from culture-index tool (recommended)
- **PDF** - Direct PDF analysis using Claude's vision

## Workflows

- `interpret-individual.md` - Single profile analysis
- `analyze-team.md` - Team composition assessment
- `detect-burnout.md` - Stress/frustration detection
- `compare-profiles.md` - Multi-profile compatibility

## Reference Documents

- `primary-traits.md` - A, B, C, D trait details
- `secondary-traits.md` - EU, L, I trait details
- `patterns-archetypes.md` - 19 patterns and archetypes
- `motivators.md` - Engagement strategies by trait
- `team-composition.md` - Gas/brake/glue framework
- `anti-patterns.md` - Common interpretation mistakes

## Calcifier recipe for `interpreting-culture-index`

The [`interpreting-culture-index` Python recipe](skills/interpreting-culture-index/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/interpreting-culture-index/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/interpreting-culture-index/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

| Input | Type | Default |
| --- | --- | --- |
| `operation` | `Operation` | Required |
| `request` | `str` | `''` |
| `profile_files` | `list[str] \| None` | `None` |
| `context_files` | `list[str] \| None` | `None` |
| `working_directory` | `str` | `'.'` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
