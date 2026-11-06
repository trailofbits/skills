# cvss-scoring

Produces CVSS v4.0 vector strings from plain-text vulnerability descriptions.

## Installation

Claude Code:

```sh
/plugin marketplace add trailofbits/skills
/plugin install cvss-scoring@trailofbits
```

Codex:

```sh
codex plugin marketplace add trailofbits/skills
codex plugin add cvss-scoring@trailofbits
```

## Skills

| Skill | Description |
|-------|-------------|
| [cvss-scoring](skills/cvss-scoring/SKILL.md) | Systematically evaluates all 11 base metrics to produce a CVSS v4.0 vector string and a calculator link that scores it |

## How It Works

1. You provide a plain-text vulnerability description (severity, exploitation scenario, impact, remediation)
2. The skill extracts security-relevant facts, then evaluates each CVSS v4.0 metric individually
3. Output: a metric-by-metric justification table, the vector string, and a
   [FIRST.org calculator](https://www.first.org/cvss/calculator/4.0) link carrying that
   vector in the URL fragment — open it and every metric is preselected with the numeric
   score shown

The skill does NOT compute the numeric score itself. CVSS v4.0 scoring uses a lookup-based algorithm that requires the official calculator.

## References

- [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)
- [CVSS v4.0 User Guide](https://www.first.org/cvss/v4.0/user-guide)
- [CVSS v4.0 Examples](https://www.first.org/cvss/v4.0/examples)
- [CVSS v4.0 Calculator](https://www.first.org/cvss/calculator/4.0)

## Calcifier recipe

The generated [Python recipe](skills/cvss-scoring/.calcifier/recipe.py)
provides an optional compiled entry point for this skill. It has no child recipes
and can be installed independently. It was generated with Calcifier 0.1.0;
Calcifier is a runtime requirement only for this entry point.

The recipe uses a configured `worker` role to assess `description`, validates
metric values and required fields, then renders the vector in canonical order
with its calculator link. It returns clarification questions or a refusal when
appropriate and does not calculate a numeric score.

Review the Python before granting trust. With a Calcifier version-1 agent
configuration that defines `worker`, run from the plugin directory:

```bash
calcifier lint skills/cvss-scoring/.calcifier/recipe.py --portable
calcifier exec skills/cvss-scoring/.calcifier/recipe.py --trust \
  --agent-config /path/to/agents.json \
  --input 'description=Describe the vulnerability, attack conditions, and impact'
```

`--trust` records consent for the reviewed recipe and its pinned sources. Omit
it on subsequent runs unless the package changes.
