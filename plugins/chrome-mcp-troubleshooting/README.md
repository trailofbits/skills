# Chrome MCP Troubleshooting

Diagnose and fix Claude in Chrome MCP extension connectivity issues.

**Original Author:** [@jeffzwang](https://github.com/jeffzwang) from [@ExaAILabs](https://github.com/ExaAILabs)
**Enhanced by:** Trail of Bits

## When to Use

- `mcp__claude-in-chrome__*` tools fail with "Browser extension is not connected"
- Browser automation works erratically or times out
- After updating Claude Code or Claude.app
- When switching between Claude Code CLI and Claude.app (Cowork)

## What It Does

- Explains the Claude.app vs Claude Code native host conflict
- Provides toggle script to switch between the two
- Quick diagnosis commands
- Full reset procedure
- Covers edge cases (multiple profiles, stale wrappers, TMPDIR issues)

## Installation

```
/plugin marketplace add trailofbits/skills
/plugin install chrome-mcp-troubleshooting@trailofbits
```

The plugin ships one skill, `chrome-mcp-troubleshooting`. It triggers on its own when
the symptoms above appear; invoke it directly with
`/chrome-mcp-troubleshooting:chrome-mcp-troubleshooting`.

Replaces `claude-in-chrome-troubleshooting`. If installed, uninstall the old plugin
and install this one using the commands above.

## License

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

## Calcifier recipe for `chrome-mcp-troubleshooting`

The [`chrome-mcp-troubleshooting` Python recipe](skills/chrome-mcp-troubleshooting/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/chrome-mcp-troubleshooting/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/chrome-mcp-troubleshooting/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

| Input | Type | Default |
| --- | --- | --- |
| `symptom` | `str` | `'Browser extension is not connected'` |
| `owner` | `Literal['claude-code', 'cowork']` | `'claude-code'` |
| `operation` | `Literal['diagnose', 'switch', 'reset']` | `'diagnose'` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
