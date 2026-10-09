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
