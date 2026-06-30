# Installing Trail of Bits Skills for OpenCode

## Prerequisites

- [OpenCode.ai](https://opencode.ai) installed

## Installation

Add `trailofbits-skills` to the `plugin` array in your `opencode.json` (global or project-level):

```json
{
  "plugin": ["trailofbits-skills@git+https://github.com/trailofbits/skills.git"]
}
```

Restart OpenCode. The plugin installs through OpenCode's plugin manager and
registers all skills from the marketplace.

Verify by asking: "list your skills" and checking that Trail of Bits skills appear.

OpenCode uses its own plugin install. If you also use Claude Code, Codex, or
another harness, install separately for each one.

## Local Development

To test a local checkout without installing via git spec, run OpenCode from
within the cloned repository — the plugin at `.opencode/plugins/` loads
automatically.

## Updating

OpenCode installs through a git-backed package spec. Some OpenCode and Bun
versions pin that resolved git dependency in a lockfile or cache, so a restart
may not pick up the newest commit. If updates do not appear, clear OpenCode's
package cache or reinstall the plugin.

To pin a specific version:

```json
{
  "plugin": ["trailofbits-skills@git+https://github.com/trailofbits/skills.git#v1.0.0"]
}
```

## Troubleshooting

### Plugin not loading

1. Check logs: `opencode run --print-logs "hello" 2>&1 | grep -i trailofbits`
2. Verify the plugin line in your `opencode.json`
3. Make sure you're running a recent version of OpenCode

### Skills not found

1. Use the `skill` tool to list what's discovered
2. Check that the plugin is loading (see above)
