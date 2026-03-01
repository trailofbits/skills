# OpenCode Compatibility

This repository is Claude Code plugin-marketplace first, but plugin workflows can be used in OpenCode with the same command-to-skill relationship.

## Compatibility Model

The OpenCode installer preserves plugin usability by installing both:

- plugin skills into `~/.config/opencode/skills`
- plugin commands into `~/.config/opencode/commands`

This keeps the same flow users expect from Claude plugins:

- invoke a plugin command
- command prompt loads/invokes the matching skill
- skill executes the full workflow

## What Translates Well

- Skill content from `plugins/*/skills/**/SKILL.md`
- Plugin command content from `plugins/*/commands/*.md`
- Bundle and plugin-level installation filters

## What Does Not Translate 1:1

- Claude plugin wrappers (`.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`)
- Claude hooks/commands runtime behavior
- `allowed-tools` frontmatter enforcement (OpenCode ignores unknown frontmatter fields)

## Install For OpenCode (No Clone Required)

OpenCode does not currently provide a Claude-style marketplace menu for skill repositories, so this repo ships a shell installer.

By default, the installer:

- downloads this repository archive from GitHub
- copies both skills and commands into OpenCode config directories

### Install All Plugins

```bash
curl -fsSL https://raw.githubusercontent.com/trailofbits/skills/main/scripts/install_opencode_skills.sh | bash
```

### Install Smart Contract Bundle

```bash
curl -fsSL https://raw.githubusercontent.com/trailofbits/skills/main/scripts/install_opencode_skills.sh | bash -s -- --bundle smart-contracts
```

The smart contract bundle includes these plugins:

- `building-secure-contracts`
- `entry-point-analyzer`
- `spec-to-code-compliance`
- `property-based-testing`

### Inspect Before Running (Safer Two-Step)

```bash
curl -fsSL -o /tmp/install_opencode_skills.sh https://raw.githubusercontent.com/trailofbits/skills/main/scripts/install_opencode_skills.sh
bash /tmp/install_opencode_skills.sh --bundle smart-contracts
```

## Use Installed Plugin Commands

After installation, run plugin commands directly in OpenCode (same command-first workflow):

```text
/trailofbits:entry-points .
/trailofbits:spec-compliance SPEC.md .
/trailofbits:variants
```

These commands invoke the associated skills automatically.

## List, Filter, and Scope Installation

### Preview Selected Items

```bash
bash /tmp/install_opencode_skills.sh --list --bundle smart-contracts
```

### Filter by Plugin or Item Name

```bash
# Install one plugin's skills and commands
bash /tmp/install_opencode_skills.sh --plugin entry-point-analyzer

# Install a specific skill and matching commands
bash /tmp/install_opencode_skills.sh --skill entry-point-analyzer

# Install one command by name
bash /tmp/install_opencode_skills.sh --commands-only --command trailofbits:entry-points
```

### Install Only Skills or Only Commands

```bash
bash /tmp/install_opencode_skills.sh --skills-only --bundle smart-contracts
bash /tmp/install_opencode_skills.sh --commands-only --bundle smart-contracts
```

## Custom Target Directories

```bash
# Skills target (default: ~/.config/opencode/skills)
# Commands target (default: ~/.config/opencode/commands)
bash /tmp/install_opencode_skills.sh --bundle smart-contracts --target .opencode/skills --commands-target .opencode/commands
```

## Uninstall

```bash
# Remove all managed skills and commands from default targets
bash /tmp/install_opencode_skills.sh --uninstall

# Remove only smart contract bundle items
bash /tmp/install_opencode_skills.sh --uninstall --bundle smart-contracts
```

## Local Contributor Mode

If you are in a local checkout and want symlinks for development:

```bash
bash scripts/install_opencode_skills.sh --source local --bundle smart-contracts --link
```

## Useful Flags

- `--dry-run` preview actions
- `--force` replace existing targets or remove unmanaged paths
- `--repo <owner/repo>` and `--ref <ref>` install from a specific GitHub source
- `--include-incompatible-commands` include known Claude-specific commands (off by default)

## Known Command Caveats

`skill-improver` command files use Claude-specific `${CLAUDE_PLUGIN_ROOT}` script hooks. They are skipped by default during OpenCode install.

## Portability Notes

Some skills use `{baseDir}` in instructions. Treat `{baseDir}` as the skill directory root when running outside Claude Code.

The repository includes a compatibility validator:

```bash
python3 scripts/validate_opencode_compat.py
```

## Optional: Install With OpenPackage

OpenPackage can also install this repository for OpenCode. This is optional and not required for the first-party installer flow above.

```bash
npm install -g opkg
opkg install gh@trailofbits/skills --platforms opencode
```
