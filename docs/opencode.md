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
- **Command frontmatter differences:** Claude commands use `allowed-tools` (restricts tool access) and `argument-hint` (placeholder text in the UI). OpenCode silently ignores these fields — commands still work but without tool restrictions or argument hints.
- **`{baseDir}` variable:** Claude Code substitutes `{baseDir}` with the skill directory path at runtime. OpenCode does not perform this substitution (see [Portability Notes](#portability-notes)).

## Install For OpenCode (No Clone Required)

OpenCode does not currently provide a Claude-style marketplace menu for skill repositories, so this repo ships a shell installer.

By default, the installer:

- downloads this repository archive from GitHub
- copies both skills and commands into OpenCode config directories

### Recommended: Download and Inspect

```bash
curl -fsSL -o /tmp/install_opencode_skills.sh \
  https://raw.githubusercontent.com/trailofbits/skills/main/scripts/install_opencode_skills.sh
less /tmp/install_opencode_skills.sh  # review the script
bash /tmp/install_opencode_skills.sh
```

### Install Smart Contract Bundle

```bash
bash /tmp/install_opencode_skills.sh --bundle smart-contracts
```

The smart contract bundle includes these plugins:

- `building-secure-contracts`
- `entry-point-analyzer`
- `spec-to-code-compliance`
- `property-based-testing`

### Quick Install (Piped)

If you trust the source, you can pipe directly:

```bash
curl -fsSL https://raw.githubusercontent.com/trailofbits/skills/main/scripts/install_opencode_skills.sh | bash
```

## Use Installed Plugin Commands

After installation, run plugin commands directly in OpenCode (same command-first workflow):

```text
/trailofbits:entry-points .
/trailofbits:spec-compliance SPEC.md .
/trailofbits:variants
```

These commands invoke the associated skills automatically.

### How Skills and Commands Interact in OpenCode

OpenCode automatically registers each installed skill as a slash command using the skill's frontmatter `name`. For example, installing the `entry-point-analyzer` skill automatically creates `/entry-point-analyzer`.

The installer also copies explicit command files (like `entry-points.md` with name `trailofbits:entry-points`), which register as `/trailofbits:entry-points`. These command files add value beyond auto-registration:

- They provide a **different invocation name** (namespaced with `trailofbits:`)
- They include a **specific prompt template** (e.g., argument parsing, workflow instructions)
- They reference the associated skill by name, keeping the command-first workflow

Both the auto-registered `/entry-point-analyzer` and the explicit `/trailofbits:entry-points` ultimately use the same skill content.

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

### `{baseDir}` references

Some skills use `{baseDir}` in their instructions to reference files relative to the skill directory. Claude Code replaces this variable at runtime. **OpenCode does not perform this substitution** — `{baseDir}` will appear as a literal string.

In practice, references like `{baseDir}/references/guide.md` will not resolve automatically. When an OpenCode agent encounters these, it should navigate to the corresponding file within the skill's directory (e.g., `~/.config/opencode/skills/<skill-name>/references/guide.md`).

The repository includes a compatibility validator that flags skills using `{baseDir}`:

```bash
python3 scripts/validate_opencode_compat.py
```

## Optional: Install With OpenPackage

[OpenPackage](https://github.com/enulus/openpackage) (`opkg`) can also install from this repository. This is an alternative to the first-party installer above. Note: this repo does not include an `openpackage.yml` manifest, so OpenPackage auto-detects the structure.

```bash
npm install -g opkg
opkg install gh@trailofbits/skills --platforms opencode
```
