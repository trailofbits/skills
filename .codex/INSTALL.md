# Installing Trail of Bits Skills for Codex

This repository primarily targets Claude plugin discovery, but it also exposes a Codex-native skill tree under `.codex/skills/`.

## Install

1. Clone the repository:
   ```sh
   git clone https://github.com/trailofbits/skills.git ~/.codex/trailofbits-skills
   ```

2. Link the Codex-native skill directories into your Codex skills directory:
   ```sh
   ~/.codex/trailofbits-skills/.codex/scripts/install-for-codex.sh
   ```

3. Restart Codex so it discovers the new skills.

## Verify

```sh
ls -la ~/.codex/skills | grep trailofbits-
```

## Notes

- Existing Claude plugin support remains unchanged under `plugins/`.
- Codex uses the `.codex/skills/` view, which reuses the existing skill content where possible.
- The `gh-cli` plugin does not expose a Claude `skills/` directory, so Codex gets a wrapper skill describing the intended authenticated GitHub CLI workflow.
