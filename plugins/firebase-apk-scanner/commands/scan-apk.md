---
description: Scans Android APKs for Firebase security misconfigurations
argument-hint: "<apk-file-or-directory>"
allowed-tools: Bash Read Grep Glob
---

# Scan APK for Firebase Misconfigurations

**Arguments:** $ARGUMENTS

Parse the APK file or directory from the arguments. If empty, ask the user for the path.

This command is the entry point for a Firebase APK scan. The `firebase-apk-scanner` skill
sets `disable-model-invocation: true`, so it cannot be invoked as a skill from here. Read
its workflow file and follow it directly.

Resolve the plugin root, then confirm the skill's workflow and scanner are present. The
`ls` echoes the expanded absolute paths, which is how you learn the value to use below:

```bash
ls "${CLAUDE_PLUGIN_ROOT}/skills/firebase-apk-scanner/SKILL.md" \
   "${CLAUDE_PLUGIN_ROOT}/skills/firebase-apk-scanner/scanner.sh"
```

If that fails (under Codex `CLAUDE_PLUGIN_ROOT` is unset, so the paths collapse to
`/skills/...`), search for the plugin instead:

```bash
find ~/.claude ~/.codex . -path '*/plugins/firebase-apk-scanner/skills/firebase-apk-scanner/scanner.sh' -print -quit 2>/dev/null
```

Strip the trailing `/skills/firebase-apk-scanner/scanner.sh` to get the root. If neither
resolves, **stop** and report the paths searched — do not continue with an empty root.

Then read `<root>/skills/firebase-apk-scanner/SKILL.md` and carry out its workflow against
the parsed path. Within that workflow, `{baseDir}` is `<root>/skills/firebase-apk-scanner`,
so `{baseDir}/scanner.sh` is the scanner confirmed above. `$ARGUMENTS` appears throughout
that file as literal text, not a shell variable — substitute the path you parsed above
wherever it occurs, and never run a command with a bare `$ARGUMENTS` still in it.
