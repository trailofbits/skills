---
name: trailofbits:scan-apk
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

Confirm the skill's workflow and scanner are present:

```bash
ls "${CLAUDE_PLUGIN_ROOT}/skills/firebase-apk-scanner/SKILL.md" \
   "${CLAUDE_PLUGIN_ROOT}/skills/firebase-apk-scanner/scanner.sh"
```

Then read `${CLAUDE_PLUGIN_ROOT}/skills/firebase-apk-scanner/SKILL.md` and carry out its
workflow against the parsed path. Within that workflow, `{baseDir}` is
`${CLAUDE_PLUGIN_ROOT}/skills/firebase-apk-scanner`, so `{baseDir}/scanner.sh` is the
scanner script confirmed above.
