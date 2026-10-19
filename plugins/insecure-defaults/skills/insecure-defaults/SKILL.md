---
name: insecure-defaults
description: "Audits files or repositories for insecure configuration defaults, fallback secrets, default credentials, fail-open switches, weak crypto, permissive access, and debug leakage. Use when checking insecure defaults and tracing their production reachability."
disable-model-invocation: true
allowed-tools: Bash Read Workflow
---

# Insecure defaults audit

This is the `/insecure-defaults:audit` command for hosts that load skills but not commands.
Read [the command](../../commands/audit.md) and follow it, with these substitutions:

- **Scope:** the path the user named (default `.`) where the command says `$1`.
- **Plugin root:** this plugin's directory, resolved from this SKILL.md's installed location, where the command says `${CLAUDE_PLUGIN_ROOT}`. The workflow `insecure-defaults:audit-pipeline` is [`workflows/audit.js`](../../workflows/audit.js).

**Outside Claude Code** (no `Workflow` tool): run this skill's workflow with the `workflow-runner:run-workflow` skill. If that skill is not installed, say so and stop.
